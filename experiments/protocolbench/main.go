package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"math"
	"math/big"
	"os"
	"runtime"
	"sort"
	"strconv"
	"time"

	"foldaudit/schemes/benchcore"
	"foldaudit/schemes/foldaudit"
	"foldaudit/schemes/miaoscis2026"
	"foldaudit/schemes/xutifs26"
	"foldaudit/schemes/yutc25"
	"foldaudit/schemes/zhangtpds23"
)

const (
	challengeSize = 690
	baseM         = 4
	baseBMB       = 10
	baseS         = 20
)

type params struct {
	M   int
	BMB int
	S   int
	C   int
}

func (p params) N() int {
	return max(p.C, int(math.Ceil(float64(p.BMB*1_000_000)/float64(32*p.S))))
}

type row struct {
	Scenario string
	Variable string
	Value    int
	Scheme   string
	Phase    string
	Params   params
	Seconds  float64
	StdDev   float64
	Repeats  int
	OK       bool
}

type timedResult struct {
	duration time.Duration
	ok       bool
}

type phaseSamples struct {
	seconds []float64
	ok      bool
}

func main() {
	outPath := flag.String("out", "experiments/out/vi_evaluation/vi_overhead_all.csv", "output CSV path")
	profile := flag.String("profile", "paper", "benchmark profile: paper or quick")
	phases := flag.String("phases", "all", "benchmark phases: all, online, or store")
	repeats := flag.Int("repeats", 10, "number of protocol executions per workload point")
	flag.Parse()
	if *repeats < 1 {
		fatal(fmt.Errorf("repeats must be at least 1"))
	}
	if *phases != "all" && *phases != "online" && *phases != "store" {
		fatal(fmt.Errorf("unknown phases %q", *phases))
	}

	file, writer, err := createCSV(*outPath)
	if err != nil {
		fatal(err)
	}
	defer file.Close()
	if err := writeCSVHeader(writer); err != nil {
		fatal(err)
	}
	if err := runProfile(*profile, *repeats, *phases, func(rows []row) error {
		if err := writeCSVRows(writer, rows); err != nil {
			return err
		}
		writer.Flush()
		return writer.Error()
	}); err != nil {
		fatal(err)
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		fatal(err)
	}
	fmt.Printf("wrote protocol execution measurements to %s\n", *outPath)
}

func runProfile(profile string, repeats int, phases string, emit func([]row) error) error {
	var mValues, bValues, sValues []int
	switch profile {
	case "paper":
		mValues = intRange(4, 20, 4)
		bValues = intRange(10, 50, 10)
		sValues = []int{20, 40, 60, 80, 100}
	case "quick":
		mValues = []int{1, 2}
		bValues = []int{0}
		sValues = []int{20}
	default:
		return fmt.Errorf("unknown profile %q", profile)
	}

	baseline := params{M: baseM, BMB: baseBMB, S: baseS, C: challengeSize}
	if profile == "quick" {
		baseline = params{M: 2, BMB: 0, S: 20, C: 8}
		if repeats > 2 {
			repeats = 2
		}
	}
	if err := emit(runAllSchemes("baseline", "baseline", 0, baseline, repeats, phases)); err != nil {
		return err
	}
	for _, m := range mValues {
		p := params{M: m, BMB: baseline.BMB, S: baseline.S, C: baseline.C}
		if err := emit(runAllSchemes("vary_m", "m", m, p, repeats, phases)); err != nil {
			return err
		}
	}
	for _, b := range bValues {
		p := params{M: baseline.M, BMB: b, S: baseline.S, C: baseline.C}
		if err := emit(runAllSchemes("vary_B", "B_MB", b, p, repeats, phases)); err != nil {
			return err
		}
	}
	for _, s := range sValues {
		p := params{M: baseline.M, BMB: baseline.BMB, S: s, C: baseline.C}
		if err := emit(runAllSchemes("vary_s", "s", s, p, repeats, phases)); err != nil {
			return err
		}
	}
	return nil
}

func runAllSchemes(scenario, variable string, value int, p params, repeats int, phases string) []row {
	schemes := []struct {
		name   string
		fn     func(params) map[string]timedResult
		online func(params, int) map[string]phaseSamples
		store  func(params) timedResult
	}{
		{"YuTC25", runYu, runYuOnline, runYuStore},
		{"ZhangTPDS23", runZhang, runZhangOnline, runZhangStore},
		{"MiaoSCIS2026", runMiao, runMiaoOnline, runMiaoStore},
		{"XuTIFS26", runXu, runXuOnline, runXuStore},
		{"FoldAudit", runFoldAudit, runFoldAuditOnline, runFoldAuditStore},
	}

	var rows []row
	for _, scheme := range schemes {
		fmt.Fprintf(os.Stderr, "running %s scenario=%s %s=%d m=%d B_MB=%d s=%d c=%d n=%d repeats=%d\n",
			scheme.name, scenario, variable, value, p.M, p.BMB, p.S, p.C, p.N(), repeats)
		if phases == "online" {
			results := scheme.online(p, repeats)
			for _, phase := range []string{"ProofGen", "Verify"} {
				sample := results[phase]
				median, stddev := medianStdDev(sample.seconds)
				rows = append(rows, row{Scenario: scenario, Variable: variable, Value: value, Scheme: scheme.name, Phase: phase, Params: p, Seconds: median, StdDev: stddev, Repeats: repeats, OK: sample.ok})
			}
			continue
		}
		if phases == "store" {
			var samples []float64
			ok := true
			for repeat := 1; repeat <= repeats; repeat++ {
				fmt.Fprintf(os.Stderr, "  repeat %d/%d\n", repeat, repeats)
				result := scheme.store(p)
				samples = append(samples, result.duration.Seconds())
				ok = ok && result.ok
			}
			median, stddev := medianStdDev(samples)
			rows = append(rows, row{Scenario: scenario, Variable: variable, Value: value, Scheme: scheme.name, Phase: "Store", Params: p, Seconds: median, StdDev: stddev, Repeats: repeats, OK: ok})
			continue
		}
		samples := make(map[string][]float64)
		phaseOK := map[string]bool{"Store": true, "Challenge": true, "ProofGen": true, "Verify": true, "Audit": true}
		for repeat := 1; repeat <= repeats; repeat++ {
			fmt.Fprintf(os.Stderr, "  repeat %d/%d\n", repeat, repeats)
			results := scheme.fn(p)
			for _, phase := range []string{"Store", "Challenge", "ProofGen", "Verify"} {
				r := results[phase]
				samples[phase] = append(samples[phase], r.duration.Seconds())
				phaseOK[phase] = phaseOK[phase] && r.ok
			}
			audit := results["Challenge"].duration + results["ProofGen"].duration + results["Verify"].duration
			auditOK := results["Challenge"].ok && results["ProofGen"].ok && results["Verify"].ok
			samples["Audit"] = append(samples["Audit"], audit.Seconds())
			phaseOK["Audit"] = phaseOK["Audit"] && auditOK
		}
		for _, phase := range []string{"Store", "Challenge", "ProofGen", "Verify"} {
			median, stddev := medianStdDev(samples[phase])
			rows = append(rows, row{Scenario: scenario, Variable: variable, Value: value, Scheme: scheme.name, Phase: phase, Params: p, Seconds: median, StdDev: stddev, Repeats: repeats, OK: phaseOK[phase]})
		}
		median, stddev := medianStdDev(samples["Audit"])
		rows = append(rows, row{Scenario: scenario, Variable: variable, Value: value, Scheme: scheme.name, Phase: "Audit", Params: p, Seconds: median, StdDev: stddev, Repeats: repeats, OK: phaseOK["Audit"]})
	}
	return rows
}

func runXu(p params) map[string]timedResult {
	n := p.N()
	protocol := xutifs26.NewProtocol(p.M, n, p.S)
	data := dataset(p.M, n, p.S, "xu")
	var stored *xutifs26.StoredBatch
	store := timed(func() bool {
		var err error
		stored, err = protocol.Store(data)
		return err == nil
	})
	var chal xutifs26.Challenge
	challenge := timed(func() bool {
		chal = protocol.Challenge(p.C)
		return true
	})
	var proof *xutifs26.Proof
	prove := timed(func() bool {
		var err error
		proof, err = protocol.Prove(stored, chal)
		return err == nil
	})
	verify := timed(func() bool { return protocol.Verify(stored, chal, proof) })
	return map[string]timedResult{"Store": store, "Challenge": challenge, "ProofGen": prove, "Verify": verify}
}

func runXuStore(p params) timedResult {
	n := p.N()
	protocol := xutifs26.NewProtocol(p.M, n, p.S)
	data := dataset(p.M, n, p.S, "xu")
	return timed(func() bool {
		_, err := protocol.Store(data)
		return err == nil
	})
}

func runXuOnline(p params, repeats int) map[string]phaseSamples {
	n := p.N()
	protocol := xutifs26.NewProtocol(p.M, n, p.S)
	stored, err := protocol.Store(dataset(p.M, n, p.S, "xu"))
	if err != nil {
		return failedOnlineSamples()
	}
	samples := newOnlineSamples()
	for repeat := 1; repeat <= repeats; repeat++ {
		fmt.Fprintf(os.Stderr, "  repeat %d/%d\n", repeat, repeats)
		chal := protocol.Challenge(p.C)
		var proof *xutifs26.Proof
		prove := timed(func() bool {
			var err error
			proof, err = protocol.Prove(stored, chal)
			return err == nil
		})
		verify := timed(func() bool { return protocol.Verify(stored, chal, proof) })
		appendOnlineSample(samples, "ProofGen", prove)
		appendOnlineSample(samples, "Verify", verify)
	}
	return samples
}

func runYu(p params) map[string]timedResult {
	n := p.N()
	protocol := yutc25.NewProtocol(n, p.S)
	data := dataset(p.M, n, p.S, "yu")
	var stored *yutc25.StoredBatch
	store := timed(func() bool {
		var err error
		stored, err = protocol.StoreBatch(data)
		return err == nil
	})
	var chal yutc25.BatchChallenge
	challenge := timed(func() bool {
		chal = protocol.BatchChallenge(p.M, p.C)
		return true
	})
	var proof *yutc25.BatchProof
	prove := timed(func() bool {
		var err error
		proof, err = protocol.ProveBatch(stored, chal)
		return err == nil
	})
	verify := timed(func() bool { return protocol.VerifyBatch(stored, chal, proof) })
	return map[string]timedResult{"Store": store, "Challenge": challenge, "ProofGen": prove, "Verify": verify}
}

func runYuStore(p params) timedResult {
	n := p.N()
	protocol := yutc25.NewProtocol(n, p.S)
	data := dataset(p.M, n, p.S, "yu")
	return timed(func() bool {
		_, err := protocol.StoreBatch(data)
		return err == nil
	})
}

func runYuOnline(p params, repeats int) map[string]phaseSamples {
	n := p.N()
	protocol := yutc25.NewProtocol(n, p.S)
	stored, err := protocol.StoreBatch(dataset(p.M, n, p.S, "yu"))
	if err != nil {
		return failedOnlineSamples()
	}
	samples := newOnlineSamples()
	for repeat := 1; repeat <= repeats; repeat++ {
		fmt.Fprintf(os.Stderr, "  repeat %d/%d\n", repeat, repeats)
		chal := protocol.BatchChallenge(p.M, p.C)
		var proof *yutc25.BatchProof
		prove := timed(func() bool {
			var err error
			proof, err = protocol.ProveBatch(stored, chal)
			return err == nil
		})
		verify := timed(func() bool { return protocol.VerifyBatch(stored, chal, proof) })
		appendOnlineSample(samples, "ProofGen", prove)
		appendOnlineSample(samples, "Verify", verify)
	}
	return samples
}

func runZhang(p params) map[string]timedResult {
	n := p.N()
	protocol := zhangtpds23.NewProtocol(p.M, n, p.S)
	data := dataset(p.M, n, p.S, "zhang")
	var stored *zhangtpds23.StoredBatch
	store := timed(func() bool {
		var err error
		stored, err = protocol.Store(data)
		return err == nil
	})
	var chal zhangtpds23.Challenge
	challenge := timed(func() bool {
		chal = protocol.Challenge(p.C)
		return true
	})
	var proof *zhangtpds23.Proof
	prove := timed(func() bool {
		var err error
		proof, err = protocol.Prove(stored, chal)
		return err == nil
	})
	verify := timed(func() bool { return protocol.Verify(stored, chal, proof) })
	return map[string]timedResult{"Store": store, "Challenge": challenge, "ProofGen": prove, "Verify": verify}
}

func runZhangStore(p params) timedResult {
	n := p.N()
	protocol := zhangtpds23.NewProtocol(p.M, n, p.S)
	data := dataset(p.M, n, p.S, "zhang")
	return timed(func() bool {
		_, err := protocol.Store(data)
		return err == nil
	})
}

func runZhangOnline(p params, repeats int) map[string]phaseSamples {
	n := p.N()
	protocol := zhangtpds23.NewProtocol(p.M, n, p.S)
	stored, err := protocol.Store(dataset(p.M, n, p.S, "zhang"))
	if err != nil {
		return failedOnlineSamples()
	}
	samples := newOnlineSamples()
	for repeat := 1; repeat <= repeats; repeat++ {
		fmt.Fprintf(os.Stderr, "  repeat %d/%d\n", repeat, repeats)
		chal := protocol.Challenge(p.C)
		var proof *zhangtpds23.Proof
		prove := timed(func() bool {
			var err error
			proof, err = protocol.Prove(stored, chal)
			return err == nil
		})
		verify := timed(func() bool { return protocol.Verify(stored, chal, proof) })
		appendOnlineSample(samples, "ProofGen", prove)
		appendOnlineSample(samples, "Verify", verify)
	}
	return samples
}

func runMiao(p params) map[string]timedResult {
	n := p.N()
	protocol := miaoscis2026.NewProtocol(n)
	files := miaoFiles(p.M, n)
	var stored *miaoscis2026.StoredData
	store := timed(func() bool {
		var err error
		stored, err = protocol.Store(files)
		return err == nil
	})
	var chal miaoscis2026.Challenge
	challenge := timed(func() bool {
		trap, err := protocol.Trapdoor(stored, []string{"audit"})
		if err != nil {
			return false
		}
		chal = protocol.ChallengeWithTrapdoor(trap, p.C, p.M)
		return true
	})
	var proof *miaoscis2026.Proof
	prove := timed(func() bool {
		var err error
		proof, err = protocol.Prove(stored, chal)
		return err == nil
	})
	verify := timed(func() bool { return protocol.Verify(stored, chal, proof) })
	return map[string]timedResult{"Store": store, "Challenge": challenge, "ProofGen": prove, "Verify": verify}
}

func runMiaoStore(p params) timedResult {
	n := p.N()
	protocol := miaoscis2026.NewProtocol(n)
	files := miaoFiles(p.M, n)
	return timed(func() bool {
		_, err := protocol.Store(files)
		return err == nil
	})
}

func runMiaoOnline(p params, repeats int) map[string]phaseSamples {
	n := p.N()
	protocol := miaoscis2026.NewProtocol(n)
	stored, err := protocol.Store(miaoFiles(p.M, n))
	if err != nil {
		return failedOnlineSamples()
	}
	samples := newOnlineSamples()
	for repeat := 1; repeat <= repeats; repeat++ {
		fmt.Fprintf(os.Stderr, "  repeat %d/%d\n", repeat, repeats)
		trap, err := protocol.Trapdoor(stored, []string{"audit"})
		if err != nil {
			appendOnlineSample(samples, "ProofGen", timedResult{ok: false})
			appendOnlineSample(samples, "Verify", timedResult{ok: false})
			continue
		}
		chal := protocol.ChallengeWithTrapdoor(trap, p.C, p.M)
		var proof *miaoscis2026.Proof
		prove := timed(func() bool {
			var err error
			proof, err = protocol.Prove(stored, chal)
			return err == nil
		})
		verify := timed(func() bool { return protocol.Verify(stored, chal, proof) })
		appendOnlineSample(samples, "ProofGen", prove)
		appendOnlineSample(samples, "Verify", verify)
	}
	return samples
}

func runFoldAudit(p params) map[string]timedResult {
	n := p.N()
	cfg := foldaudit.DefaultConfig()
	cfg.NumFiles = p.M
	cfg.ChunksPerFile = n
	cfg.SectorsPerChunk = p.S
	cfg.ChallengedChunks = p.C
	protocol, err := foldaudit.Setup(cfg, newDeterministicReader(42))
	if err != nil {
		return failedResults()
	}
	data := dataset(p.M, n, p.S, "foldaudit")
	var stored *foldaudit.StoredBatch
	store := timed(func() bool {
		var err error
		stored, err = protocol.Store(data)
		return err == nil
	})
	var chal *foldaudit.Challenge
	challenge := timed(func() bool {
		var err error
		chal, err = protocol.Challenge()
		return err == nil
	})
	var proof *foldaudit.AuditProof
	prove := timed(func() bool {
		var err error
		proof, err = protocol.ProofGen(stored, chal)
		return err == nil
	})
	verify := timed(func() bool { return protocol.Verify(stored, chal, proof) })
	return map[string]timedResult{"Store": store, "Challenge": challenge, "ProofGen": prove, "Verify": verify}
}

func runFoldAuditStore(p params) timedResult {
	n := p.N()
	cfg := foldaudit.DefaultConfig()
	cfg.NumFiles = p.M
	cfg.ChunksPerFile = n
	cfg.SectorsPerChunk = p.S
	cfg.ChallengedChunks = p.C
	protocol, err := foldaudit.Setup(cfg, newDeterministicReader(42))
	if err != nil {
		return timedResult{ok: false}
	}
	data := dataset(p.M, n, p.S, "foldaudit")
	return timed(func() bool {
		_, err := protocol.Store(data)
		return err == nil
	})
}

func runFoldAuditOnline(p params, repeats int) map[string]phaseSamples {
	n := p.N()
	cfg := foldaudit.DefaultConfig()
	cfg.NumFiles = p.M
	cfg.ChunksPerFile = n
	cfg.SectorsPerChunk = p.S
	cfg.ChallengedChunks = p.C
	protocol, err := foldaudit.Setup(cfg, newDeterministicReader(42))
	if err != nil {
		return failedOnlineSamples()
	}
	stored, err := protocol.Store(dataset(p.M, n, p.S, "foldaudit"))
	if err != nil {
		return failedOnlineSamples()
	}
	samples := newOnlineSamples()
	for repeat := 1; repeat <= repeats; repeat++ {
		fmt.Fprintf(os.Stderr, "  repeat %d/%d\n", repeat, repeats)
		chal, err := protocol.Challenge()
		if err != nil {
			appendOnlineSample(samples, "ProofGen", timedResult{ok: false})
			appendOnlineSample(samples, "Verify", timedResult{ok: false})
			continue
		}
		var proof *foldaudit.AuditProof
		prove := timed(func() bool {
			var err error
			proof, err = protocol.ProofGen(stored, chal)
			return err == nil
		})
		verify := timed(func() bool { return protocol.Verify(stored, chal, proof) })
		appendOnlineSample(samples, "ProofGen", prove)
		appendOnlineSample(samples, "Verify", verify)
	}
	return samples
}

func newOnlineSamples() map[string]phaseSamples {
	return map[string]phaseSamples{
		"ProofGen": {ok: true},
		"Verify":   {ok: true},
	}
}

func appendOnlineSample(samples map[string]phaseSamples, phase string, result timedResult) {
	sample := samples[phase]
	sample.seconds = append(sample.seconds, result.duration.Seconds())
	sample.ok = sample.ok && result.ok
	samples[phase] = sample
}

func failedOnlineSamples() map[string]phaseSamples {
	return map[string]phaseSamples{
		"ProofGen": {ok: false},
		"Verify":   {ok: false},
	}
}

func dataset(m, n, s int, label string) [][][]*big.Int {
	out := make([][][]*big.Int, m)
	for i := 0; i < m; i++ {
		out[i] = make([][]*big.Int, n)
		for j := 0; j < n; j++ {
			out[i][j] = make([]*big.Int, s)
			for k := 0; k < s; k++ {
				out[i][j][k] = benchcore.Scalar(label, i*n*s+j*s+k)
			}
		}
	}
	return out
}

func miaoFiles(m, n int) []struct {
	FID      string
	Keywords []string
	Blocks   []*big.Int
} {
	files := make([]struct {
		FID      string
		Keywords []string
		Blocks   []*big.Int
	}, m)
	for i := 0; i < m; i++ {
		blocks := make([]*big.Int, n)
		for j := 0; j < n; j++ {
			blocks[j] = benchcore.Scalar("miao", i*n+j)
		}
		files[i] = struct {
			FID      string
			Keywords []string
			Blocks   []*big.Int
		}{
			FID:      fmt.Sprintf("file-%d", i),
			Keywords: []string{"audit", fmt.Sprintf("kw-%d", i%3)},
			Blocks:   blocks,
		}
	}
	return files
}

func timed(fn func() bool) timedResult {
	runtime.GC()
	start := time.Now()
	ok := fn()
	return timedResult{duration: time.Since(start), ok: ok}
}

func failedResults() map[string]timedResult {
	return map[string]timedResult{
		"Store":     {ok: false},
		"Challenge": {ok: false},
		"ProofGen":  {ok: false},
		"Verify":    {ok: false},
	}
}

func createCSV(path string) (*os.File, *csv.Writer, error) {
	if err := os.MkdirAll(parentDir(path), 0o755); err != nil {
		return nil, nil, err
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	return file, csv.NewWriter(file), nil
}

func writeCSVHeader(w *csv.Writer) error {
	header := []string{"measurement_method", "scenario", "variable", "value", "scheme", "phase", "m", "B_MB", "s", "c", "n", "seconds", "seconds_stddev", "repeats", "ok"}
	return w.Write(header)
}

func writeCSVRows(w *csv.Writer, rows []row) error {
	for _, r := range rows {
		record := []string{
			"protocol_execution",
			r.Scenario,
			r.Variable,
			strconv.Itoa(r.Value),
			r.Scheme,
			r.Phase,
			strconv.Itoa(r.Params.M),
			strconv.Itoa(r.Params.BMB),
			strconv.Itoa(r.Params.S),
			strconv.Itoa(r.Params.C),
			strconv.Itoa(r.Params.N()),
			strconv.FormatFloat(r.Seconds, 'f', 9, 64),
			strconv.FormatFloat(r.StdDev, 'f', 9, 64),
			strconv.Itoa(r.Repeats),
			strconv.FormatBool(r.OK),
		}
		if err := w.Write(record); err != nil {
			return err
		}
	}
	return nil
}

func medianStdDev(values []float64) (float64, float64) {
	if len(values) == 0 {
		return 0, 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	mid := len(sorted) / 2
	median := sorted[mid]
	if len(sorted)%2 == 0 {
		median = (sorted[mid-1] + sorted[mid]) / 2
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	mean := sum / float64(len(values))
	if len(values) == 1 {
		return median, 0
	}
	var squared float64
	for _, v := range values {
		diff := v - mean
		squared += diff * diff
	}
	return median, math.Sqrt(squared / float64(len(values)-1))
}

func intRange(start, end, step int) []int {
	var out []int
	for v := start; v <= end; v += step {
		out = append(out, v)
	}
	return out
}

func parentDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

type deterministicReader struct {
	state uint64
}

func newDeterministicReader(seed uint64) *deterministicReader {
	return &deterministicReader{state: seed}
}

func (r *deterministicReader) Read(p []byte) (int, error) {
	for i := range p {
		r.state = r.state*6364136223846793005 + 1442695040888963407
		p[i] = byte(r.state >> 56)
	}
	return len(p), nil
}
