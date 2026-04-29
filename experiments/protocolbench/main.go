package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"math"
	"math/big"
	"os"
	"runtime"
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
	baseM         = 5
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

func main() {
	outPath := flag.String("out", "experiments/out/vi_evaluation/vi_overhead_all.csv", "output CSV path")
	profile := flag.String("profile", "paper", "benchmark profile: paper or quick")
	repeats := flag.Int("repeats", 3, "number of protocol executions to average per workload point")
	flag.Parse()
	if *repeats < 1 {
		fatal(fmt.Errorf("repeats must be at least 1"))
	}

	file, writer, err := createCSV(*outPath)
	if err != nil {
		fatal(err)
	}
	defer file.Close()
	if err := writeCSVHeader(writer); err != nil {
		fatal(err)
	}
	if err := runProfile(*profile, *repeats, func(rows []row) error {
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

func runProfile(profile string, repeats int, emit func([]row) error) error {
	var mValues, bValues, sValues []int
	switch profile {
	case "paper":
		mValues = intRange(5, 30, 5)
		bValues = intRange(10, 100, 10)
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
	if err := emit(runAllSchemes("baseline", "baseline", 0, baseline, repeats)); err != nil {
		return err
	}
	for _, m := range mValues {
		p := params{M: m, BMB: baseline.BMB, S: baseline.S, C: baseline.C}
		if err := emit(runAllSchemes("vary_m", "m", m, p, repeats)); err != nil {
			return err
		}
	}
	for _, b := range bValues {
		p := params{M: baseline.M, BMB: b, S: baseline.S, C: baseline.C}
		if err := emit(runAllSchemes("vary_B", "B_MB", b, p, repeats)); err != nil {
			return err
		}
	}
	for _, s := range sValues {
		p := params{M: baseline.M, BMB: baseline.BMB, S: s, C: baseline.C}
		if err := emit(runAllSchemes("vary_s", "s", s, p, repeats)); err != nil {
			return err
		}
	}
	return nil
}

func runAllSchemes(scenario, variable string, value int, p params, repeats int) []row {
	schemes := []struct {
		name string
		fn   func(params) map[string]timedResult
	}{
		{"YuTC25", runYu},
		{"ZhangTPDS23", runZhang},
		{"MiaoSCIS2026", runMiao},
		{"XuTIFS26", runXu},
		{"FoldAudit", runFoldAudit},
	}

	var rows []row
	for _, scheme := range schemes {
		fmt.Fprintf(os.Stderr, "running %s scenario=%s %s=%d m=%d B_MB=%d s=%d c=%d n=%d repeats=%d\n",
			scheme.name, scenario, variable, value, p.M, p.BMB, p.S, p.C, p.N(), repeats)
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
			mean, stddev := meanStdDev(samples[phase])
			rows = append(rows, row{Scenario: scenario, Variable: variable, Value: value, Scheme: scheme.name, Phase: phase, Params: p, Seconds: mean, StdDev: stddev, Repeats: repeats, OK: phaseOK[phase]})
		}
		mean, stddev := meanStdDev(samples["Audit"])
		rows = append(rows, row{Scenario: scenario, Variable: variable, Value: value, Scheme: scheme.name, Phase: "Audit", Params: p, Seconds: mean, StdDev: stddev, Repeats: repeats, OK: phaseOK["Audit"]})
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

func meanStdDev(values []float64) (float64, float64) {
	if len(values) == 0 {
		return 0, 0
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	mean := sum / float64(len(values))
	if len(values) == 1 {
		return mean, 0
	}
	var squared float64
	for _, v := range values {
		diff := v - mean
		squared += diff * diff
	}
	return mean, math.Sqrt(squared / float64(len(values)-1))
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
