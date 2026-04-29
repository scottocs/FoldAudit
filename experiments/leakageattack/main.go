package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"
	"time"

	"foldaudit/schemes/benchcore"
	"foldaudit/schemes/foldaudit"
	"foldaudit/schemes/miaoscis2026"
	"foldaudit/schemes/xutifs26"
	"foldaudit/schemes/yutc25"
	"foldaudit/schemes/zhangtpds23"
)

type deterministicReader struct {
	state uint64
}

type result struct {
	scheme  string
	trials  int
	auditMS float64
	ok      bool
}

func main() {
	trialsFlag := flag.Int("trials", 20, "audit rounds per scheme")
	mFlag := flag.Int("m", 4, "files per batch")
	nFlag := flag.Int("n", 64, "chunks/blocks per file")
	sFlag := flag.Int("s", 8, "sectors per chunk")
	cFlag := flag.Int("c", 8, "challenged chunks per file")
	outFlag := flag.String("out", "", "optional CSV output path")
	flag.Parse()

	if *trialsFlag <= 0 {
		fatalf("-trials must be positive")
	}
	if *mFlag <= 0 || *nFlag <= 0 || *sFlag <= 0 || *cFlag <= 0 || *cFlag > *nFlag {
		fatalf("invalid dimensions")
	}

	benches := []struct {
		name string
		run  func(m, n, s, c, trials int) (result, error)
	}{
		{"YuTC25", runYu},
		{"ZhangTPDS23", runZhang},
		{"MiaoSCIS2026", runMiao},
		{"XuTIFS26", runXu},
		{"FoldAudit", runFoldAudit},
	}

	results := make([]result, 0, len(benches))
	for _, bench := range benches {
		row, err := bench.run(*mFlag, *nFlag, *sFlag, *cFlag, *trialsFlag)
		if err != nil {
			fatalf("%s failed: %v", bench.name, err)
		}
		results = append(results, row)
	}

	printResults(*mFlag, *nFlag, *sFlag, *cFlag, results)
	if *outFlag != "" {
		if err := writeCSV(*outFlag, *mFlag, *nFlag, *sFlag, *cFlag, results); err != nil {
			fatalf("write CSV: %v", err)
		}
	}
}

func runYu(m, n, s, c, trials int) (result, error) {
	p := yutc25.NewProtocol(n, s)
	stored, err := p.StoreBatch(dataset(m, n, s, "yu"))
	if err != nil {
		return result{}, err
	}
	return measure("YuTC25", trials, func(trial int) bool {
		chal := yutc25.BatchChallenge{FileChallenges: make([]yutc25.Challenge, m)}
		for i := range chal.FileChallenges {
			chal.FileChallenges[i] = p.ChallengeFromKeys(seed("yu-k1", trial, i), seed("yu-k2", trial, i), c)
		}
		proof, err := p.ProveBatch(stored, chal)
		return err == nil && p.VerifyBatch(stored, chal, proof)
	}), nil
}

func runZhang(m, n, s, c, trials int) (result, error) {
	p := zhangtpds23.NewProtocol(m, n, s)
	stored, err := p.Store(dataset(m, n, s, "zhang"))
	if err != nil {
		return result{}, err
	}
	return measure("ZhangTPDS23", trials, func(trial int) bool {
		chal := p.ChallengeFromSeed(seed("zhang-chal", trial, 0), c)
		proof, err := p.Prove(stored, chal)
		return err == nil && p.Verify(stored, chal, proof)
	}), nil
}

func runMiao(m, n, s, c, trials int) (result, error) {
	_ = s
	p := miaoscis2026.NewProtocol(n)
	stored, err := p.Store(miaoFiles(m, n))
	if err != nil {
		return result{}, err
	}
	trap, err := p.Trapdoor(stored, []string{"audit"})
	if err != nil {
		return result{}, err
	}
	return measure("MiaoSCIS2026", trials, func(trial int) bool {
		chal := p.ChallengeWithTrapdoor(trap, c, m)
		proof, err := p.Prove(stored, chal)
		return err == nil && p.Verify(stored, chal, proof)
	}), nil
}

func runXu(m, n, s, c, trials int) (result, error) {
	p := xutifs26.NewProtocol(m, n, s)
	stored, err := p.Store(dataset(m, n, s, "xu"))
	if err != nil {
		return result{}, err
	}
	return measure("XuTIFS26", trials, func(trial int) bool {
		chal := p.ChallengeFromSeed(seed("xu-chal", trial, 0), c)
		proof, err := p.Prove(stored, chal)
		return err == nil && p.Verify(stored, chal, proof)
	}), nil
}

func runFoldAudit(m, n, s, c, trials int) (result, error) {
	cfg := foldaudit.DefaultConfig()
	cfg.NumFiles = m
	cfg.ChunksPerFile = n
	cfg.SectorsPerChunk = s
	cfg.ChallengedChunks = c
	p, err := foldaudit.Setup(cfg, newDeterministicReader(20260501))
	if err != nil {
		return result{}, err
	}
	stored, err := p.Store(dataset(m, n, s, "foldaudit"))
	if err != nil {
		return result{}, err
	}
	return measure("FoldAudit", trials, func(trial int) bool {
		chal, err := p.Challenge()
		if err != nil {
			return false
		}
		proof, err := p.ProofGen(stored, chal)
		return err == nil && p.Verify(stored, chal, proof)
	}), nil
}

func measure(name string, trials int, run func(trial int) bool) result {
	total := 0.0
	ok := true
	for trial := 0; trial < trials; trial++ {
		start := time.Now()
		accepted := run(trial)
		total += float64(time.Since(start).Nanoseconds()) / 1e6
		ok = ok && accepted
	}
	return result{scheme: name, trials: trials, auditMS: total / float64(trials), ok: ok}
}

func dataset(m, n, s int, label string) [][][]*big.Int {
	out := make([][][]*big.Int, m)
	for i := range out {
		out[i] = make([][]*big.Int, n)
		for j := range out[i] {
			out[i][j] = make([]*big.Int, s)
			for k := range out[i][j] {
				out[i][j][k] = scalar(label, i, j, k)
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
	for i := range files {
		blocks := make([]*big.Int, n)
		for j := range blocks {
			blocks[j] = scalar("miao", i, j, 0)
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

func scalar(label string, values ...int) *big.Int {
	parts := make([][]byte, 0, len(values))
	for _, value := range values {
		parts = append(parts, benchcore.IntBytes(value))
	}
	return benchcore.ScalarFromBytes("leakage-attack:"+label, parts...)
}

func seed(label string, values ...int) []byte {
	parts := make([][]byte, 0, len(values))
	for _, value := range values {
		parts = append(parts, benchcore.IntBytes(value))
	}
	return benchcore.HashBytes("leakage-attack:"+label, parts...)
}

func newDeterministicReader(seed uint64) io.Reader {
	return &deterministicReader{state: seed}
}

func (r *deterministicReader) Read(p []byte) (int, error) {
	for i := range p {
		r.state = r.state*6364136223846793005 + 1442695040888963407
		p[i] = byte(r.state >> 56)
	}
	return len(p), nil
}

func printResults(m, n, s, c int, results []result) {
	fmt.Printf("Data-leakage audit-round cost (m=%d, n=%d, s=%d, c=%d)\n\n", m, n, s, c)
	fmt.Printf("%-15s %-8s %-12s %-8s\n", "scheme", "trials", "audit ms", "ok")
	for _, row := range results {
		fmt.Printf("%-15s %-8d %-12.3f %-8t\n", row.scheme, row.trials, row.auditMS, row.ok)
	}
}

func writeCSV(path string, m, n, s, c int, results []result) error {
	if err := os.MkdirAll(parentDir(path), 0o755); err != nil {
		return err
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	w := csv.NewWriter(file)
	defer w.Flush()
	if err := w.Write([]string{"scheme", "trials", "m", "n", "s", "c", "audit_mean_ms", "ok"}); err != nil {
		return err
	}
	for _, row := range results {
		record := []string{
			row.scheme,
			strconv.Itoa(row.trials),
			strconv.Itoa(m),
			strconv.Itoa(n),
			strconv.Itoa(s),
			strconv.Itoa(c),
			fmt.Sprintf("%.8f", row.auditMS),
			strconv.FormatBool(row.ok),
		}
		if err := w.Write(record); err != nil {
			return err
		}
	}
	return nil
}

func parentDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
