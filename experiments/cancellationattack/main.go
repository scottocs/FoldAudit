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

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"

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
	scheme   string
	trials   int
	accepted int
	attackMS float64
	verifyMS float64
	totalMS  float64
}

func main() {
	trialsFlag := flag.Int("trials", 20, "trials per scheme")
	mFlag := flag.Int("m", 4, "files per batch")
	nFlag := flag.Int("n", 64, "chunks/blocks per file")
	sFlag := flag.Int("s", 8, "sectors per chunk")
	cFlag := flag.Int("c", 8, "challenged chunks per file")
	outFlag := flag.String("out", "", "optional CSV output path")
	flag.Parse()

	if *trialsFlag <= 0 {
		fatalf("-trials must be positive")
	}
	if *mFlag < 2 {
		fatalf("-m must be at least 2 for cancellation attempts")
	}
	if *cFlag <= 0 || *cFlag > *nFlag {
		fatalf("-c must be in [1,n]")
	}

	benches := []struct {
		name string
		run  func(trial, m, n, s, c int) (bool, time.Duration, time.Duration, error)
	}{
		{"YuTC25", runYu},
		{"ZhangTPDS23", runZhang},
		{"MiaoSCIS2026", runMiao},
		{"XuTIFS26", runXu},
		{"FoldAudit", runFoldAudit},
	}

	results := make([]result, 0, len(benches))
	for _, bench := range benches {
		row := measure(bench.name, *trialsFlag, func(trial int) (bool, time.Duration, time.Duration, error) {
			return bench.run(trial, *mFlag, *nFlag, *sFlag, *cFlag)
		})
		results = append(results, row)
	}

	printResults(*mFlag, *nFlag, *sFlag, *cFlag, results)
	if *outFlag != "" {
		if err := writeCSV(*outFlag, results); err != nil {
			fatalf("write CSV: %v", err)
		}
	}
}

func measure(name string, trials int, run func(trial int) (bool, time.Duration, time.Duration, error)) result {
	accepted := 0
	attackTotal := 0.0
	verifyTotal := 0.0
	for trial := 0; trial < trials; trial++ {
		ok, attackElapsed, verifyElapsed, err := run(trial)
		if err != nil {
			fatalf("%s trial %d failed: %v", name, trial, err)
		}
		if ok {
			accepted++
		}
		attackTotal += float64(attackElapsed.Nanoseconds()) / 1e6
		verifyTotal += float64(verifyElapsed.Nanoseconds()) / 1e6
	}
	attackMean := attackTotal / float64(trials)
	verifyMean := verifyTotal / float64(trials)
	return result{
		scheme:   name,
		trials:   trials,
		accepted: accepted,
		attackMS: attackMean,
		verifyMS: verifyMean,
		totalMS:  attackMean + verifyMean,
	}
}

func runYu(trial, m, n, s, c int) (bool, time.Duration, time.Duration, error) {
	p := yutc25.NewProtocol(n, s)
	stored, err := p.StoreBatch(dataset(m, n, s, "yu", trial))
	if err != nil {
		return false, 0, 0, err
	}
	chal := yutc25.BatchChallenge{FileChallenges: make([]yutc25.Challenge, m)}
	for i := range chal.FileChallenges {
		chal.FileChallenges[i] = p.ChallengeFromKeys(seed("yu-k1", trial, i), seed("yu-k2", trial, i), c)
	}
	proof, err := p.ProveBatch(stored, chal)
	if err != nil {
		return false, 0, 0, err
	}

	attackStart := time.Now()
	forged := &yutc25.BatchProof{Proofs: make([]*yutc25.Proof, len(proof.Proofs))}
	copy(forged.Proofs, proof.Proofs)
	forged.Proofs[0] = cloneYuProof(proof.Proofs[0])
	forged.Proofs[1] = cloneYuProof(proof.Proofs[1])
	forged.Proofs[0].Value = benchcore.Add(forged.Proofs[0].Value, benchcore.One())
	forged.Proofs[1].Value = benchcore.Sub(forged.Proofs[1].Value, benchcore.One())
	attackElapsed := time.Since(attackStart)

	verifyStart := time.Now()
	ok := true
	for i := range stored.Files {
		if !p.Verify(stored.Roots[i], chal.FileChallenges[i], forged.Proofs[i]) {
			ok = false
		}
	}
	return ok, attackElapsed, time.Since(verifyStart), nil
}

func runZhang(trial, m, n, s, c int) (bool, time.Duration, time.Duration, error) {
	p := zhangtpds23.NewProtocol(m, n, s)
	stored, err := p.Store(dataset(m, n, s, "zhang", trial))
	if err != nil {
		return false, 0, 0, err
	}
	chal := p.ChallengeFromSeed(seed("zhang-chal", trial, 0), c)

	attackStart := time.Now()
	betas := zhangBetas(chal, m)
	delta0 := benchcore.One()
	scale0 := benchcore.Mul(betas[0], chal.Coeffs[0][0])
	scale1 := benchcore.Mul(betas[1], chal.Coeffs[1][0])
	invScale1, err := benchcore.Inv(scale1)
	if err != nil {
		return false, 0, 0, err
	}
	delta1 := benchcore.Neg(benchcore.Mul(scale0, invScale1))
	stored.Files[0].Blocks[chal.Indices[0][0]].Coeffs[0] = benchcore.Add(stored.Files[0].Blocks[chal.Indices[0][0]].Coeffs[0], delta0)
	stored.Files[1].Blocks[chal.Indices[1][0]].Coeffs[0] = benchcore.Add(stored.Files[1].Blocks[chal.Indices[1][0]].Coeffs[0], delta1)
	proof, err := p.Prove(stored, chal)
	if err != nil {
		return false, 0, 0, err
	}
	attackElapsed := time.Since(attackStart)

	verifyStart := time.Now()
	ok := p.Verify(stored, chal, proof)
	return ok, attackElapsed, time.Since(verifyStart), nil
}

func runMiao(trial, m, n, s, c int) (bool, time.Duration, time.Duration, error) {
	_ = s
	p := miaoscis2026.NewProtocol(n)
	input := make([]struct {
		FID      string
		Keywords []string
		Blocks   []*big.Int
	}, m)
	for i := range input {
		input[i].FID = fmt.Sprintf("file-%d", i)
		input[i].Keywords = []string{"audit"}
		input[i].Blocks = make([]*big.Int, n)
		for j := range input[i].Blocks {
			input[i].Blocks[j] = scalar("miao", trial, i, j, 0)
		}
	}
	stored, err := p.Store(input)
	if err != nil {
		return false, 0, 0, err
	}
	trap, err := p.Trapdoor(stored, []string{"audit"})
	if err != nil {
		return false, 0, 0, err
	}
	chal := p.ChallengeWithTrapdoor(trap, c, m)

	attackStart := time.Now()
	delta0 := benchcore.One()
	scale0 := chal.Coeffs[0][0]
	scale1 := chal.Coeffs[1][0]
	invScale1, err := benchcore.Inv(scale1)
	if err != nil {
		return false, 0, 0, err
	}
	delta1 := benchcore.Neg(benchcore.Mul(scale0, invScale1))
	stored.Files[0].Blocks[chal.Indices[0]] = benchcore.Add(stored.Files[0].Blocks[chal.Indices[0]], delta0)
	stored.Files[1].Blocks[chal.Indices[0]] = benchcore.Add(stored.Files[1].Blocks[chal.Indices[0]], delta1)
	proof, err := p.Prove(stored, chal)
	if err != nil {
		return false, 0, 0, err
	}
	attackElapsed := time.Since(attackStart)

	verifyStart := time.Now()
	ok := p.Verify(stored, chal, proof)
	return ok, attackElapsed, time.Since(verifyStart), nil
}

func runXu(trial, m, n, s, c int) (bool, time.Duration, time.Duration, error) {
	p := xutifs26.NewProtocol(m, n, s)
	stored, err := p.Store(dataset(m, n, s, "xu", trial))
	if err != nil {
		return false, 0, 0, err
	}
	chal := p.ChallengeFromSeed(seed("xu-chal", trial, 0), c)
	proof, err := p.Prove(stored, chal)
	if err != nil {
		return false, 0, 0, err
	}

	attackStart := time.Now()
	forged := &xutifs26.Proof{Files: make([]xutifs26.FileProof, len(proof.Files))}
	copy(forged.Files, proof.Files)
	forged.Files[0].Value = benchcore.Add(forged.Files[0].Value, benchcore.One())
	forged.Files[1].Value = benchcore.Sub(forged.Files[1].Value, benchcore.One())
	attackElapsed := time.Since(attackStart)

	verifyStart := time.Now()
	ok := p.Verify(stored, chal, forged)
	return ok, attackElapsed, time.Since(verifyStart), nil
}

func runFoldAudit(trial, m, n, s, c int) (bool, time.Duration, time.Duration, error) {
	cfg := foldaudit.DefaultConfig()
	cfg.NumFiles = m
	cfg.ChunksPerFile = n
	cfg.SectorsPerChunk = s
	cfg.ChallengedChunks = c
	p, err := foldaudit.Setup(cfg, newDeterministicReader(uint64(20260429+trial)))
	if err != nil {
		return false, 0, 0, err
	}
	data, err := p.RandomDataset()
	if err != nil {
		return false, 0, 0, err
	}
	stored, err := p.Store(data)
	if err != nil {
		return false, 0, 0, err
	}
	chal, err := p.Challenge()
	if err != nil {
		return false, 0, 0, err
	}

	attackStart := time.Now()
	rhoGuess := benchcore.ScalarFromBytes("foldaudit:cancellation-attack:rho-guess", benchcore.IntBytes(trial))
	proof, err := forgedFoldAuditProof(p, stored, chal, rhoGuess, trial)
	if err != nil {
		return false, 0, 0, err
	}
	attackElapsed := time.Since(attackStart)

	verifyStart := time.Now()
	ok := p.Verify(stored, chal, proof)
	return ok, attackElapsed, time.Since(verifyStart), nil
}

func forgedFoldAuditProof(protocol *foldaudit.Protocol, stored *foldaudit.StoredBatch, chal *foldaudit.Challenge, rhoGuess *big.Int, trial int) (*foldaudit.AuditProof, error) {
	deltas := make([]*big.Int, protocol.Config.NumFiles)
	for i := range deltas {
		deltas[i] = benchcore.Zero()
	}
	rhoInv, err := benchcore.Inv(rhoGuess)
	if err != nil {
		return nil, err
	}
	deltas[0] = benchcore.One()
	deltas[1] = benchcore.Neg(rhoInv)

	fileProofs := make([]foldaudit.FileProof, protocol.Config.NumFiles)
	piR := make([]foldaudit.SchnorrProof, protocol.Config.NumFiles)
	for i := range stored.Files {
		fi, err := foldAuditAggregatePolynomial(stored.Files[i], chal, i)
		if err != nil {
			return nil, err
		}
		yi := fi.Eval(chal.EvaluationPoints[i])
		wi, remainder := fi.SubConstant(yi).DivLinear(chal.EvaluationPoints[i])
		if remainder.Sign() != 0 {
			return nil, fmt.Errorf("file %d quotient has nonzero remainder", i)
		}
		auth, err := foldAuditAuthPaths(stored.Files[i], chal)
		if err != nil {
			return nil, err
		}
		fileProofs[i] = foldaudit.FileProof{
			Auth:   auth,
			YTilde: benchcore.Add(yi, deltas[i]),
			R:      benchcore.G1Zero(),
			Cw:     protocol.CommitPolynomial(wi),
			B:      protocol.CommitPolynomial(fi),
		}
		z := benchcore.ScalarFromBytes("foldaudit:cancellation-attack:schnorr-z", benchcore.IntBytes(trial), benchcore.IntBytes(i))
		piR[i] = foldaudit.SchnorrProof{A: benchcore.G1Base(z), Z: z}
	}
	return &foldaudit.AuditProof{FileProofs: fileProofs, PiR: piR}, nil
}

func foldAuditAggregatePolynomial(file foldaudit.StoredFile, chal *foldaudit.Challenge, fileIndex int) (benchcore.Poly, error) {
	out := benchcore.NewPoly([]*big.Int{benchcore.Zero()})
	for pos, chunkIndex := range chal.Indices {
		if chunkIndex < 0 || chunkIndex >= len(file.Polynomials) {
			return benchcore.Poly{}, fmt.Errorf("challenge index %d out of range", chunkIndex)
		}
		out = out.Add(file.Polynomials[chunkIndex].Scale(chal.Coefficients[fileIndex][pos]))
	}
	return out, nil
}

func foldAuditAuthPaths(file foldaudit.StoredFile, chal *foldaudit.Challenge) ([]foldaudit.TagProof, error) {
	out := make([]foldaudit.TagProof, len(chal.Indices))
	for pos, chunkIndex := range chal.Indices {
		path, err := file.Tree.Proof(chunkIndex)
		if err != nil {
			return nil, err
		}
		out[pos] = foldaudit.TagProof{Index: chunkIndex, Tag: file.Tags[chunkIndex], Path: path}
	}
	return out, nil
}

func cloneYuProof(proof *yutc25.Proof) *yutc25.Proof {
	return &yutc25.Proof{
		Quotient: proof.Quotient.Clone(),
		Openings: append([]yutc25.TagOpening(nil), proof.Openings...),
		Value:    benchcore.Normalize(proof.Value),
		B:        cloneG1(proof.B),
	}
}

func cloneG1(point *bn256.G1) *bn256.G1 {
	if point == nil {
		return nil
	}
	return new(bn256.G1).Set(point)
}

func zhangBetas(chal zhangtpds23.Challenge, m int) []*big.Int {
	out := make([]*big.Int, m)
	for i := range out {
		out[i] = benchcore.Mul(benchcore.Pow(chal.Gamma, i), zhangZExcept(chal.Points, i).Eval(chal.Z))
	}
	return out
}

func zhangZExcept(points []*big.Int, skip int) benchcore.Poly {
	subset := make([]*big.Int, 0, len(points)-1)
	for i, point := range points {
		if i != skip {
			subset = append(subset, point)
		}
	}
	return benchcore.ZPoly(subset)
}

func dataset(m, n, s int, label string, trial int) [][][]*big.Int {
	out := make([][][]*big.Int, m)
	for i := range out {
		out[i] = make([][]*big.Int, n)
		for j := range out[i] {
			out[i][j] = make([]*big.Int, s)
			for k := range out[i][j] {
				out[i][j][k] = scalar(label, trial, i, j, k)
			}
		}
	}
	return out
}

func scalar(label string, values ...int) *big.Int {
	parts := make([][]byte, 0, len(values))
	for _, value := range values {
		parts = append(parts, benchcore.IntBytes(value))
	}
	return benchcore.ScalarFromBytes("cancellation-attack:"+label, parts...)
}

func seed(label string, values ...int) []byte {
	parts := make([][]byte, 0, len(values))
	for _, value := range values {
		parts = append(parts, benchcore.IntBytes(value))
	}
	return benchcore.HashBytes("cancellation-attack:"+label, parts...)
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
	fmt.Printf("Cancellation-attack reproduction cost (m=%d, n=%d, s=%d, c=%d)\n\n", m, n, s, c)
	fmt.Printf("%-15s %-8s %-12s %-12s %-12s %-12s\n", "scheme", "trials", "accepted", "attack ms", "verify ms", "total ms")
	for _, row := range results {
		fmt.Printf("%-15s %-8d %-12s %-12.3f %-12.3f %-12.3f\n",
			row.scheme,
			row.trials,
			fmt.Sprintf("%d/%d", row.accepted, row.trials),
			row.attackMS,
			row.verifyMS,
			row.totalMS,
		)
	}
}

func writeCSV(path string, results []result) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	w := csv.NewWriter(file)
	defer w.Flush()
	if err := w.Write([]string{"scheme", "trials", "accepted", "accepted_rate", "attack_mean_ms", "verify_mean_ms", "total_mean_ms"}); err != nil {
		return err
	}
	for _, row := range results {
		record := []string{
			row.scheme,
			strconv.Itoa(row.trials),
			strconv.Itoa(row.accepted),
			fmt.Sprintf("%.8f", float64(row.accepted)/float64(row.trials)),
			fmt.Sprintf("%.8f", row.attackMS),
			fmt.Sprintf("%.8f", row.verifyMS),
			fmt.Sprintf("%.8f", row.totalMS),
		}
		if err := w.Write(record); err != nil {
			return err
		}
	}
	return w.Error()
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
