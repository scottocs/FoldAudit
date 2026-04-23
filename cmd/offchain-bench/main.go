package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"pdp26/crypto/pdpbatch"
)

type correctnessResult struct {
	Config           map[string]any `json:"config"`
	ChallengeIndices []int          `json:"challengeIndices"`
	HonestAccept     bool           `json:"honestAccept"`
	TamperedAccept   bool           `json:"tamperedAccept"`
}

type benchmarkRow struct {
	AuthMode             string  `json:"authMode"`
	NumFiles             int     `json:"numFiles"`
	ChunksPerFile        int     `json:"chunksPerFile"`
	SectorsPerChunk      int     `json:"sectorsPerChunk"`
	ChallengedChunks     int     `json:"challengedChunks"`
	Repeats              int     `json:"repeats"`
	TimingRounds         int     `json:"timingRoundsPerRepeat"`
	AvgStoreMS           float64 `json:"avgStoreMs"`
	AvgProofgenMS        float64 `json:"avgProofgenMs"`
	AvgVerifyMS          float64 `json:"avgVerifyMs"`
	AvgStoreHashes       float64 `json:"avgStoreHashes"`
	AvgProofgenHashes    float64 `json:"avgProofgenHashes"`
	AvgVerifyHashes      float64 `json:"avgVerifyHashes"`
	AvgProofBytes        float64 `json:"avgProofBytes"`
	AvgAuthHashNodes     float64 `json:"avgAuthHashNodes"`
	AvgChallengeBytes    float64 `json:"avgChallengeBytes"`
	AvgStoredPayloadByte float64 `json:"avgStoredPayloadBytes"`
}

type runResult struct {
	GeneratedAt  string            `json:"generatedAt"`
	Mode         string            `json:"mode"`
	Quick        bool              `json:"quick"`
	Repeats      int               `json:"repeats"`
	TimingRounds int               `json:"timingRoundsPerRepeat"`
	Correctness  correctnessResult `json:"correctness"`
	Rows         []benchmarkRow    `json:"rows"`
	CSVPath      string            `json:"csvPath"`
	Notes        []string          `json:"notes"`
}

// main 组织离线 PDP 基准测试：先跑正确性演示，再输出 JSON 汇总和 CSV 明细。
func main() {
	quick := flag.Bool("quick", true, "run the smaller off-chain benchmark sweep; use --quick=false for the larger sweep")
	repeats := flag.Int("repeats", 3, "benchmark repeats per configuration")
	timingRounds := flag.Int("timing-rounds", 50, "inner timing rounds per repeat for proof generation and verification")
	outPath := flag.String("out", repoPath("results", "offchain_benchmark_summary.json"), "summary JSON output path")
	csvPath := flag.String("csv", repoPath("results", "offchain_benchmark_results.csv"), "CSV output path")
	flag.Parse()

	if *repeats <= 0 {
		log.Fatal("repeats must be positive")
	}
	if *timingRounds <= 0 {
		log.Fatal("timing-rounds must be positive")
	}

	correctness, err := runCorrectnessDemo()
	if err != nil {
		log.Fatalf("correctness demo: %v", err)
	}
	rows, err := runBenchmarkSuite(*quick, *repeats, *timingRounds)
	if err != nil {
		log.Fatalf("benchmark suite: %v", err)
	}
	if err := writeCSV(*csvPath, rows); err != nil {
		log.Fatalf("write csv: %v", err)
	}

	result := runResult{
		GeneratedAt:  time.Now().Format(time.RFC3339),
		Mode:         "offchain-third-party-verifier",
		Quick:        *quick,
		Repeats:      *repeats,
		TimingRounds: *timingRounds,
		Correctness:  correctness,
		Rows:         rows,
		CSVPath:      *csvPath,
		Notes: []string{
			"All protocol work is executed off-chain.",
			"verify_ms is the third-party verifier's local verification time averaged over timing_rounds per repeat.",
			"The KZG backend in crypto/pdpbatch uses gnark-crypto BLS12-381 G1/G2 groups and pairing checks.",
		},
	}
	if err := writeJSON(*outPath, result); err != nil {
		log.Fatalf("write summary: %v", err)
	}

	pretty, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(pretty))
}

// runCorrectnessDemo 生成一轮诚实证明和一轮篡改证明，用于确认协议能接受诚实数据并拒绝被改动的数据。
func runCorrectnessDemo() (correctnessResult, error) {
	protocol, err := pdpbatch.NewBatchPDPProtocol(pdpbatch.DefaultProtocolConfig())
	if err != nil {
		return correctnessResult{}, err
	}
	dataset := protocol.RandomFileBatch()
	storedBatch, err := protocol.Store(dataset)
	if err != nil {
		return correctnessResult{}, err
	}
	challenge := protocol.Challenge()
	honestProof, err := protocol.ProofGen(storedBatch, challenge, pdpbatch.AuthModeMP)
	if err != nil {
		return correctnessResult{}, err
	}
	honestAccept := protocol.Verify(storedBatch, challenge, honestProof)

	tamperedBatch := protocol.CloneStoredBatch(storedBatch)
	if err := protocol.TamperChallengedSector(tamperedBatch, challenge); err != nil {
		return correctnessResult{}, err
	}
	tamperedProof, err := protocol.ProofGen(tamperedBatch, challenge, pdpbatch.AuthModeMP)
	if err != nil {
		return correctnessResult{}, err
	}
	tamperedAccept := protocol.Verify(tamperedBatch, challenge, tamperedProof)

	return correctnessResult{
		Config:           protocol.ConfigDict(),
		ChallengeIndices: append([]int(nil), challenge.Indices...),
		HonestAccept:     honestAccept,
		TamperedAccept:   tamperedAccept,
	}, nil
}

// runBenchmarkSuite 遍历不同规模和认证模式，收集存储、证明生成、验证耗时以及证明大小等指标。
func runBenchmarkSuite(quick bool, repeats int, timingRounds int) ([]benchmarkRow, error) {
	rows := make([]benchmarkRow, 0)
	for _, config := range sweepConfigs(quick) {
		for _, authMode := range []pdpbatch.AuthMode{pdpbatch.AuthModeSP, pdpbatch.AuthModeMP} {
			storeTimes := make([]float64, 0, repeats)
			proofgenTimes := make([]float64, 0, repeats)
			verifyTimes := make([]float64, 0, repeats)
			storeHashes := make([]float64, 0, repeats)
			proofgenHashes := make([]float64, 0, repeats)
			verifyHashes := make([]float64, 0, repeats)
			proofBytes := make([]float64, 0, repeats)
			authHashNodes := make([]float64, 0, repeats)
			challengeBytes := make([]float64, 0, repeats)
			storedPayloadBytes := make([]float64, 0, repeats)

			for repeat := 0; repeat < repeats; repeat++ {
				runConfig := config
				runConfig.RNGSeed += int64(repeat)
				protocol, err := pdpbatch.NewBatchPDPProtocol(runConfig)
				if err != nil {
					return nil, err
				}

				dataset := protocol.RandomFileBatch()
				storeBefore := protocol.Counter.Snapshot()
				storedBatch, err := protocol.Store(dataset)
				if err != nil {
					return nil, err
				}
				storeAfter := protocol.Counter.Snapshot()
				storeMS, err := measureAverage(timingRounds, func() error {
					_, err := protocol.Store(dataset)
					return err
				})
				if err != nil {
					return nil, err
				}

				challenge := protocol.Challenge()
				proofgenBefore := protocol.Counter.Snapshot()
				proof, err := protocol.ProofGen(storedBatch, challenge, authMode)
				if err != nil {
					return nil, err
				}
				proofgenAfter := protocol.Counter.Snapshot()
				verifyBefore := protocol.Counter.Snapshot()
				accepted := protocol.Verify(storedBatch, challenge, proof)
				verifyAfter := protocol.Counter.Snapshot()
				if !accepted {
					return nil, fmt.Errorf("honest %s proof should verify", authMode)
				}

				proofgenMS, err := measureAverage(timingRounds, func() error {
					_, err := protocol.ProofGen(storedBatch, challenge, authMode)
					return err
				})
				if err != nil {
					return nil, err
				}
				verifyMS, err := measureAverage(timingRounds, func() error {
					if !protocol.Verify(storedBatch, challenge, proof) {
						return fmt.Errorf("honest %s proof rejected during timing", authMode)
					}
					return nil
				})
				if err != nil {
					return nil, err
				}

				sizeReport := protocol.SizeReport(challenge, proof)
				storeOps := pdpbatch.DiffCounters(storeAfter, storeBefore)
				proofgenOps := pdpbatch.DiffCounters(proofgenAfter, proofgenBefore)
				verifyOps := pdpbatch.DiffCounters(verifyAfter, verifyBefore)

				storeTimes = append(storeTimes, roundFloat(storeMS, 6))
				proofgenTimes = append(proofgenTimes, proofgenMS)
				verifyTimes = append(verifyTimes, verifyMS)
				storeHashes = append(storeHashes, float64(storeOps["hashes"]))
				proofgenHashes = append(proofgenHashes, float64(proofgenOps["hashes"]))
				verifyHashes = append(verifyHashes, float64(verifyOps["hashes"]))
				proofBytes = append(proofBytes, float64(sizeReport["proof_bytes"]))
				authHashNodes = append(authHashNodes, float64(sizeReport["auth_hash_nodes"]))
				challengeBytes = append(challengeBytes, float64(sizeReport["challenge_bytes"]))
				storedPayloadBytes = append(storedPayloadBytes, float64(sizeReport["store_bytes"]))
			}

			rows = append(rows, benchmarkRow{
				AuthMode:             string(authMode),
				NumFiles:             config.NumFiles,
				ChunksPerFile:        config.ChunksPerFile,
				SectorsPerChunk:      config.SectorsPerChunk,
				ChallengedChunks:     config.ChallengedChunks,
				Repeats:              repeats,
				TimingRounds:         timingRounds,
				AvgStoreMS:           mean(storeTimes, 6),
				AvgProofgenMS:        mean(proofgenTimes, 6),
				AvgVerifyMS:          mean(verifyTimes, 6),
				AvgStoreHashes:       mean(storeHashes, 3),
				AvgProofgenHashes:    mean(proofgenHashes, 3),
				AvgVerifyHashes:      mean(verifyHashes, 3),
				AvgProofBytes:        mean(proofBytes, 3),
				AvgAuthHashNodes:     mean(authHashNodes, 3),
				AvgChallengeBytes:    mean(challengeBytes, 3),
				AvgStoredPayloadByte: mean(storedPayloadBytes, 3),
			})
		}
	}
	return rows, nil
}

// sweepConfigs 根据 quick 参数返回一组协议规模配置，用于控制基准测试覆盖范围。
func sweepConfigs(quick bool) []pdpbatch.ProtocolConfig {
	configs := []pdpbatch.ProtocolConfig{}
	add := func(numFiles, chunksPerFile, sectorsPerChunk, challengedChunks int, seed int64) {
		config := pdpbatch.DefaultProtocolConfig()
		config.NumFiles = numFiles
		config.ChunksPerFile = chunksPerFile
		config.SectorsPerChunk = sectorsPerChunk
		config.ChallengedChunks = challengedChunks
		config.RNGSeed = seed
		configs = append(configs, config)
	}

	if quick {
		add(2, 32, 8, 4, 11)
		add(4, 64, 8, 8, 13)
		add(8, 64, 8, 8, 17)
		return configs
	}

	add(2, 64, 8, 4, 11)
	add(4, 64, 8, 8, 13)
	add(8, 128, 8, 8, 17)
	add(16, 128, 8, 16, 19)
	return configs
}

// writeCSV 将每组基准测试结果写入 CSV，便于后续用表格或脚本分析。
func writeCSV(path string, rows []benchmarkRow) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{
		"auth_mode",
		"num_files",
		"chunks_per_file",
		"sectors_per_chunk",
		"challenged_chunks",
		"repeats",
		"timing_rounds_per_repeat",
		"avg_store_ms",
		"avg_proofgen_ms",
		"avg_verify_ms",
		"avg_store_hashes",
		"avg_proofgen_hashes",
		"avg_verify_hashes",
		"avg_proof_bytes",
		"avg_auth_hash_nodes",
		"avg_challenge_bytes",
		"avg_stored_payload_bytes",
	}
	if err := writer.Write(header); err != nil {
		return err
	}
	for _, row := range rows {
		record := []string{
			row.AuthMode,
			strconv.Itoa(row.NumFiles),
			strconv.Itoa(row.ChunksPerFile),
			strconv.Itoa(row.SectorsPerChunk),
			strconv.Itoa(row.ChallengedChunks),
			strconv.Itoa(row.Repeats),
			strconv.Itoa(row.TimingRounds),
			formatFloat(row.AvgStoreMS),
			formatFloat(row.AvgProofgenMS),
			formatFloat(row.AvgVerifyMS),
			formatFloat(row.AvgStoreHashes),
			formatFloat(row.AvgProofgenHashes),
			formatFloat(row.AvgVerifyHashes),
			formatFloat(row.AvgProofBytes),
			formatFloat(row.AvgAuthHashNodes),
			formatFloat(row.AvgChallengeBytes),
			formatFloat(row.AvgStoredPayloadByte),
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}
	return writer.Error()
}

// writeJSON 以缩进 JSON 的形式写出汇总结果，并自动创建目标目录。
func writeJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// measureAverage 重复执行目标函数并返回单次平均耗时，单位为毫秒。
func measureAverage(rounds int, fn func() error) (float64, error) {
	start := time.Now()
	for i := 0; i < rounds; i++ {
		if err := fn(); err != nil {
			return 0, err
		}
	}
	elapsedMS := float64(time.Since(start).Nanoseconds()) / 1_000_000
	return roundFloat(elapsedMS/float64(rounds), 6), nil
}

// mean 计算浮点数组的平均值，并按指定小数位做四舍五入。
func mean(values []float64, decimals int) float64 {
	var total float64
	for _, value := range values {
		total += value
	}
	return roundFloat(total/float64(len(values)), decimals)
}

// roundFloat 将浮点数四舍五入到指定小数位。
func roundFloat(value float64, decimals int) float64 {
	scale := math.Pow10(decimals)
	return math.Round(value*scale) / scale
}

// formatFloat 将浮点数格式化为无多余尾零的十进制字符串。
func formatFloat(value float64) string {
	return strconv.FormatFloat(value, 'f', -1, 64)
}

// repoPath 基于当前命令源码位置拼出仓库根目录下的路径，避免运行目录变化影响输出位置。
func repoPath(parts ...string) string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return filepath.Join(parts...)
	}
	cmdDir := filepath.Dir(thisFile)
	moduleRoot := filepath.Clean(filepath.Join(cmdDir, "..", ".."))
	all := append([]string{moduleRoot}, parts...)
	return filepath.Join(all...)
}
