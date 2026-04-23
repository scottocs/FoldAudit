package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"

	"pdp26/contracts"
	"pdp26/crypto/kzg"
)

const SepoliaChainID = 11155111

type cliConfig struct {
	RPCURL          string
	PrivateKeyHex   string
	ContractAddress string
	Samples         int
	Timeout         time.Duration
	OutputPath      string
}

var simulatedContractAddress = common.HexToAddress("0x000000000000000000000000000000000000dEaD")

type deploymentResult struct {
	Address           string `json:"address,omitempty"`
	TxHash            string `json:"txHash,omitempty"`
	GasUsed           uint64 `json:"gasUsed,omitempty"`
	GasEstimate       uint64 `json:"gasEstimate,omitempty"`
	EffectiveGasPrice string `json:"effectiveGasPriceWei,omitempty"`
	TxFeeWei          string `json:"txFeeWei,omitempty"`
	BlockNumber       uint64 `json:"blockNumber,omitempty"`
	DeployedByScript  bool   `json:"deployedByScript"`
}

type callResult struct {
	SampleSeed        uint64 `json:"sampleSeed"`
	VersionedHash     string `json:"versionedHash"`
	Point             string `json:"point"`
	Claim             string `json:"claim"`
	Commitment        string `json:"commitment"`
	Proof             string `json:"proof"`
	EthCallOK         bool   `json:"ethCallOK"`
	FieldElements     string `json:"fieldElementsPerBlob,omitempty"`
	BLSModulus        string `json:"blsModulus,omitempty"`
	GasEstimate       uint64 `json:"gasEstimate,omitempty"`
	TxHash            string `json:"txHash,omitempty"`
	GasUsed           uint64 `json:"gasUsed,omitempty"`
	EffectiveGasPrice string `json:"effectiveGasPriceWei,omitempty"`
	TxFeeWei          string `json:"txFeeWei,omitempty"`
	BlockNumber       uint64 `json:"blockNumber,omitempty"`
	TransactionSent   bool   `json:"transactionSent"`
}

type runResult struct {
	GeneratedAt       string           `json:"generatedAt"`
	ChainID           string           `json:"chainId"`
	RPCURL            string           `json:"rpcUrl"`
	Contract          deploymentResult `json:"contract"`
	ArtifactVersion   string           `json:"artifactSolcVersion"`
	PrivateKeyPresent bool             `json:"privateKeyPresent"`
	FinalBalanceWei   string           `json:"finalBalanceWei,omitempty"`
	TotalSpentWei     string           `json:"totalSpentWei,omitempty"`
	Notes             []string         `json:"notes"`
	Calls             []callResult     `json:"calls"`
}

func main() {
	cfg := cliConfig{}
	flag.StringVar(&cfg.RPCURL, "rpc", envFirst("SEPOLIA_RPC_URL", "RPC_URL"), "Sepolia RPC URL")
	flag.StringVar(&cfg.PrivateKeyHex, "private-key", envFirst("SEPOLIA_PRIVATE_KEY", "PRIVATE_KEY"), "deployer private key")
	//在用户环境变量中添加地址的私钥，或者直接通过命令行参数传入地址的私钥，程序会使用这个私钥来部署合约和发送交易。如果没有提供私钥，程序将模拟合约部署并仅执行eth_call和estimateGas，不会发送任何交易。
	flag.StringVar(&cfg.ContractAddress, "contract", "", "existing wrapper contract address; skips deployment when set")
	flag.IntVar(&cfg.Samples, "samples", 3, "number of KZG samples to execute")
	flag.DurationVar(&cfg.Timeout, "timeout", 2*time.Minute, "timeout for each chain operation")
	flag.StringVar(&cfg.OutputPath, "out", defaultOutputPath(), "result json path")
	flag.Parse()

	if cfg.RPCURL == "" {
		log.Fatal("missing Sepolia RPC URL; set --rpc or SEPOLIA_RPC_URL")
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	client, err := ethclient.DialContext(ctx, cfg.RPCURL)
	if err != nil {
		log.Fatalf("dial rpc: %v", err)
	}
	defer client.Close()

	chainID, err := client.ChainID(ctx)
	if err != nil {
		log.Fatalf("get chain id: %v", err)
	}
	if chainID.Cmp(big.NewInt(SepoliaChainID)) != 0 {
		log.Fatalf("rpc is not Sepolia: expected %d, got %s", SepoliaChainID, chainID.String())
	}

	artifact, parsedABI, bytecode, err := contracts.Load()
	if err != nil {
		log.Fatalf("load contract artifact: %v", err)
	}

	rpcClient, err := rpc.DialContext(ctx, cfg.RPCURL)
	if err != nil {
		log.Fatalf("dial raw rpc: %v", err)
	}
	defer rpcClient.Close()

	var privateKey *ecdsa.PrivateKey
	var from common.Address
	if cfg.PrivateKeyHex != "" {
		privateKey, err = parsePrivateKey(cfg.PrivateKeyHex)
		if err != nil {
			log.Fatalf("parse private key: %v", err)
		}
		from = ethcrypto.PubkeyToAddress(privateKey.PublicKey)
	}

	result := runResult{
		GeneratedAt:       time.Now().Format(time.RFC3339),
		ChainID:           chainID.String(),
		RPCURL:            cfg.RPCURL,
		ArtifactVersion:   artifact.SolcVersion,
		PrivateKeyPresent: privateKey != nil,
	}

	contractAddr, deployResult, useStateOverride, err := ensureContract(
		ctx,
		client,
		parsedABI,
		bytecode,
		cfg.ContractAddress,
		privateKey,
		from,
	)
	if err != nil {
		log.Fatalf("prepare contract: %v", err)
	}
	result.Contract = deployResult

	if privateKey == nil {
		result.Notes = append(result.Notes, "No private key was supplied, so no transactions were sent.")
	}
	if useStateOverride {
		result.Notes = append(result.Notes, "The wrapper contract was simulated on Sepolia via state override using the compiled runtime bytecode; gas values are estimateGas results, not receipt gasUsed.")
	} else if privateKey == nil {
		result.Notes = append(result.Notes, "The wrapper contract address was reused, so only eth_call / estimateGas were executed.")
	}

	totalSpent := big.NewInt(0)
	for i := 0; i < cfg.Samples; i++ {
		sample, err := kzg.NewSample(uint64(i + 1))
		if err != nil {
			log.Fatalf("build sample %d: %v", i+1, err)
		}

		callData, err := parsedABI.Pack(
			"verify",
			sample.VersionedHash,
			sample.Point,
			sample.Claim,
			sample.CommitmentBytes(),
			sample.ProofBytes(),
		)
		if err != nil {
			log.Fatalf("abi pack sample %d: %v", i+1, err)
		}

		callMsg := ethereum.CallMsg{
			From: from,
			To:   &contractAddr,
			Data: callData,
		}

		var estimate uint64
		var output []byte
		if useStateOverride {
			estimate, err = estimateGasWithOverride(ctx, rpcClient, callMsg, artifact.DeployedBytecode)
			if err != nil {
				log.Fatalf("estimate gas with override sample %d: %v", i+1, err)
			}
			output, err = callWithOverride(ctx, rpcClient, callMsg, artifact.DeployedBytecode)
			if err != nil {
				log.Fatalf("eth_call with override sample %d: %v", i+1, err)
			}
		} else {
			estimate, err = client.EstimateGas(ctx, callMsg)
			if err != nil {
				log.Fatalf("estimate gas sample %d: %v", i+1, err)
			}
			output, err = client.CallContract(ctx, callMsg, nil)
			if err != nil {
				log.Fatalf("eth_call sample %d: %v", i+1, err)
			}
		}
		values, err := parsedABI.Unpack("verify", output)
		if err != nil {
			log.Fatalf("unpack eth_call output sample %d: %v", i+1, err)
		}
		ok, fieldElements, modulus := decodeReturn(values)

		entry := callResult{
			SampleSeed:      sample.Seed,
			VersionedHash:   hexutil.Encode(sample.VersionedHash[:]),
			Point:           hexutil.Encode(sample.Point[:]),
			Claim:           hexutil.Encode(sample.Claim[:]),
			Commitment:      hexutil.Encode(sample.Commitment[:]),
			Proof:           hexutil.Encode(sample.Proof[:]),
			EthCallOK:       ok,
			FieldElements:   fieldElements.String(),
			BLSModulus:      modulus.String(),
			GasEstimate:     estimate,
			TransactionSent: false,
		}

		if privateKey != nil {
			txHash, gasUsed, blockNumber, effectiveGasPrice, txFeeWei, err := sendVerificationTx(ctx, client, parsedABI, contractAddr, privateKey, sample)
			if err != nil {
				log.Fatalf("send tx sample %d: %v", i+1, err)
			}
			entry.TransactionSent = true
			entry.TxHash = txHash.Hex()
			entry.GasUsed = gasUsed
			entry.BlockNumber = blockNumber
			entry.EffectiveGasPrice = effectiveGasPrice.String()
			entry.TxFeeWei = txFeeWei.String()
			totalSpent.Add(totalSpent, txFeeWei)
		}

		result.Calls = append(result.Calls, entry)
	}

	if result.Contract.TxFeeWei != "" {
		deployFee := new(big.Int)
		deployFee.SetString(result.Contract.TxFeeWei, 10)
		totalSpent.Add(totalSpent, deployFee)
	}
	if privateKey != nil {
		balance, err := client.BalanceAt(ctx, from, nil)
		if err != nil {
			log.Fatalf("fetch final balance: %v", err)
		}
		result.FinalBalanceWei = balance.String()
		result.TotalSpentWei = totalSpent.String()
	}

	if err := writeJSON(cfg.OutputPath, result); err != nil {
		log.Fatalf("write result file: %v", err)
	}

	pretty, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(pretty))
}

func ensureContract(
	ctx context.Context,
	client *ethclient.Client,
	parsedABI abi.ABI,
	bytecode []byte,
	contractFlag string,
	privateKey *ecdsa.PrivateKey,
	from common.Address,
) (common.Address, deploymentResult, bool, error) {
	if contractFlag != "" {
		addr := common.HexToAddress(contractFlag)
		return addr, deploymentResult{Address: addr.Hex(), DeployedByScript: false}, false, nil
	}
	if privateKey == nil {
		deployEstimate, err := client.EstimateGas(ctx, ethereum.CallMsg{From: from, Data: bytecode})
		if err != nil {
			return common.Address{}, deploymentResult{}, false, fmt.Errorf("estimate deployment gas without key: %w", err)
		}
		return simulatedContractAddress, deploymentResult{
			Address:          simulatedContractAddress.Hex(),
			DeployedByScript: false,
			GasEstimate:      deployEstimate,
		}, true, nil
	}

	auth, err := newTransactor(ctx, client, privateKey)
	if err != nil {
		return common.Address{}, deploymentResult{}, false, fmt.Errorf("create transactor: %w", err)
	}

	deployEstimate, err := client.EstimateGas(ctx, ethereum.CallMsg{From: from, Data: bytecode})
	if err != nil {
		return common.Address{}, deploymentResult{}, false, fmt.Errorf("estimate deployment gas: %w", err)
	}

	address, tx, _, err := bind.DeployContract(auth, parsedABI, bytecode, client)
	if err != nil {
		return common.Address{}, deploymentResult{}, false, fmt.Errorf("deploy contract: %w", err)
	}

	receipt, err := bind.WaitMined(ctx, client, tx)
	if err != nil {
		return common.Address{}, deploymentResult{}, false, fmt.Errorf("wait for deployment: %w", err)
	}
	if receipt.Status != 1 {
		return common.Address{}, deploymentResult{}, false, fmt.Errorf("deployment reverted: %s", tx.Hash().Hex())
	}

	txFeeWei := new(big.Int).Mul(new(big.Int).SetUint64(receipt.GasUsed), receipt.EffectiveGasPrice)
	return address, deploymentResult{
		Address:           address.Hex(),
		TxHash:            tx.Hash().Hex(),
		GasUsed:           receipt.GasUsed,
		GasEstimate:       deployEstimate,
		EffectiveGasPrice: receipt.EffectiveGasPrice.String(),
		TxFeeWei:          txFeeWei.String(),
		BlockNumber:       receipt.BlockNumber.Uint64(),
		DeployedByScript:  true,
	}, false, nil
}

func sendVerificationTx(
	ctx context.Context,
	client *ethclient.Client,
	parsedABI abi.ABI,
	contractAddr common.Address,
	privateKey *ecdsa.PrivateKey,
	sample *kzg.Sample,
) (common.Hash, uint64, uint64, *big.Int, *big.Int, error) {
	auth, err := newTransactor(ctx, client, privateKey)
	if err != nil {
		return common.Hash{}, 0, 0, nil, nil, fmt.Errorf("create transactor: %w", err)
	}
	contract := bind.NewBoundContract(contractAddr, parsedABI, client, client, client)
	tx, err := contract.Transact(
		auth,
		"verify",
		sample.VersionedHash,
		sample.Point,
		sample.Claim,
		sample.CommitmentBytes(),
		sample.ProofBytes(),
	)
	if err != nil {
		return common.Hash{}, 0, 0, nil, nil, fmt.Errorf("submit verify tx: %w", err)
	}
	receipt, err := bind.WaitMined(ctx, client, tx)
	if err != nil {
		return common.Hash{}, 0, 0, nil, nil, fmt.Errorf("wait verify tx: %w", err)
	}
	if receipt.Status != 1 {
		return tx.Hash(), receipt.GasUsed, 0, nil, nil, fmt.Errorf("verify tx reverted: %s", tx.Hash().Hex())
	}
	txFeeWei := new(big.Int).Mul(new(big.Int).SetUint64(receipt.GasUsed), receipt.EffectiveGasPrice)
	return tx.Hash(), receipt.GasUsed, receipt.BlockNumber.Uint64(), receipt.EffectiveGasPrice, txFeeWei, nil
}

func newTransactor(ctx context.Context, client *ethclient.Client, privateKey *ecdsa.PrivateKey) (*bind.TransactOpts, error) {
	chainID, err := client.ChainID(ctx)
	if err != nil {
		return nil, err
	}
	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
	if err != nil {
		return nil, err
	}
	tipCap, err := client.SuggestGasTipCap(ctx)
	if err != nil {
		return nil, err
	}
	head, err := client.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, err
	}
	feeCap := new(big.Int).Add(new(big.Int).Mul(head.BaseFee, big.NewInt(2)), tipCap)
	auth.Context = ctx
	auth.GasTipCap = tipCap
	auth.GasFeeCap = feeCap
	return auth, nil
}

func decodeReturn(values []interface{}) (bool, *big.Int, *big.Int) {
	ok := values[0].(bool)
	fieldElements := values[1].(*big.Int)
	modulus := values[2].(*big.Int)
	return ok, fieldElements, modulus
}

func parsePrivateKey(input string) (*ecdsa.PrivateKey, error) {
	clean := strings.TrimPrefix(strings.TrimSpace(input), "0x")
	if _, err := hex.DecodeString(clean); err != nil {
		return nil, fmt.Errorf("invalid hex private key: %w", err)
	}
	return ethcrypto.HexToECDSA(clean)
}

func envFirst(keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}

func defaultOutputPath() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "sepolia_kzg_gas.json"
	}
	cmdDir := filepath.Dir(thisFile)
	moduleRoot := filepath.Clean(filepath.Join(cmdDir, "..", ".."))
	return filepath.Join(moduleRoot, "results", "sepolia_kzg_gas.json")
}

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

func callWithOverride(ctx context.Context, rpcClient *rpc.Client, callMsg ethereum.CallMsg, deployedBytecode string) ([]byte, error) {
	var raw string
	callArg := map[string]any{
		"from": callMsg.From.Hex(),
		"to":   callMsg.To.Hex(),
		"data": hexutil.Encode(callMsg.Data),
	}
	overrides := map[string]any{
		callMsg.To.Hex(): map[string]any{
			"code": hexutil.Encode(common.FromHex(deployedBytecode)),
		},
	}
	if err := rpcClient.CallContext(ctx, &raw, "eth_call", callArg, "latest", overrides); err != nil {
		return nil, err
	}
	return hexutil.Decode(raw)
}

func estimateGasWithOverride(ctx context.Context, rpcClient *rpc.Client, callMsg ethereum.CallMsg, deployedBytecode string) (uint64, error) {
	var gas hexutil.Uint64
	callArg := map[string]any{
		"from": callMsg.From.Hex(),
		"to":   callMsg.To.Hex(),
		"data": hexutil.Encode(callMsg.Data),
	}
	overrides := map[string]any{
		callMsg.To.Hex(): map[string]any{
			"code": hexutil.Encode(common.FromHex(deployedBytecode)),
		},
	}
	if err := rpcClient.CallContext(ctx, &gas, "eth_estimateGas", callArg, "latest", overrides); err != nil {
		return 0, err
	}
	return uint64(gas), nil
}
