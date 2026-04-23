package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	contractName = "KZGPointEvaluationWrapper"
	solcVersion  = "0.8.24"
)

type solcInput struct {
	Language string                       `json:"language"`
	Sources  map[string]map[string]string `json:"sources"`
	Settings solcSettings                 `json:"settings"`
}

type solcSettings struct {
	Optimizer       solcOptimizer                        `json:"optimizer"`
	OutputSelection map[string]map[string][]string       `json:"outputSelection"`
}

type solcOptimizer struct {
	Enabled bool `json:"enabled"`
	Runs    int  `json:"runs"`
}

type solcOutput struct {
	Contracts map[string]map[string]solcContract `json:"contracts"`
	Errors    []struct {
		Severity string `json:"severity"`
		Message  string `json:"message"`
	} `json:"errors,omitempty"`
}

type solcContract struct {
	ABI json.RawMessage `json:"abi"`
	EVM struct {
		Bytecode        struct{ Object string `json:"object"` } `json:"bytecode"`
		DeployedBytecode struct{ Object string `json:"object"` } `json:"deployedBytecode"`
	} `json:"evm"`
}

type artifact struct {
	ContractName     string          `json:"contractName"`
	ABI              json.RawMessage `json:"abi"`
	Bytecode         string          `json:"bytecode"`
	DeployedBytecode string          `json:"deployedBytecode"`
	SolcVersion      string          `json:"solcVersion"`
}

func main() {
	contractsDir := flag.String("dir", "contracts", "path to contracts directory")
	flag.Parse()

	solFile := filepath.Join(*contractsDir, contractName+".sol")
	outFile := filepath.Join(*contractsDir, contractName+".json")

	src, err := os.ReadFile(solFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", solFile, err)
		os.Exit(1)
	}

	input := solcInput{
		Language: "Solidity",
		Sources: map[string]map[string]string{
			contractName + ".sol": {"content": string(src)},
		},
		Settings: solcSettings{
			Optimizer: solcOptimizer{Enabled: true, Runs: 200},
			OutputSelection: map[string]map[string][]string{
				"*": {"*": {"abi", "evm.bytecode.object", "evm.deployedBytecode.object"}},
			},
		},
	}

	inputJSON, err := json.Marshal(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal solc input: %v\n", err)
		os.Exit(1)
	}

	cmd := exec.Command("solc", "--standard-json")
	cmd.Stdin = bytes.NewReader(inputJSON)
	out, err := cmd.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "solc: %v\n", err)
		os.Exit(1)
	}

	var compiled solcOutput
	if err := json.Unmarshal(out, &compiled); err != nil {
		fmt.Fprintf(os.Stderr, "parse solc output: %v\n", err)
		os.Exit(1)
	}

	for _, e := range compiled.Errors {
		if e.Severity == "error" {
			fmt.Fprintf(os.Stderr, "solc error: %s\n", e.Message)
			os.Exit(1)
		}
	}

	fileContracts, ok := compiled.Contracts[contractName+".sol"]
	if !ok {
		fmt.Fprintf(os.Stderr, "source file %s.sol not found in solc output\n", contractName)
		os.Exit(1)
	}
	contract, ok := fileContracts[contractName]
	if !ok {
		fmt.Fprintf(os.Stderr, "contract %s not found in solc output\n", contractName)
		os.Exit(1)
	}

	a := artifact{
		ContractName:     contractName,
		ABI:              contract.ABI,
		Bytecode:         contract.EVM.Bytecode.Object,
		DeployedBytecode: contract.EVM.DeployedBytecode.Object,
		SolcVersion:      solcVersion,
	}

	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal artifact: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(outFile, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write artifact: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s\n", outFile)
}
