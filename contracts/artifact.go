package contracts

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

//go:embed KZGPointEvaluationWrapper.json
var artifactBytes []byte

type Artifact struct {
	ContractName     string          `json:"contractName"`
	ABI              json.RawMessage `json:"abi"`
	Bytecode         string          `json:"bytecode"`
	DeployedBytecode string          `json:"deployedBytecode"`
	SolcVersion      string          `json:"solcVersion"`
}

func Load() (*Artifact, abi.ABI, []byte, error) {
	var artifact Artifact
	if err := json.Unmarshal(artifactBytes, &artifact); err != nil {
		return nil, abi.ABI{}, nil, fmt.Errorf("unmarshal contract artifact: %w", err)
	}
	parsedABI, err := abi.JSON(strings.NewReader(string(artifact.ABI)))
	if err != nil {
		return nil, abi.ABI{}, nil, fmt.Errorf("parse abi: %w", err)
	}
	return &artifact, parsedABI, common.FromHex(artifact.Bytecode), nil
}
