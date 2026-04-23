# PDP26 Sepolia KZG Gas Test

This repository is organized by responsibility:

- [contracts](</c:/Users/62692/Documents/PDP26/code/contracts>): Solidity source, compiled artifact, contract helper code, and contract build script
- [crypto](</c:/Users/62692/Documents/PDP26/code/crypto>): cryptographic implementations only, currently the real EIP-4844 KZG code
- [cmd](</c:/Users/62692/Documents/PDP26/code/cmd>): executable entrypoints
- [legacy](</c:/Users/62692/Documents/PDP26/code/legacy>): archived Python prototype from the earlier exploration stage

The active code path for Sepolia gas testing is:

- [contracts/KZGPointEvaluationWrapper.sol](</c:/Users/62692/Documents/PDP26/code/contracts/KZGPointEvaluationWrapper.sol>)
- [contracts/KZGPointEvaluationWrapper.json](</c:/Users/62692/Documents/PDP26/code/contracts/KZGPointEvaluationWrapper.json>)
- [contracts/artifact.go](</c:/Users/62692/Documents/PDP26/code/contracts/artifact.go>)
- [crypto/kzg/sample.go](</c:/Users/62692/Documents/PDP26/code/crypto/kzg/sample.go>)
- [cmd/sepolia-gas/main.go](</c:/Users/62692/Documents/PDP26/code/cmd/sepolia-gas/main.go>)

## What is real here

This version uses Ethereum's real EIP-4844 KZG stack:

- off-chain proof generation: `github.com/ethereum/go-ethereum/crypto/kzg4844`
- real curve: BLS12-381
- on-chain verification path: the Sepolia point-evaluation precompile at `0x0A`

## Local verification

From the repository root:

```powershell
go test ./...
go build ./...
```

## Sepolia run

The CLI needs:

- a Sepolia RPC URL
- a funded Sepolia private key if you want actual transactions and receipt `gasUsed`

Example:

```powershell
$env:SEPOLIA_RPC_URL="https://your-sepolia-rpc"
$env:SEPOLIA_PRIVATE_KEY="0x..."
go run ./cmd/sepolia-gas --samples 3
```

If you already deployed the wrapper contract, you can reuse it:

```powershell
go run ./cmd/sepolia-gas --rpc https://your-sepolia-rpc --contract 0xYourWrapperAddress
```

The default result file is
[results/sepolia_kzg_gas.json](</c:/Users/62692/Documents/PDP26/code/results/sepolia_kzg_gas.json>).

## Rebuild Contract Artifact

If you change the Solidity source, regenerate the artifact with:

```powershell
python contracts\compile_contract.py
```
