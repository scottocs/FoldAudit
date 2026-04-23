# PDP26 Off-chain Batch PDP Verification

This repository now treats verification as an off-chain workflow with three
parties:

- Data Owner: prepares files, chunks, tags, and Merkle roots.
- Cloud Server: stores the tagged data and generates audit proofs.
- Third-party Verifier: samples challenges and verifies proofs locally.

No blockchain transaction, contract deployment, gas estimate, or on-chain
authentication is required for the active workflow.

## Repository Layout

- [crypto/pdpbatch](crypto/pdpbatch): Go implementation of the batch PDP protocol, including BLS12-381 KZG commitments, Merkle authentication, proof generation, and verification.
- [cmd/offchain-bench](cmd/offchain-bench): off-chain correctness and timing benchmark runner.
- [crypto/kzg](crypto/kzg): real EIP-4844 KZG sample code, kept for standalone KZG experiments.
- [legacy](legacy): archived Python prototype and its previous benchmark outputs.
- [contracts](contracts) and [cmd/sepolia-gas](cmd/sepolia-gas): historical Sepolia/on-chain experiment code, not part of the current active path.

## Active Off-chain Path

The active PDP flow is:

1. `BatchPDPProtocol.Store`: encode chunks, commit tags, and build Merkle roots.
2. `BatchPDPProtocol.Challenge`: third-party verifier samples audit indices, coefficients, and evaluation points.
3. `BatchPDPProtocol.ProofGen`: cloud server generates an audit proof.
4. `BatchPDPProtocol.Verify`: third-party verifier checks Merkle authentication and BLS12-381 pairing equations locally.

## Local Verification

From the repository root:

```powershell
go test ./...
go build ./...
```

## Off-chain Benchmark

Run the default quick sweep:

```powershell
go run ./cmd/offchain-bench --quick --repeats 3
```

Run the larger sweep:

```powershell
go run ./cmd/offchain-bench --quick=false --repeats 3
```

Use `--timing-rounds` to control the inner averaging loop for fast local
operations. The default is `50`, so each repeat averages 50 local proof
generations and 50 local verifications.

Default outputs:

- [results/offchain_benchmark_summary.json](results/offchain_benchmark_summary.json)
- [results/offchain_benchmark_results.csv](results/offchain_benchmark_results.csv)

The main timing columns are:

- `avg_store_ms`: data-owner storage/tagging/Merkle setup time.
- `avg_proofgen_ms`: cloud-server proof generation time.
- `avg_verify_ms`: third-party verifier local verification time.

## Current Cryptographic Scope

The active batch PDP implementation now uses `gnark-crypto`'s BLS12-381
G1/G2 groups, scalar field arithmetic, SRS-based KZG commitments, and pairing
checks. The benchmark remains fully off-chain.

The older Sepolia contract path remains in the repository for reference only
while blockchain authentication is out of scope.
