# FoldAudit

This repository contains the FoldAudit protocol implementation, reproduced
comparison protocols, protocol-execution benchmarks, attack simulations, plotting
scripts, and the paper source.

The testing workflow is organized around one principle: paper figures should be
derived from executable protocol paths whenever possible, not from manually
edited data. Use quick tests for code sanity, the paper profile for Section VI
data, and the attack runners for the security-simulation figures.

## Repository Layout

- `schemes/`
  - `foldaudit/`: FoldAudit protocol implementation.
  - `yutc25/`, `zhangtpds23/`, `miaoscis2026/`, `xutifs26/`: reproduced related protocols.
  - `benchcore/`: shared field, group, polynomial, Merkle, dataset, and helper code.
  - `relatedbench/`: cross-protocol reproduction tests.
- `experiments/`
  - `protocolbench/main.go`: main Go runner for protocol-execution overhead data.
  - `cancellationattack/main.go`: Go runner for folded-cancellation attack simulations.
  - `leakageattack/main.go`: Go runner for repeated-audit leakage timing.
  - `evaluate_vi_settings.py`: plots Section VI figures from protocolbench CSV data.
  - `plot_attack_simulations.py`: plots attack/sampling figures from attack CSV data.
  - `render_vi_aggregate_figures.py`: communication/aggregate helper plots.
  - `out/`: generated CSV and PDF results used for paper figures.
- `paper/`
  - `FoldAudit.tex`: paper source.
  - `figures/`: paper-local copies of selected generated PDF figures.
  - `refs/`: reference material.

## Requirements

- Go 1.24 or newer.
- Python 3 with `matplotlib`, `numpy`, `pandas`, and `seaborn`.
- A LaTeX distribution with `pdflatex`.

Install Python packages in your preferred environment:

```bash
python3 -m pip install matplotlib numpy pandas seaborn
```

If Go cannot write its default build cache in a restricted environment, set a
local cache for the command:

```bash
GOCACHE=/tmp/foldaudit-gocache go test ./...
```

## Test Strategy

There are three levels of tests.

1. Code sanity tests

   These compile all packages and run protocol-level unit/reproduction tests.

   ```bash
   go test ./...
   ```

2. Quick executable pipeline test

   This runs the same benchmark path as the paper with small parameters. It is
   the fastest way to check that Store, Challenge, ProofGen, Verify, CSV writing,
   and plotting still work end to end.

   ```bash
   go run ./experiments/protocolbench \
     -profile quick \
     -repeats 1 \
     -out /tmp/foldaudit_vi_overhead_quick.csv

   python3 experiments/evaluate_vi_settings.py \
     --csv /tmp/foldaudit_vi_overhead_quick.csv
   ```

3. Paper-setting experiments

   This is the source of the current Section VI runtime figures. It directly
   executes each reproduced protocol and records phase timings; it does not
   extrapolate from primitive operation counts.

   ```bash
   go run ./experiments/protocolbench \
     -profile paper \
     -repeats 3 \
     -out experiments/out/vi_evaluation/vi_overhead_all.csv

   python3 experiments/evaluate_vi_settings.py \
     --csv experiments/out/vi_evaluation/vi_overhead_all.csv
   ```

## Section VI Settings

The paper profile uses:

- challenge size `c = 690`
- batch size `m in {5, 10, 15, 20, 25, 30}`
- file size `B in {10, 20, 30, 40, 50, 60, 70, 80, 90, 100} MB`
- sectors per chunk `s in {20, 40, 60, 80, 100}`
- baseline setting `m = 5`, `B = 10 MB`, `s = 20`
- chunks per file `n = max(c, ceil(B/(32s)))`
- default repetitions per workload point: `3`

The Go runner records `Store`, `Challenge`, `ProofGen`, `Verify`, and derived
`Audit = Challenge + ProofGen + Verify` rows. Each CSV row includes an `ok`
field; plotting aborts if any protocol execution failed.

## Attack Simulations

Generate attack timing CSV files:

```bash
go run ./experiments/leakageattack \
  -trials 20 \
  -m 4 \
  -n 64 \
  -s 8 \
  -c 8 \
  -out experiments/out/attack_simulation/data_leakage_audit_cost.csv

go run ./experiments/cancellationattack \
  -trials 20 \
  -m 4 \
  -n 64 \
  -s 8 \
  -c 8 \
  -out experiments/out/attack_simulation/cancellation_attack_cost.csv
```

Then draw the attack and sampling figures:

```bash
python3 experiments/plot_attack_simulations.py
```

The attack plotting script currently writes more figures than the paper may
include. Keep all `experiments/out/attack_simulation/` outputs as reproducible
results; copy only paper-used figures into `paper/figures/attack_simulation/`.

## Plot Outputs

The VI plotting script writes:

- `experiments/out/vi_evaluation/baseline.csv`
- `experiments/out/vi_evaluation/vary_m.csv`
- `experiments/out/vi_evaluation/vary_B.csv`
- `experiments/out/vi_evaluation/vary_s.csv`
- `experiments/out/vi_evaluation/average_overhead_summary.csv`
- `experiments/out/vi_evaluation/audit_vs_m.pdf`
- `experiments/out/vi_evaluation/store_vs_file_size.pdf`
- `experiments/out/vi_evaluation/proofgen_vs_s.pdf`
- `experiments/out/vi_evaluation/verify_vs_s.pdf`
- `experiments/out/vi_evaluation/baseline_phase_overhead.pdf`
- `experiments/out/vi_evaluation/mean_audit_overhead.pdf`

The paper-local figure directories are intentionally separate from
`experiments/out/`. After regenerating results, refresh the paper copies with
the figures referenced by `paper/FoldAudit.tex`.

Example:

```bash
cp experiments/out/attack_simulation/sampling_detection_probability.pdf paper/figures/attack_simulation/
cp experiments/out/attack_simulation/data_leakage_attack_cost.pdf paper/figures/attack_simulation/
cp experiments/out/attack_simulation/cancellation_attack_cost.pdf paper/figures/attack_simulation/

cp experiments/out/vi_evaluation/store_vs_file_size.pdf paper/figures/vi_evaluation/
cp experiments/out/vi_evaluation/proofgen_vs_s.pdf paper/figures/vi_evaluation/
cp experiments/out/vi_evaluation/verify_vs_s.pdf paper/figures/vi_evaluation/
cp experiments/out/vi_evaluation/audit_vs_m.pdf paper/figures/vi_evaluation/
cp experiments/out/vi_evaluation/baseline_phase_overhead.pdf paper/figures/vi_evaluation/
cp experiments/out/vi_evaluation/proof_communication_vs_m.pdf paper/figures/vi_evaluation/
```
