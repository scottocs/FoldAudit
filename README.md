# FoldAudit

This repository contains the FoldAudit paper, Go reproductions of the compared
PDP protocols, and experiment scripts for two kinds of performance analysis:

- strict protocol execution: directly runs each reproduced protocol's source
  code and measures `Store`, challenge generation, `ProofGen`, and `Verify`.
- operation-cost estimation: combines single-operation latency with the
  complexity formulas in the paper. This path is kept for cross-checking and
  theoretical sanity checks, not for replacing the protocol-execution figures.

## Directory Layout

- `paper/`
  - `FoldAudit.tex`: main paper source.
  - `FoldAudit.pdf`: compiled output.
  - `figures/vi_evaluation/`: PDF figures included by Section VI.
  - `refs/`: reference papers and `PDP_Protocols.tex`, the implementation
    reference for related schemes.
- `schemes/`
  - `foldaudit/`: Go implementation of FoldAudit.
  - `yutc25/`, `zhangtpds23/`, `miaoscis2026/`, `xutifs26/`: reproduced
    related PDP schemes.
  - `benchcore/`: shared field, group, hash-to-group, polynomial, Merkle, and
    timing helpers.
  - `relatedbench/`: cross-scheme correctness tests.
- `experiments/`
  - `protocolbench/main.go`: strict protocol-execution benchmark runner.
  - `evaluate_vi_settings.py`: plots Section VI figures from strict execution
    CSV data.
  - `plot_paper_figures.py`: legacy operation-cost figure renderer. It expects
    cost-model CSV files under `experiments/out/`; keep this file if the
    single-operation-latency times complexity estimation path is still needed.
  - `render_vi_aggregate_figures.py`: older helper for only the two aggregate
    VI bar figures.
  - `out/vi_evaluation/`: generated CSV and PDF outputs.
- `go.mod`, `go.sum`: Go module metadata.

## Requirements

- Go 1.24 or newer.
- Python 3 with `matplotlib`, `pandas`, and `seaborn`.
- A LaTeX distribution with `pdflatex`.

Use the local virtual environment if it exists:

```bash
.venv/bin/python -m pip install matplotlib pandas seaborn
```

Otherwise install the packages in your preferred Python environment:

```bash
python3 -m pip install matplotlib pandas seaborn
```

## Protocol Correctness Tests

Run all scheme tests:

```bash
go test ./schemes/...
```

These tests execute FoldAudit and the reproduced related protocols against
shared simulated data. They check that each protocol can complete its own
store, challenge, proof, and verification path.

## Strict Protocol-Execution Experiments

This is the data path used for the current Section VI figures. It does not use
single-operation extrapolation.

Current paper settings:

- challenge size `c = 690`
- batch size `m in {5, 10, 15, 20, 25, 30}`
- file size `B in {10, 20, 30, 40, 50, 60, 70, 80, 90, 100} MB`
- sectors per chunk `s in {20, 40, 60, 80, 100}`
- baseline setting `m = 5`, `B = 10 MB`, `s = 20`
- chunks per file `n = max(c, ceil(B/(32s)))`
- default repetitions per workload point: `3`

The benchmark call order is:

```text
experiments/protocolbench/main.go
  -> runProfile
  -> runAllSchemes
  -> runYu / runZhang / runMiao / runXu / runFoldAudit
  -> Store
  -> Challenge or equivalent challenge-generation routine
  -> Prove / ProofGen
  -> Verify
```

Generate strict execution data:

```bash
go run ./experiments/protocolbench \
  -profile paper \
  -repeats 3 \
  -out experiments/out/vi_evaluation/vi_overhead_all.csv
```

Then draw the Section VI PDF figures:

```bash
.venv/bin/python experiments/evaluate_vi_settings.py \
  --csv experiments/out/vi_evaluation/vi_overhead_all.csv
```

The plotting script writes:

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

Refresh the figures included by the paper:

```bash
cp experiments/out/vi_evaluation/*.pdf paper/figures/vi_evaluation/
```

For a quick pipeline check:

```bash
go run ./experiments/protocolbench \
  -profile quick \
  -repeats 2 \
  -out /tmp/foldaudit_protocol_quick.csv

.venv/bin/python experiments/evaluate_vi_settings.py \
  --csv /tmp/foldaudit_protocol_quick.csv
```

The full paper profile is expensive because the storage phase actually
generates tags for simulated files. The `B = 100 MB` points can take a long time
and may be memory-sensitive on small machines.

## Operation-Cost Estimation Path

This path should be kept because it is useful for cross-checking whether the
measured curve ordering agrees with Table III/IV complexity trends.

Current status:

- The paper contains the single-operation latency table used for
  cross-checking.
- `experiments/plot_paper_figures.py` renders figures from cost-model CSV files
  such as `experiments/out/cost_model_main.csv`,
  `experiments/out/vary_m_audit.csv`,
  `experiments/out/vary_c_verify.csv`, and
  `experiments/out/vary_file_store.csv`.
- The script that generates those `cost_model_*.csv` files is not present in
  the current working tree. If the estimation path is still needed, restore or
  rewrite that CSV generator instead of deleting `plot_paper_figures.py`.

Do not mix this estimation data with `vi_overhead_all.csv`. Section VI figures
should use the strict protocol-execution CSV unless the paper explicitly says a
figure is an operation-count estimate.

## Compile the Paper

From `paper/`:

```bash
pdflatex -interaction=nonstopmode -halt-on-error FoldAudit.tex
pdflatex -interaction=nonstopmode -halt-on-error FoldAudit.tex
```

Run twice when references, labels, captions, or bibliography entries change.

## Files to Keep

These files are part of the main workflow and should not be deleted:

- `paper/FoldAudit.tex`
- `paper/refs/PDP_Protocols.tex`
- `paper/refs/*.pdf`
- `paper/figures/vi_evaluation/*.pdf`
- `schemes/**/protocol.go`
- `schemes/**/protocol_test.go`
- `schemes/benchcore/*.go`
- `schemes/relatedbench/protocol_reproduction_test.go`
- `experiments/protocolbench/main.go`
- `experiments/evaluate_vi_settings.py`
- `experiments/plot_paper_figures.py`, if operation-cost estimation is kept
- `go.mod`, `go.sum`

## Files That Look Unused or Regenerable

I did not delete these. They are candidates for cleanup after you confirm they
are not needed.

Clearly safe to delete:

- `.DS_Store`
- `experiments/.DS_Store`
- `paper/figures/.DS_Store`
- `paper/refs/.DS_Store`
- `schemes/foldaudit/.DS_Store`
- `experiments/__pycache__/`
- `paper/FoldAudit.aux`
- `paper/FoldAudit.fls`

Regenerable experiment outputs:

- `experiments/out/vi_evaluation/*.csv`
- `experiments/out/vi_evaluation/*.pdf`

Delete these only after the corresponding paper figures have been copied to
`paper/figures/vi_evaluation/` or after you are ready to rerun the experiments.

Potentially obsolete helper:

- `experiments/render_vi_aggregate_figures.py`: older two-figure renderer.
  `experiments/evaluate_vi_settings.py` now generates all VI figures directly.
  Keep it only if you still need the older fixed-canvas aggregate-figure style.

Not used by the main paper build, but may be useful as backups or drafts:

- `paper/ori.tex`
- `paper/ori.pdf`
- `paper/foldaudit-tmp.tex`
- `paper/foldaudit-tmp.pdf`
- `paper/PDP_Protocols_revised.tex`
- `paper/PDP_Protocols_revised.pdf`
- `paper/FoldAudit op x times.pdf`

Local editor/environment files:

- `.vscode/`
- `.venv/`

Keep them if you use this local workspace setup. They are not required by the
paper or benchmark source code.
