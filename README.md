# FoldAudit

This repository contains the FoldAudit paper, protocol reproductions for the
main related PDP schemes, and scripts for generating the experimental figures
used in Section VI of the paper.

## Directory Layout

- `paper/`
  - `FoldAudit.tex`: main LaTeX source of the paper.
  - `FoldAudit.pdf`: compiled paper output.
  - `figures/vi_evaluation/`: figures inserted into Section VI.
  - `refs/`: key reference papers and notes, including `PDP_Protocols.tex`.
- `schemes/`
  - `foldaudit/`: Go implementation of the FoldAudit protocol core and tests.
  - `yutc25/`, `zhangtpds23/`, `miaoscis2026/`, `xutifs26/`: system-level reproductions of the related schemes compared in the paper, including multi-file audit paths where applicable.
  - `benchcore/`: shared benchmark and protocol utilities.
  - `relatedbench/`: correctness tests for the reproduced related protocols.
- `experiments/`
  - `evaluate_vi_settings.py`: regenerates Section VI overhead data and figures from the experimental settings in `paper/FoldAudit.tex`.
  - `out/vi_evaluation/`: generated CSV records and PDF/SVG/PNG figures.
- `go.mod`, `go.sum`: Go module metadata.

## Requirements

- Go 1.24 or newer.
- Python 3 with `matplotlib`, `pandas`, and `seaborn`.
- A LaTeX distribution with `pdflatex` for compiling the paper.

If the local virtual environment already exists, use `.venv/bin/python`.
Otherwise install the Python packages in your preferred environment:

```bash
python3 -m pip install matplotlib pandas seaborn
```

## Test the Protocol Implementations

Run all Go tests from the repository root:

```bash
go test ./schemes/...
```

The tests check FoldAudit correctness and the reproduced related protocol cores
under the shared benchmark utilities.

## Regenerate Section VI Experimental Results

The Section VI evaluation uses the paper settings:

- challenge size `c = 690`
- batch size `m = 1..20`
- file size `B = 1..100 MB`
- sectors per chunk `s = 20..100`
- chunks per file `n = max(c, ceil(B/(32s)))`

Generate fresh CSV files by executing the reproduced protocols on simulated
file contents, then draw the figures:

```bash
go run ./experiments/protocolbench -profile paper -out experiments/out/vi_evaluation/vi_overhead_all.csv
.venv/bin/python experiments/evaluate_vi_settings.py
```

The `paper` profile executes the full Section VI workload and can take a long
time because storage generation really computes tags for the simulated files.

For a fast sanity check of the protocol-execution pipeline, use the small quick
profile instead of the full paper workload:

```bash
go run ./experiments/protocolbench -profile quick -out /tmp/foldaudit_protocol_quick.csv
.venv/bin/python experiments/evaluate_vi_settings.py --csv /tmp/foldaudit_protocol_quick.csv
```

Generated outputs are written to:

```text
experiments/out/vi_evaluation/
```

Important files include:

- `vi_overhead_all.csv`: all generated overhead records.
- `average_overhead_summary.csv`: average audit overhead by scheme.
- `audit_vs_m.pdf`
- `store_vs_file_size.pdf`
- `proofgen_vs_s.pdf`
- `verify_vs_s.pdf`
- `baseline_phase_overhead.pdf`
- `mean_audit_overhead.pdf`

To refresh the figures embedded in the paper, copy the generated PDF files:

```bash
cp experiments/out/vi_evaluation/*.pdf paper/figures/vi_evaluation/
```

## Notes

- The experiment pipeline measures protocol-level overhead by directly calling
  each reproduced scheme's `Store`, challenge generation, proof generation, and
  verification routines. It no longer estimates runtime from single-operation
  primitive costs.
- `paper/refs/PDP_Protocols.tex` is used as the implementation reference for
  the related protocols in `schemes/`.
