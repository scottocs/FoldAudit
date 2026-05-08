#!/usr/bin/env python3
"""Render all paper line charts with the supplemental-runtime pgfplots style.

The runtime charts are generated from the protocol-execution CSV. The
communication charts are computed from Table IV formulas using the same byte
constants as the paper. The sampling chart is the analytical sampling curve used
for parameter selection.
"""

from __future__ import annotations

import csv
import math
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VI_OUT = ROOT / "experiments/out/vi_evaluation"
ATTACK_OUT = ROOT / "experiments/out/attack_simulation"
VI_FIGURES = ROOT / "paper/figures/vi_evaluation"
ATTACK_FIGURES = ROOT / "paper/figures/attack_simulation"
CSV_PATH = VI_OUT / "vi_overhead_all.csv"

SCHEMES = ["YuTC25", "ZhangTPDS23", "MiaoSCIS2026", "XuTIFS26", "FoldAudit"]
DISPLAY = {
    "YuTC25": "Yu et al.",
    "ZhangTPDS23": "Zhang et al.",
    "MiaoSCIS2026": "Miao et al.",
    "XuTIFS26": "Xu et al.",
    "FoldAudit": "FoldAudit",
}
COLORS = {
    "YuTC25": "4C78A8",
    "ZhangTPDS23": "F58518",
    "MiaoSCIS2026": "B279A2",
    "XuTIFS26": "54A24B",
    "FoldAudit": "6B7280",
}
MARKS = {
    "YuTC25": "*",
    "ZhangTPDS23": "square*",
    "MiaoSCIS2026": "triangle*",
    "XuTIFS26": "diamond*",
    "FoldAudit": "pentagon*",
}

FIELD_BYTES = 32
HASH_BYTES = 32
G1_BYTES = 64
BASE_M = 4
BASE_B_MB = 10
BASE_S = 20
BASE_C = 690

RUNTIME_PLOTS = [
    ("vary_B", "Store", "B_MB", "File size $B$ (MB)", "Time (s)", "store_vs_file_size"),
    ("vary_s", "Store", "s", "Sectors per chunk $s$", "Time (s)", "store_vs_s"),
    ("vary_m", "Store", "m", "Batch size $m$", "Time (s)", "store_vs_m"),
    ("vary_B", "ProofGen", "B_MB", "File size $B$ (MB)", "Time (s)", "proofgen_vs_file_size"),
    ("vary_s", "ProofGen", "s", "Sectors per chunk $s$", "Time (s)", "proofgen_vs_s"),
    ("vary_m", "ProofGen", "m", "Batch size $m$", "Time (s)", "proofgen_vs_m"),
    ("vary_B", "Verify", "B_MB", "File size $B$ (MB)", "Time (s)", "verify_vs_file_size"),
    ("vary_s", "Verify", "s", "Sectors per chunk $s$", "Time (s)", "verify_vs_s"),
    ("vary_m", "Verify", "m", "Batch size $m$", "Time (s)", "verify_vs_m"),
]


def load_rows() -> list[dict[str, str]]:
    if not CSV_PATH.exists():
        raise SystemExit(f"missing {CSV_PATH}")
    with CSV_PATH.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise SystemExit(f"{CSV_PATH} is empty")
    if {row["measurement_method"] for row in rows} != {"protocol_execution"}:
        raise SystemExit(f"{CSV_PATH} is not a protocol-execution CSV")
    failed = [row for row in rows if row["ok"].lower() != "true"]
    if failed:
        raise SystemExit(f"protocol benchmark contains failed rows, e.g. {failed[0]}")
    return rows


def runtime_series(rows: list[dict[str, str]], scenario: str, phase: str, x_key: str) -> list[dict[str, object]]:
    series = []
    for scheme in SCHEMES:
        coords = [
            (float(row[x_key]), float(row["seconds"]))
            for row in rows
            if row["scenario"] == scenario and row["phase"] == phase and row["scheme"] == scheme
        ]
        coords.sort()
        if not coords:
            raise SystemExit(f"missing data for {scenario}/{phase}/{scheme}")
        series.append(
            {
                "name": DISPLAY[scheme],
                "color": scheme,
                "mark": MARKS[scheme],
                "coords": coords,
            }
        )
    return series


def chunk_count(b_mb: int, s: int, c: int) -> int:
    return max(c, math.ceil((b_mb * 1_000_000) / (32 * s)))


def merkle_depth(n: int) -> int:
    return max(1, math.ceil(math.log2(n)))


def store_bytes(scheme: str, m: int, n: int, s: int) -> int:
    if scheme in {"YuTC25", "XuTIFS26", "FoldAudit"}:
        return m * n * s * FIELD_BYTES + m * n * G1_BYTES + m * HASH_BYTES
    if scheme == "ZhangTPDS23":
        return m * n * s * FIELD_BYTES + m * n * G1_BYTES
    if scheme == "MiaoSCIS2026":
        return m * n * FIELD_BYTES + (m * n + m) * G1_BYTES
    raise ValueError(scheme)


def proof_bytes(scheme: str, m: int, n: int, s: int, c: int) -> int:
    depth = merkle_depth(n)
    if scheme == "XuTIFS26":
        return m * (FIELD_BYTES + (c + 1) * G1_BYTES + c * depth * HASH_BYTES)
    if scheme == "ZhangTPDS23":
        return 3 * G1_BYTES + FIELD_BYTES
    if scheme == "YuTC25":
        return m * (s * FIELD_BYTES + (c + 1) * G1_BYTES + c * depth * HASH_BYTES)
    if scheme == "MiaoSCIS2026":
        return FIELD_BYTES + 2 * G1_BYTES
    if scheme == "FoldAudit":
        return m * (c + 4) * G1_BYTES + 2 * m * FIELD_BYTES + m * c * depth * HASH_BYTES
    raise ValueError(scheme)


def communication_series(metric: str) -> tuple[list[dict[str, object]], list[int]]:
    xs = list(range(10, 51, 10)) if metric == "store" else list(range(4, 21, 4))
    series = []
    for scheme in SCHEMES:
        coords = []
        for x in xs:
            if metric == "store":
                n = chunk_count(x, BASE_S, BASE_C)
                y = store_bytes(scheme, BASE_M, n, BASE_S) / (1024 * 1024)
            else:
                n = chunk_count(BASE_B_MB, BASE_S, BASE_C)
                y = proof_bytes(scheme, x, n, BASE_S, BASE_C) / 1024
            coords.append((float(x), float(y)))
        series.append(
            {
                "name": DISPLAY[scheme],
                "color": scheme,
                "mark": MARKS[scheme],
                "coords": coords,
            }
        )
    return series, xs


def sampling_series() -> tuple[list[dict[str, object]], list[int]]:
    colors = ["YuTC25", "XuTIFS26", "ZhangTPDS23", "MiaoSCIS2026"]
    marks = ["*", "diamond*", "square*", "triangle*"]
    ratios = [0.005, 0.01, 0.02, 0.05]
    c_values = list(range(0, 801, 20))
    series = []
    for ratio, color, mark in zip(ratios, colors, marks):
        coords = [(float(c), 1.0 - (1.0 - ratio) ** c) for c in c_values]
        series.append(
            {
                "name": f"$\\delta={ratio * 100:.1f}\\%$",
                "color": color,
                "mark": mark,
                "coords": coords,
            }
        )
    return series, list(range(0, 801, 100))


def coord_tex(coords: list[tuple[float, float]]) -> str:
    return " ".join(f"({x:g},{y:.9f})" for x, y in coords)


def tex_source(
    series: list[dict[str, object]],
    xlabel: str,
    ylabel: str,
    xticks: list[int],
    extra_axis: str = "",
    extra_draw: str = "",
) -> str:
    color_defs = "\n".join(f"\\definecolor{{{scheme}}}{{HTML}}{{{COLORS[scheme]}}}" for scheme in SCHEMES)
    axis_options = [
        "width=3.55in",
        "height=2.55in",
        "scale only axis=false",
        f"xlabel={{{xlabel}}}",
        f"ylabel={{{ylabel}}}",
        "xminorticks=false",
        "yminorticks=false",
        f"xtick={{{','.join(str(value) for value in xticks)}}}",
        r"tick label style={font=\scriptsize}",
        r"label style={font=\scriptsize}",
        r"legend style={font=\fontsize{6.2}{7}\selectfont, draw=none, fill=none, at={(0.5,1.03)}, anchor=south, legend columns=5}",
        r"grid=major",
        r"grid style={line width=0.3pt, draw=gray!35}",
        r"axis line style={line width=0.6pt}",
        r"legend image post style={scale=0.55}",
    ]
    if extra_axis:
        axis_options.extend(option.strip() for option in extra_axis.split(",") if option.strip())
    axis_options_tex = ",\n  ".join(axis_options)
    plot_lines = []
    for item in series:
        plot_lines.append(
            "\n".join(
                [
                    f"\\addplot+[color={item['color']}, mark={item['mark']}, mark size=1.55pt]",
                    f"coordinates {{{coord_tex(item['coords'])}}};",
                    f"\\addlegendentry{{{item['name']}}}",
                ]
            )
        )
    return rf"""\documentclass[tikz,border=0pt]{{standalone}}
\usepackage{{pgfplots}}
\pgfplotsset{{compat=1.18}}
{color_defs}
\begin{{document}}
\begin{{tikzpicture}}
\begin{{axis}}[
  {axis_options_tex}
]
{chr(10).join(plot_lines)}
{extra_draw}
\end{{axis}}
\end{{tikzpicture}}
\end{{document}}
"""


def render(tex: str, out_dir: Path, paper_dir: Path, name: str) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    paper_dir.mkdir(parents=True, exist_ok=True)
    tex_path = out_dir / f"{name}.tex"
    tex_path.write_text(tex, encoding="utf-8")
    subprocess.run(
        ["pdflatex", "-interaction=nonstopmode", "-halt-on-error", tex_path.name],
        cwd=out_dir,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    (paper_dir / f"{name}.pdf").write_bytes((out_dir / f"{name}.pdf").read_bytes())


def render_runtime(rows: list[dict[str, str]]) -> None:
    for scenario, phase, x_key, xlabel, ylabel, name in RUNTIME_PLOTS:
        series = runtime_series(rows, scenario, phase, x_key)
        xticks = sorted({int(float(row[x_key])) for row in rows if row["scenario"] == scenario and row["phase"] == phase})
        render(tex_source(series, xlabel, ylabel, xticks), VI_OUT, VI_FIGURES, name)


def render_communication() -> None:
    store_series, store_ticks = communication_series("store")
    render(tex_source(store_series, "File size $B$ (MB)", "Store comm. (MiB)", store_ticks), VI_OUT, VI_FIGURES, "store_communication_vs_file_size")
    proof_series, proof_ticks = communication_series("proof")
    render(tex_source(proof_series, "Batch size $m$", "Proof comm. (KiB)", proof_ticks), VI_OUT, VI_FIGURES, "proof_communication_vs_m")


def render_sampling() -> None:
    series, ticks = sampling_series()
    extra_axis = "ymin=0, ymax=1.03, xmin=0, xmax=800,"
    extra_draw = "\n".join(
        [
            "\\addplot+[black, no marks, dashed, line width=0.65pt] coordinates {(690,0) (690,1.03)};",
            "\\addplot+[gray, no marks, dotted, line width=0.65pt] coordinates {(0,0.999) (800,0.999)};",
            "\\node[font=\\scriptsize, rotate=90, anchor=south] at (axis cs:676,0.34) {$c=690$};",
            "\\node[font=\\scriptsize, text=gray, anchor=south west] at (axis cs:18,0.944) {$99.9\\%$};",
        ]
    )
    render(tex_source(series, "Challenge size $c$", "Detection probability", ticks, extra_axis, extra_draw), ATTACK_OUT, ATTACK_FIGURES, "sampling_detection_probability")


def main() -> None:
    rows = load_rows()
    render_runtime(rows)
    render_communication()
    render_sampling()
    print("Rendered all paper line charts with the supplemental pgfplots style")


if __name__ == "__main__":
    main()
