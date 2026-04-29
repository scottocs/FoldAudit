#!/usr/bin/env python3
"""Render the aggregate VI figures used in FoldAudit.tex.

The communication values are computed from Table IV's formulas, not from runtime
measurements. The constants match the implementation profile used in Section VI:
one field element and one SHA-256 digest are 32 bytes, and one serialized bn256
G1 element is 64 bytes.
"""

from __future__ import annotations

from math import ceil, log2
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from matplotlib.ticker import LogLocator, NullFormatter
from matplotlib.transforms import ScaledTranslation


OUT = Path("experiments/out/vi_evaluation")
PAPER_FIGURES = Path("paper/figures/vi_evaluation")

SCHEMES = ["YuTC25", "ZhangTPDS23", "MiaoSCIS2026", "XuTIFS26", "FoldAudit"]
DISPLAY = {
    "YuTC25": "Yu et al.",
    "ZhangTPDS23": "Zhang et al.",
    "MiaoSCIS2026": "Miao et al.",
    "XuTIFS26": "Xu et al.",
    "FoldAudit": "FoldAudit",
}
PALETTE = {
    "YuTC25": "#4C78A8",
    "ZhangTPDS23": "#F58518",
    "MiaoSCIS2026": "#B279A2",
    "XuTIFS26": "#54A24B",
    "FoldAudit": "#6B7280",
}
MARKERS = {
    "YuTC25": "o",
    "ZhangTPDS23": "s",
    "MiaoSCIS2026": "^",
    "XuTIFS26": "D",
    "FoldAudit": "P",
}

FIGSIZE = (3.55, 2.55)
BAR_XTICK_SHIFT_PT = 0.0

FIELD_BYTES = 32
HASH_BYTES = 32
G1_BYTES = 64

BASE_M = 5
BASE_B_MB = 10
BASE_S = 20
BASE_C = 690


def chunk_count(b_mb: int, s: int, c: int) -> int:
    return max(c, ceil((b_mb * 1_000_000) / (32 * s)))


def merkle_depth(n: int) -> int:
    return max(1, ceil(log2(n)))


def store_bytes(scheme: str, m: int, n: int, s: int) -> int:
    if scheme in {"YuTC25", "XuTIFS26", "FoldAudit"}:
        return m * n * s * FIELD_BYTES + m * n * G1_BYTES + m * HASH_BYTES
    if scheme == "ZhangTPDS23":
        return m * n * s * FIELD_BYTES + m * n * G1_BYTES
    if scheme == "MiaoSCIS2026":
        return m * n * FIELD_BYTES + (m * n + m) * G1_BYTES
    raise ValueError(f"unknown scheme {scheme}")


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
    raise ValueError(f"unknown scheme {scheme}")


def setup_style() -> None:
    sns.set_theme(style="whitegrid", context="paper")
    plt.rcParams.update(
        {
            "font.family": "serif",
            "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
            "font.size": 8.5,
            "axes.labelsize": 8.5,
            "ytick.labelsize": 7.5,
            "legend.fontsize": 7.3,
            "axes.linewidth": 0.8,
            "grid.linewidth": 0.45,
            "lines.linewidth": 1.55,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "savefig.dpi": 600,
        }
    )


def log_y(ax: plt.Axes) -> None:
    ax.set_yscale("log")
    ax.yaxis.set_major_locator(LogLocator(base=10))
    ax.yaxis.set_minor_locator(LogLocator(base=10, subs=(2, 3, 4, 5, 6, 7, 8, 9)))
    ax.yaxis.set_minor_formatter(NullFormatter())
    ax.grid(True, axis="y", which="major", color="#D0D0D0")
    ax.grid(True, axis="y", which="minor", color="#ECECEC", alpha=0.7)
    ax.grid(False, axis="x")
    sns.despine(ax=ax, top=True, right=True)


def shift_xticklabels_right(ax: plt.Axes) -> None:
    if BAR_XTICK_SHIFT_PT == 0:
        return
    shift = ScaledTranslation(BAR_XTICK_SHIFT_PT / 72.0, 0.0, ax.figure.dpi_scale_trans)
    for label in ax.get_xticklabels():
        label.set_transform(label.get_transform() + shift)


def save_fixed_canvas(fig: plt.Figure, name: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    PAPER_FIGURES.mkdir(parents=True, exist_ok=True)
    for directory in (OUT, PAPER_FIGURES):
        fig.savefig(directory / f"{name}.pdf", bbox_inches=None, pad_inches=0)
    plt.close(fig)


def build_communication_rows() -> pd.DataFrame:
    rows: list[dict[str, float | int | str]] = []

    for b_mb in range(10, 101, 10):
        n = chunk_count(b_mb, BASE_S, BASE_C)
        for scheme in SCHEMES:
            rows.append(
                {
                    "scenario": "vary_B",
                    "metric": "Store",
                    "scheme": scheme,
                    "m": BASE_M,
                    "B_MB": b_mb,
                    "s": BASE_S,
                    "c": BASE_C,
                    "n": n,
                    "bytes": store_bytes(scheme, BASE_M, n, BASE_S),
                }
            )

    for m in range(5, 31, 5):
        n = chunk_count(BASE_B_MB, BASE_S, BASE_C)
        for scheme in SCHEMES:
            rows.append(
                {
                    "scenario": "vary_m",
                    "metric": "AuditProof",
                    "scheme": scheme,
                    "m": m,
                    "B_MB": BASE_B_MB,
                    "s": BASE_S,
                    "c": BASE_C,
                    "n": n,
                    "bytes": proof_bytes(scheme, m, n, BASE_S, BASE_C),
                }
            )

    df = pd.DataFrame(rows)
    df.to_csv(OUT / "communication_overhead_summary.csv", index=False)
    return df


def plot_phase_bars() -> None:
    data = pd.read_csv(OUT / "baseline.csv")
    data = data[data.phase.isin(["Store", "ProofGen", "Verify"])].copy()
    data["scheme"] = pd.Categorical(data["scheme"], categories=SCHEMES, ordered=True)

    fig, ax = plt.subplots(figsize=FIGSIZE)
    width = 0.24
    phases = ["Store", "ProofGen", "Verify"]
    x_positions = list(range(len(SCHEMES)))
    for offset, phase, color in zip([-width, 0, width], phases, ["#9ECAE1", "#74C476", "#FD8D3C"]):
        part = data[data.phase == phase].sort_values("scheme")
        bars = ax.bar(
            [x + offset for x in x_positions],
            part["seconds"],
            width=width,
            label=phase,
            color=color,
            edgecolor="#222222",
            linewidth=0.45,
        )
        if phase == "Verify":
            for bar in bars:
                bar.set_hatch("//")

    log_y(ax)
    ax.set_xticks(x_positions)
    ax.set_xticklabels([DISPLAY[s] for s in SCHEMES], rotation=0, ha="center")
    ax.tick_params(axis="x", labelsize=7.5)
    shift_xticklabels_right(ax)
    ax.set_ylabel("Time (s, log)")
    ax.legend(ncol=3, frameon=False, loc="lower center", bbox_to_anchor=(0.5, 1.02), borderaxespad=0.0)
    fig.tight_layout(rect=(0, 0, 1, 0.90))
    save_fixed_canvas(fig, "baseline_phase_overhead")


def plot_store_communication(df: pd.DataFrame) -> None:
    data = df[(df["scenario"] == "vary_B") & (df["metric"] == "Store")].copy()
    fig, ax = plt.subplots(figsize=FIGSIZE)
    for scheme in SCHEMES:
        part = data[data.scheme == scheme].sort_values("B_MB")
        ax.plot(
            part["B_MB"],
            part["bytes"] / (1024 * 1024),
            marker=MARKERS[scheme],
            markersize=3.3,
            color=PALETTE[scheme],
            label=DISPLAY[scheme],
        )
    log_y(ax)
    ax.set_xlabel("File size B (MB)")
    ax.set_ylabel("Store comm. (MiB, log)")
    ax.set_xticks([10, 20, 40, 60, 80, 100])
    ax.legend(
        ncol=5,
        frameon=False,
        fontsize=6.2,
        handlelength=0.9,
        handletextpad=0.25,
        columnspacing=0.45,
        loc="lower center",
        bbox_to_anchor=(0.5, 1.01),
        borderaxespad=0.0,
    )
    fig.tight_layout(rect=(0, 0, 1, 0.91))
    save_fixed_canvas(fig, "store_communication_vs_file_size")


def plot_proof_communication(df: pd.DataFrame) -> None:
    data = df[(df["scenario"] == "vary_m") & (df["metric"] == "AuditProof")].copy()
    fig, ax = plt.subplots(figsize=FIGSIZE)
    for scheme in SCHEMES:
        part = data[data.scheme == scheme].sort_values("m")
        ax.plot(
            part["m"],
            part["bytes"] / 1024,
            marker=MARKERS[scheme],
            markersize=3.3,
            color=PALETTE[scheme],
            label=DISPLAY[scheme],
        )
    log_y(ax)
    ax.set_xlabel("Batch size m")
    ax.set_ylabel("Audit-proof comm. (KiB, log)")
    ax.set_xticks([5, 10, 15, 20, 25, 30])
    ax.legend(
        ncol=3,
        frameon=False,
        fontsize=6.5,
        handlelength=0.9,
        handletextpad=0.25,
        columnspacing=0.55,
        loc="lower center",
        bbox_to_anchor=(0.5, 1.01),
        borderaxespad=0.0,
    )
    fig.tight_layout(rect=(0, 0, 1, 0.91))
    save_fixed_canvas(fig, "proof_communication_vs_m")


def main() -> None:
    setup_style()
    df = build_communication_rows()
    plot_phase_bars()
    plot_store_communication(df)
    plot_proof_communication(df)
    print("Rendered baseline_phase_overhead.pdf, store_communication_vs_file_size.pdf, and proof_communication_vs_m.pdf")


if __name__ == "__main__":
    main()
