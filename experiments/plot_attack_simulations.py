#!/usr/bin/env python3
"""Generate security-bound illustration figures for the paper.

The detection plot evaluates the analytical sampling bound used to choose the
audit challenge size. The cancellation-forgery plot renders CSV output from the
Go protocol-level attack simulator in experiments/cancellationattack.
"""

from __future__ import annotations

import csv
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
from matplotlib.lines import Line2D
from matplotlib.transforms import ScaledTranslation


OUT = Path("experiments/out/attack_simulation")
BAR_XTICK_SHIFT_PT = 0.0


def setup_style() -> None:
    sns.set_theme(style="whitegrid", context="paper")
    plt.rcParams.update(
        {
            "font.family": "serif",
            "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
            "font.size": 8.5,
            "axes.labelsize": 8.5,
            "axes.titlesize": 9.5,
            "xtick.labelsize": 7.5,
            "ytick.labelsize": 7.5,
            "legend.fontsize": 7.3,
            "axes.linewidth": 0.8,
            "grid.linewidth": 0.45,
            "lines.linewidth": 1.55,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "savefig.dpi": 600,
            "savefig.bbox": "tight",
            "savefig.pad_inches": 0.02,
        }
    )


def save(fig: plt.Figure, name: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT / f"{name}.pdf")
    plt.close(fig)


def clean_axes(ax: plt.Axes) -> None:
    ax.grid(True, axis="y", which="major", color="#D0D0D0")
    ax.grid(False, axis="x")
    sns.despine(ax=ax, top=True, right=True)


def shift_xticklabels_right(ax: plt.Axes, points: float = BAR_XTICK_SHIFT_PT) -> None:
    if points == 0:
        return
    shift = ScaledTranslation(points / 72.0, 0.0, ax.figure.dpi_scale_trans)
    for label in ax.get_xticklabels():
        label.set_transform(label.get_transform() + shift)


def plot_sampling_detection() -> None:
    c_values = np.arange(0, 801, 10)
    ratios = [0.005, 0.01, 0.02, 0.05]
    colors = ["#4C78A8", "#54A24B", "#F58518", "#B279A2"]

    fig, ax = plt.subplots(figsize=(3.55, 2.55))
    for rho, color in zip(ratios, colors):
        detection = 1.0 - np.power(1.0 - rho, c_values)
        ax.plot(c_values, detection, color=color, label=fr"$\rho={rho * 100:.1f}\%$")

    c_star = 690
    target = 0.999
    ax.axvline(c_star, color="#222222", linewidth=0.9, linestyle="--")
    ax.axhline(target, color="#777777", linewidth=0.8, linestyle=":")
    ax.text(c_star + 8, 0.34, r"$c=690$", fontsize=7.5, rotation=90, va="bottom")
    ax.text(18, target - 0.055, r"$99.9\%$", fontsize=7.5, color="#555555")

    clean_axes(ax)
    ax.set_xlabel("Challenge size $c$")
    ax.set_ylabel("Detection probability")
    ax.set_ylim(0.0, 1.03)
    ax.set_xlim(0, 800)
    ax.legend(ncol=2, frameon=False, loc="lower center", bbox_to_anchor=(0.43, 0.02))
    fig.tight_layout()
    save(fig, "sampling_detection_probability")


def cancellation_frequency(p: int, m: int, trials: int, rng: np.random.Generator) -> float:
    deltas = rng.integers(0, p, size=(trials, m), dtype=np.int64)
    zero_rows = np.all(deltas == 0, axis=1)
    while np.any(zero_rows):
        deltas[zero_rows] = rng.integers(0, p, size=(int(np.sum(zero_rows)), m), dtype=np.int64)
        zero_rows = np.all(deltas == 0, axis=1)

    rho = rng.integers(0, p, size=trials, dtype=np.int64)
    powers = np.ones((trials, m), dtype=np.int64)
    for i in range(1, m):
        powers[:, i] = (powers[:, i - 1] * rho) % p
    folded = np.sum((deltas * powers) % p, axis=1) % p
    return float(np.mean(folded == 0))


def plot_folding_cancellation() -> None:
    rng = np.random.default_rng(20260429)
    p = 1009
    trials = 250_000
    m_values = np.array([2, 4, 8, 16, 32, 64], dtype=int)
    empirical = np.array([cancellation_frequency(p, int(m), trials, rng) for m in m_values])
    bound = (m_values - 1) / p

    fig, ax = plt.subplots(figsize=(3.55, 2.55))
    ax.plot(m_values, empirical, marker="o", markersize=3.5, color="#6B7280", label="Toy-field simulation")
    ax.plot(m_values, bound, marker="s", markersize=3.2, color="#F58518", linestyle="--", label=r"Bound $(m-1)/p$")

    clean_axes(ax)
    ax.set_xlabel("Batch size $m$")
    ax.set_ylabel("Cancellation frequency")
    ax.set_xticks(m_values)
    ax.set_ylim(0, max(bound) * 1.18)
    ax.legend(frameon=False, loc="upper left")
    fig.tight_layout()
    save(fig, "folding_cancellation_toy")


def plot_real_cancellation_attack() -> None:
    csv_path = OUT / "cancellation_attack_real.csv"
    if not csv_path.exists():
        raise FileNotFoundError(
            f"{csv_path} is missing; run "
            "go run ./experiments/cancellationattack -m 2,4,8 -trials 32 "
            "-n 16 -s 4 -c 4 -out experiments/out/attack_simulation/cancellation_attack_real.csv"
        )

    rows = []
    with csv_path.open(newline="") as f:
        for row in csv.DictReader(f):
            rows.append(
                {
                    "m": int(row["m"]),
                    "forced_rate": float(row["forced_rate"]),
                    "actual_rate": float(row["actual_rate"]),
                }
            )
    rows.sort(key=lambda row: row["m"])

    m_values = np.array([row["m"] for row in rows], dtype=int)
    forced = np.array([row["forced_rate"] for row in rows])
    actual = np.array([row["actual_rate"] for row in rows])
    x = np.arange(len(m_values))
    width = 0.34

    fig, ax = plt.subplots(figsize=(3.55, 2.55))
    ax.bar(x - width / 2, forced, width=width, color="#4C78A8", label="Programmed $\\rho$")
    ax.bar(x + width / 2, actual, width=width, color="#F58518", label="Fiat-Shamir $\\rho$")

    clean_axes(ax)
    ax.set_xlabel("Batch size $m$")
    ax.set_ylabel("Forged proof acceptance rate")
    ax.set_xticks(x)
    ax.set_xticklabels([str(v) for v in m_values])
    ax.set_ylim(0.0, 1.12)
    ax.legend(frameon=False, loc="upper right")
    fig.tight_layout()
    save(fig, "cancellation_attack_real")


def plot_cancellation_attack_cost() -> None:
    csv_path = OUT / "cancellation_attack_cost.csv"
    if not csv_path.exists():
        raise FileNotFoundError(
            f"{csv_path} is missing; run "
            "go run ./experiments/cancellationattack -trials 20 -m 4 -n 64 "
            "-s 8 -c 8 -out experiments/out/attack_simulation/cancellation_attack_cost.csv"
        )

    rows = []
    with csv_path.open(newline="") as f:
        for row in csv.DictReader(f):
            rows.append(
                {
                    "scheme": row["scheme"],
                    "accepted_rate": float(row["accepted_rate"]),
                    "attack_ms": float(row["attack_mean_ms"]),
                    "verify_ms": float(row["verify_mean_ms"]),
                    "total_ms": float(row["total_mean_ms"]),
                }
            )

    order = ["YuTC25", "ZhangTPDS23", "MiaoSCIS2026", "XuTIFS26", "FoldAudit"]
    rows.sort(key=lambda row: order.index(row["scheme"]))
    labels = ["Yu et al.", "Zhang et al.", "Miao et al.", "Xu et al.", "FoldAudit"]
    attack = np.array([row["attack_ms"] for row in rows])
    verify = np.array([row["verify_ms"] for row in rows])
    totals = np.array([row["total_ms"] for row in rows])
    accepted = np.array([row["accepted_rate"] > 0.5 for row in rows])
    x = np.arange(len(rows))

    fig, ax = plt.subplots(figsize=(3.55, 2.55))
    ax.bar(x, attack, color="#4C78A8", width=0.62, edgecolor="#222222", linewidth=0.45, label="Attack")
    ax.bar(
        x,
        verify,
        bottom=attack,
        color="#F58518",
        width=0.62,
        edgecolor="#222222",
        linewidth=0.45,
        label="Verify",
    )

    for xpos, total, ok in zip(x, totals, accepted):
        color = "#C44E52" if ok else "#2E8B57"
        marker = "x" if ok else "o"
        label = "Vuln." if ok else "Res."
        ypos = total + max(totals) * 0.035
        ax.scatter([xpos], [ypos], marker=marker, s=18, color=color, linewidths=1.1, zorder=4)
        ax.text(xpos, ypos + max(totals) * 0.035, label, ha="center", va="bottom", fontsize=6.7, color=color)

    clean_axes(ax)
    ax.set_xlabel("Protocol")
    ax.set_ylabel("Attack attempt time (ms)")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=0, ha="center")
    shift_xticklabels_right(ax)
    ax.set_ylim(0.0, max(totals) * 1.32)
    time_legend = ax.legend(frameon=False, loc="upper left", ncol=2)
    ax.add_artist(time_legend)
    status_handles = [
        Line2D([0], [0], marker="o", color="none", markerfacecolor="#2E8B57", markeredgecolor="#2E8B57", markersize=4.5, label="rejected"),
        Line2D([0], [0], marker="x", color="#C44E52", linestyle="none", markersize=4.5, label="accepted"),
    ]
    ax.legend(handles=status_handles, frameon=False, loc="upper right", ncol=1, handlelength=1.0, handletextpad=0.35)
    fig.tight_layout()
    save(fig, "cancellation_attack_cost")


def incremental_ranks(rows: np.ndarray, p: int) -> np.ndarray:
    basis: dict[int, np.ndarray] = {}
    ranks = []
    for row in rows:
        current = row.copy() % p
        while True:
            pivots = np.flatnonzero(current)
            if len(pivots) == 0:
                break
            pivot = int(pivots[0])
            if pivot not in basis:
                inv = pow(int(current[pivot]), -1, p)
                basis[pivot] = (current * inv) % p
                break
            current = (current - current[pivot] * basis[pivot]) % p
        ranks.append(len(basis))
    return np.array(ranks, dtype=float)


def leakage_matrix(rounds: int, n: int, s: int, c: int, p: int, rng: np.random.Generator) -> np.ndarray:
    rows = np.zeros((rounds, n * s), dtype=np.int64)
    for r in range(rounds):
        indices = rng.choice(n, size=c, replace=False)
        z = int(rng.integers(1, p))
        powers = np.ones(s, dtype=np.int64)
        for k in range(1, s):
            powers[k] = (powers[k - 1] * z) % p
        for index in indices:
            coeff = int(rng.integers(1, p))
            start = int(index) * s
            rows[r, start : start + s] = (coeff * powers) % p
    return rows


def plot_data_leakage_rank() -> None:
    n, s, c = 64, 8, 8
    rounds = 700
    p = 65537
    rng = np.random.default_rng(20260430)
    rows = leakage_matrix(rounds, n, s, c, p, rng)
    dimension = n * s

    exposed = incremental_ranks(rows, p) / dimension
    reused_mask_rows = (rows[1:] - rows[0]) % p
    reused = np.concatenate(([0.0], incremental_ranks(reused_mask_rows, p) / dimension))
    fresh = np.zeros(rounds)
    x = np.arange(1, rounds + 1)

    fig, ax = plt.subplots(figsize=(3.55, 2.55))
    ax.plot(x, exposed, color="#4C78A8", label="Exposed")
    ax.plot(x, reused, color="#F58518", linestyle="--", label="Reused mask")
    ax.plot(x, fresh, color="#6B7280", linestyle=":", label="Fresh mask")
    ax.axhline(1.0, color="#777777", linewidth=0.8, linestyle=":")
    ax.text(18, 0.945, "full rank", fontsize=7.3, color="#555555")

    clean_axes(ax)
    ax.set_xlabel("Audit rounds")
    ax.set_ylabel("Recoverable data rank")
    ax.set_ylim(-0.03, 1.05)
    ax.set_xlim(1, rounds)
    ax.legend(frameon=False, loc="lower right")
    fig.tight_layout()
    save(fig, "data_leakage_rank")


def rank_rounds(rows_by_round: list[np.ndarray], dimension: int, p: int) -> int:
    basis: dict[int, np.ndarray] = {}
    for round_no, rows in enumerate(rows_by_round, start=1):
        for row in rows:
            current = row.copy() % p
            while True:
                pivots = np.flatnonzero(current)
                if len(pivots) == 0:
                    break
                pivot = int(pivots[0])
                if pivot not in basis:
                    inv = pow(int(current[pivot]), -1, p)
                    basis[pivot] = (current * inv) % p
                    break
                current = (current - current[pivot] * basis[pivot]) % p
        if len(basis) >= dimension:
            return round_no
    raise RuntimeError(f"rank did not reach {dimension}; final rank={len(basis)}")


def sparse_chunk_row(n: int, c: int, p: int, rng: np.random.Generator) -> np.ndarray:
    row = np.zeros(n, dtype=np.int64)
    indices = rng.choice(n, size=c, replace=False)
    for index in indices:
        row[int(index)] = int(rng.integers(1, p))
    return row


def polynomial_evaluation_row(n: int, s: int, c: int, p: int, rng: np.random.Generator) -> np.ndarray:
    row = np.zeros(n * s, dtype=np.int64)
    indices = rng.choice(n, size=c, replace=False)
    z = int(rng.integers(1, p))
    powers = np.ones(s, dtype=np.int64)
    for k in range(1, s):
        powers[k] = (powers[k - 1] * z) % p
    for index in indices:
        coeff = int(rng.integers(1, p))
        start = int(index) * s
        row[start : start + s] = (coeff * powers) % p
    return row


def zhang_batch_row(m: int, n: int, s: int, c: int, p: int, rng: np.random.Generator) -> np.ndarray:
    row = np.zeros(m * n * s, dtype=np.int64)
    for file_index in range(m):
        beta = int(rng.integers(1, p))
        file_row = polynomial_evaluation_row(n, s, c, p, rng)
        start = file_index * n * s
        row[start : start + n * s] = (beta * file_row) % p
    return row


def leakage_recovery_rounds(m: int, n: int, s: int, c: int, p: int) -> dict[str, tuple[int | None, str]]:
    max_rounds = 2600

    rng = np.random.default_rng(20260501)
    yu_rows = [[sparse_chunk_row(n, c, p, rng)] for _ in range(max_rounds)]
    yu_rounds = rank_rounds(yu_rows, n, p)

    rng = np.random.default_rng(20260502)
    xu_rows = [[polynomial_evaluation_row(n, s, c, p, rng)] for _ in range(max_rounds)]
    xu_rounds = rank_rounds(xu_rows, n * s, p)

    rng = np.random.default_rng(20260503)
    zhang_rows = [[zhang_batch_row(m, n, s, c, p, rng)] for _ in range(max_rounds)]
    zhang_rounds = rank_rounds(zhang_rows, m * n * s, p)

    return {
        "YuTC25": (yu_rounds, "partial"),
        "ZhangTPDS23": (zhang_rounds, "full"),
        "MiaoSCIS2026": (None, "masked"),
        "XuTIFS26": (xu_rounds, "full"),
        "FoldAudit": (None, "masked"),
    }


def plot_data_leakage_attack_cost() -> None:
    csv_path = OUT / "data_leakage_audit_cost.csv"
    if not csv_path.exists():
        raise FileNotFoundError(
            f"{csv_path} is missing; run "
            "go run ./experiments/leakageattack -trials 20 -m 4 -n 64 "
            "-s 8 -c 8 -out experiments/out/attack_simulation/data_leakage_audit_cost.csv"
        )

    timing = {}
    with csv_path.open(newline="") as f:
        for row in csv.DictReader(f):
            timing[row["scheme"]] = {
                "audit_ms": float(row["audit_mean_ms"]),
                "m": int(row["m"]),
                "n": int(row["n"]),
                "s": int(row["s"]),
                "c": int(row["c"]),
            }

    params = next(iter(timing.values()))
    rounds = leakage_recovery_rounds(params["m"], params["n"], params["s"], params["c"], 65537)
    order = ["YuTC25", "ZhangTPDS23", "MiaoSCIS2026", "XuTIFS26", "FoldAudit"]
    labels = ["Yu et al.", "Zhang et al.", "Miao et al.", "Xu et al.", "FoldAudit"]

    recoverable = [scheme for scheme in order if rounds[scheme][0] is not None]
    cap = max(float(rounds[scheme][0]) * timing[scheme]["audit_ms"] / 1000.0 for scheme in recoverable) * 1.25
    costs = []
    hatches = []
    colors = []
    for scheme in order:
        round_count, status = rounds[scheme]
        if round_count is None:
            costs.append(cap)
            hatches.append("///")
            colors.append("#D8D8D8")
        else:
            costs.append(float(round_count) * timing[scheme]["audit_ms"] / 1000.0)
            hatches.append("")
            colors.append("#F58518" if status == "partial" else "#4C78A8")

    x = np.arange(len(order))
    fig, ax = plt.subplots(figsize=(3.55, 2.55))
    bars = ax.bar(x, costs, color=colors, width=0.62, edgecolor="#222222", linewidth=0.45)
    for bar, hatch in zip(bars, hatches):
        bar.set_hatch(hatch)

    for xpos, scheme, cost in zip(x, order, costs):
        round_count, status = rounds[scheme]
        if round_count is None:
            ax.text(xpos, cost * 0.88, "masked", ha="center", va="top", fontsize=7.1, rotation=90)
        elif status == "partial":
            ax.text(xpos, cost * 1.05, f"{round_count} rounds*", ha="center", va="bottom", fontsize=6.8)
        else:
            ax.text(xpos, cost * 1.05, f"{round_count} rounds", ha="center", va="bottom", fontsize=6.8)

    clean_axes(ax)
    ax.set_xlabel("Protocol")
    ax.set_ylabel("Estimated leakage cost (s)")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=0, ha="center")
    shift_xticklabels_right(ax)
    ax.set_ylim(0.0, cap * 1.12)
    ax.text(0.01, 0.96, "* partial leakage", transform=ax.transAxes, fontsize=7.0, va="top")
    fig.tight_layout()
    save(fig, "data_leakage_attack_cost")


def main() -> None:
    setup_style()
    plot_sampling_detection()
    plot_data_leakage_rank()
    plot_data_leakage_attack_cost()
    plot_cancellation_attack_cost()


if __name__ == "__main__":
    main()
