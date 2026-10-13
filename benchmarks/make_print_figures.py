#!/usr/bin/env python3
"""Print-quality figures for the dissertation, from the analysis outputs only.

Separate from analyze.py's make_figures, which produces the working set. These
are sized for a 16 cm text block, so matplotlib point sizes are literal points
on the page, and coloured to match the architecture figures.

    python benchmarks/make_print_figures.py
"""

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

OUT = "benchmarks/figures_final"
W = 6.3  # 16 cm

BLUE, TEAL, CORAL, AMBER, GREY = "#185FA5", "#0F6E56", "#993C1D", "#854F0B", "#5F5E5A"

plt.rcParams.update({
    "font.family": "sans-serif",
    "font.sans-serif": ["Calibri", "Carlito", "DejaVu Sans"],
    "font.size": 9,
    "axes.titlesize": 10,
    "axes.labelsize": 9,
    "xtick.labelsize": 8.5,
    "ytick.labelsize": 8.5,
    "legend.fontsize": 8.5,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "grid.alpha": 0.25,
    "grid.linewidth": 0.6,
    "axes.axisbelow": True,
    "figure.constrained_layout.use": True,
    "svg.fonttype": "none",
})


def save(fig, name):
    fig.savefig(f"{OUT}/{name}.svg")
    fig.savefig(f"{OUT}/{name}.pdf")
    fig.savefig(f"{OUT}/{name}.png", dpi=600)
    plt.close(fig)
    print(f"  wrote {OUT}/{name}.svg, .pdf and .png")


def window_pairing():
    p = pd.read_csv(f"{OUT}/_pairing.csv")
    w = p[p.cell.str.startswith("WINDOW")]
    coupled = w[w.window_ms == w.horizon_ms]
    dec = w[(w.window_ms != w.horizon_ms) & (w.predicate == "file_path")]

    fig, ax = plt.subplots(figsize=(W, 3.4))

    fp = coupled[coupled.predicate == "file_path"].sort_values("window_ms")
    ax.plot(fp.window_ms, fp.pct, marker="o", ms=5, lw=1.8, color=BLUE, zorder=3)

    # Both are identically zero at every width, so one line carries both and
    # the second is marked by an offset glyph rather than hidden underneath.
    de = coupled[coupled.predicate == "dest_endpoint"].sort_values("window_ms")
    tr = coupled[coupled.predicate == "trace_id"].sort_values("window_ms")
    ax.plot(de.window_ms, de.pct, marker="s", ms=5, lw=1.8, color=TEAL, zorder=3)
    ax.plot(
        tr.window_ms,
        tr.pct,
        marker="^",
        ms=6,
        lw=0,
        color=CORAL,
        zorder=4,
        mfc="none",
        mew=1.4,
    )

    if not dec.empty:
        d = dec.iloc[0]
        ax.plot(
            d.window_ms,
            d.pct,
            marker="D",
            ms=7,
            color=BLUE,
            mfc="white",
            mew=1.8,
            zorder=5,
        )
    ax.annotate(
        "510 ms floor at a zero ceiling:\nthe cost of capturing\nthe process environment",
        xy=(0.25, 0.6),
        xytext=(2.0, 20.0),
        fontsize=8,
        color=BLUE,
        va="top",
        arrowprops=dict(
            arrowstyle="->", lw=0.8, color=BLUE, connectionstyle="arc3,rad=-0.2"
        ),
    )

    ax.axvline(15000, color=GREY, lw=0.8, ls=":", zorder=1)
    ax.annotate(
        "benign traffic has swept\nthe 512-object pool",
        xy=(15000, 24),
        xytext=(15800, 17),
        fontsize=8,
        color=GREY,
    )

    ax.text(
        30400, fp.pct.iloc[-1], "object path", color=BLUE, fontsize=8.5, va="center"
    )
    ax.text(30400, 0.9, "destination endpoint", color=TEAL, fontsize=8.5, va="center")
    ax.text(30400, -1.1, "declared identifier", color=CORAL, fontsize=8.5, va="center")

    ax.set_xlabel("Correlation window (ms)")
    ax.set_ylabel("Kernel events paired with another request (%)")
    ax.set_xlim(1000, 40000)
    ax.set_ylim(-3, 30)
    ax.set_xticks([2000, 5000, 10000, 20000, 30000])
    save(fig, "fig_4_3_window_pairing")


def enrichment():
    c = pd.read_csv(f"{OUT}/_collection.csv")
    m = pd.read_csv(f"{OUT}/_metrics.csv")
    ex = c[(c.event_type == "execve") & c.cell.str.startswith("ENRICH")].copy()
    ex["ceil"] = ex.enrich_retries * ex.enrich_delay_s
    ex = ex.sort_values("ceil")
    r = m[
        (m["class"] == "RCE_COMMAND_INJECTION") & m.cell.str.startswith("ENRICH")
    ].copy()
    r["ceil"] = r.enrich_retries * r.enrich_delay_s
    r = r.sort_values("ceil")

    fig, ax = plt.subplots(figsize=(W, 3.2))
    ax.plot(ex.ceil, ex.p50 / 1000, marker="o", ms=5, lw=1.8, color=BLUE, zorder=3)
    ax.set_xlabel("Enrichment retry ceiling (s)")
    ax.set_ylabel("Kernel export delay, p50 (s)")
    ax.set_ylim(-1.5, 32)
    ax.set_xlim(-1.5, 32)

    ax2 = ax.twinx()
    ax2.plot(r.ceil, r.recall, marker="s", ms=5, lw=1.6, ls="--", color=CORAL, zorder=3)
    ax2.set_ylabel("Execution recall", color=CORAL)
    ax2.set_ylim(0, 1.08)
    ax2.tick_params(axis="y", colors=CORAL)
    ax2.grid(False)
    ax2.spines["top"].set_visible(False)

    ax.annotate(
        "510 ms floor at a zero ceiling:\nthe cost of capturing the environment",
        xy=(0, 0.51),
        xytext=(3.2, 5.6),
        fontsize=8,
        color=BLUE,
        arrowprops=dict(arrowstyle="->", lw=0.8, color=BLUE),
    )
    ax2.text(16.5, 1.025, "recall 1.000 at every ceiling", fontsize=8.5, color=CORAL)
    ax.text(21.5, 24.5, "export delay", fontsize=8.5, color=BLUE)
    save(fig, "fig_4_4_enrichment")


def latency():
    l = pd.read_csv(f"{OUT}/_latency.csv")
    b = l[l.cell == "B3_DeterministicBridge"].set_index("alert_type")
    order = [
        "BOLA_AUTHORIZATION_BYPASS",
        "SSRF_UNAUTHORIZED_PROBE",
        "RCE_COMMAND_INJECTION",
    ]
    short = {
        order[0]: "Object access",
        order[1]: "Outbound probe",
        order[2]: "Process execution",
    }

    # Two panels at different scales, because 6 ms and 504 ms on one linear
    # axis renders two of the three classes as sub-pixel slivers.
    fig, (a1, a2) = plt.subplots(
        1, 2, figsize=(W, 3.0), gridspec_kw={"width_ratios": [1, 1.25]}
    )
    fig.set_layout_engine(None)
    fig.subplots_adjust(left=0.17, right=0.97, top=0.86, bottom=0.30, wspace=0.55)

    segs = [
        ("spawn_p50", "Process spawn", GREY),
        ("export_p50", "Kernel export", AMBER),
        ("pipeline_p50", "Correlation and response", TEAL),
    ]

    for ax, rows in ((a1, order[:2]), (a2, order[2:])):
        left = [0.0] * len(rows)
        for col, lab, colour in segs:
            vals = [max(b.loc[k, col], 0) for k in rows]
            ax.barh(
                [short[k] for k in rows],
                vals,
                left=left,
                color=colour,
                height=0.45,
                label=lab,
                zorder=3,
            )
            left = [a + v for a, v in zip(left, vals)]
        for i, k in enumerate(rows):
            ax.text(left[i] * 1.05, i, f"{left[i]:.0f} ms", va="center", fontsize=8.5)
        ax.set_xlim(0, max(left) * 1.32)
        ax.set_xlabel("Median latency (ms)")

    a1.set_title("Two classes at millisecond scale", fontsize=9, loc="left")
    a2.set_title("Process execution, note the scale", fontsize=9, loc="left")
    h, lb = a1.get_legend_handles_labels()
    fig.legend(
        h,
        lb,
        loc="lower center",
        ncol=3,
        frameon=False,
        bbox_to_anchor=(0.5, 0.005),
        handlelength=1.2,
        columnspacing=1.6,
    )
    save(fig, "fig_4_5_latency_decomposition")


if __name__ == "__main__":
    window_pairing()
    enrichment()
    latency()
