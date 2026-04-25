"""
STEP 5 — RESULTS ANALYSIS
===========================
Analyzes Echidna test results and computes evaluation metrics:

    1. Detection Rate     : bugs detected / total bugs injected
    2. Activation Rate    : bug lines reached by fuzzer / total bugs injected
    3. Avg Detection Time : mean detection time per bug variant (seconds)

Visualization output (PNG, dark theme):
    chart1_rate_comparison.png      — Detection & Activation Rate grouped bar
    chart2_detection_time_dist.png  — Detection time violin + strip plot
    chart3_status_breakdown.png     — Stacked bar: result status per variant
    chart4_detection_time_scatter.png — Per-contract detection time line/scatter
    chart5_overall_donut.png        — Outcome distribution donut chart
    chart6_radar.png                — Multi-metric radar / spider chart
"""

import csv
import json
import math
import os
from datetime import datetime
from typing import Dict, List, Optional

import matplotlib
matplotlib.use("Agg")           # Non-interactive backend — safe for all environments
import matplotlib.pyplot as plt
import numpy as np

from config import ANALYSIS_RESULTS_DIR, BUG_VARIANTS, ECHIDNA_TIMEOUT, LOGS_DIR
from logger import get_logger

log = get_logger("analyzer")

# ---------------------------------------------------------------------------
# Visual theme constants
# ---------------------------------------------------------------------------

_BG_FIGURE   = "#0f1117"    # Outermost figure background
_BG_AXES     = "#1a1d27"    # Individual axes background
_BG_LEGEND   = "#2a2d3e"    # Legend background
_GRID_COLOR  = "#2d3142"    # Major grid lines
_SPINE_COLOR = "#3a3f52"    # Axis spine color

_VARIANT_COLORS = {
    "single_function": "#4C72B0",
    "cross_function":  "#DD8452",
}
_STATUS_COLORS = {
    "Detected":              "#2ecc71",
    "Reachable (not broken)": "#3498db",
    "Unreachable":            "#e74c3c",
    "Timeout":                "#f39c12",
    "Error":                  "#95a5a6",
}

# Variants to include in per-variant charts (excludes the "overall" aggregate)
_PER_VARIANT = [v for v in BUG_VARIANTS]


# ---------------------------------------------------------------------------
# Metric dataclass
# ---------------------------------------------------------------------------

class MetricResult:
    """Aggregated metrics for a single bug variant."""

    def __init__(self, variant: str) -> None:
        self.variant             = variant
        self.total_injected      = 0
        self.total_detected      = 0
        self.total_activated     = 0
        self.total_timeout       = 0
        self.total_error         = 0
        self.detection_times:    List[float] = []   # Only for DETECTED results
        self.detected_files:     List[str]   = []
        self.not_detected_files: List[str]   = []

    @property
    def detection_rate(self) -> float:
        """Detection Rate = Detected / Total Injected  (Chapter 2.5.1)"""
        return self.total_detected / self.total_injected if self.total_injected else 0.0

    @property
    def activation_rate(self) -> float:
        """Activation Rate = Activated / Total Injected  (Chapter 2.5.2)"""
        return self.total_activated / self.total_injected if self.total_injected else 0.0

    @property
    def avg_detection_time(self) -> float:
        """
        Average Detection Time  (Chapter 2.5.3).
        Falls back to ECHIDNA_TIMEOUT when no detection times are recorded.
        """
        return (
            sum(self.detection_times) / len(self.detection_times)
            if self.detection_times
            else ECHIDNA_TIMEOUT
        )

    @property
    def total_reachable(self) -> int:
        """
        Reachable = bugs that were activated but did NOT break the property.
        Demonstrates compiler-level protection (e.g. Solidity 0.8+ underflow revert).
        """
        return self.total_activated - self.total_detected

    def to_dict(self) -> dict:
        return {
            "variant":                self.variant,
            "total_injected":         self.total_injected,
            "total_detected":         self.total_detected,
            "total_reachable":        self.total_reachable,
            "total_not_detected":     (
                self.total_injected
                - self.total_detected
                - self.total_timeout
                - self.total_error
            ),
            "total_activated":        self.total_activated,
            "total_timeout":          self.total_timeout,
            "total_error":            self.total_error,
            "detection_rate":         round(self.detection_rate, 4),
            "detection_rate_pct":     f"{self.detection_rate * 100:.2f}%",
            "activation_rate":        round(self.activation_rate, 4),
            "activation_rate_pct":    f"{self.activation_rate * 100:.2f}%",
            "avg_detection_time_sec": round(self.avg_detection_time, 2),
            "detected_files":         self.detected_files,
            "not_detected_files":     self.not_detected_files,
        }


# ---------------------------------------------------------------------------
# Data loaders
# ---------------------------------------------------------------------------

def load_echidna_results(path: str) -> list:
    """Load Echidna results from a JSON file."""
    if not os.path.isfile(path):
        log.error("Echidna results file not found: %s", path)
        return []
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_injection_log(path: str) -> list:
    """Load the injection log from a JSON file."""
    if not os.path.isfile(path):
        log.error("Injection log not found: %s", path)
        return []
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Metric computation
# ---------------------------------------------------------------------------

def compute_metrics(echidna_results: list) -> Dict[str, MetricResult]:
    """
    Compute all metrics from a list of Echidna results.

    Returns:
        Dict mapping variant name → MetricResult, including an "overall" entry.
    """
    metrics: Dict[str, MetricResult] = {v: MetricResult(v) for v in BUG_VARIANTS}
    metrics["overall"] = MetricResult("overall")

    for r in echidna_results:
        variant = r.get("variant", "unknown")
        if variant not in metrics:
            metrics[variant] = MetricResult(variant)

        mr      = metrics[variant]
        overall = metrics["overall"]

        mr.total_injected      += 1
        overall.total_injected += 1

        status          = r.get("status", "UNKNOWN")
        property_broken = r.get("property_broken", False)
        bug_line_hit    = r.get("bug_line_hit", False)
        detection_time  = r.get("detection_time_sec", -1.0)
        source_file     = r.get("source_file", "unknown")

        # Detection Rate
        if status == "DETECTED" and property_broken:
            mr.total_detected      += 1
            overall.total_detected += 1
            mr.detected_files.append(source_file)
            overall.detected_files.append(source_file)
            if detection_time > 0:
                mr.detection_times.append(detection_time)
                overall.detection_times.append(detection_time)
        else:
            mr.not_detected_files.append(source_file)
            overall.not_detected_files.append(source_file)

        # Activation Rate
        if bug_line_hit:
            mr.total_activated      += 1
            overall.total_activated += 1

        # Other status counters
        if status == "TIMEOUT":
            mr.total_timeout      += 1
            overall.total_timeout += 1
        elif status == "ERROR":
            mr.total_error      += 1
            overall.total_error += 1

    return metrics


# ---------------------------------------------------------------------------
# Console display
# ---------------------------------------------------------------------------

def print_metrics_table(metrics: Dict[str, MetricResult]) -> None:
    """Print a formatted metrics summary table to the log."""
    sep = "=" * 95
    log.info("")
    log.info(sep)
    log.info("ANALYSIS RESULTS — METRICS SUMMARY")
    log.info(sep)
    log.info(
        "%-20s | %-6s | %-9s | %-11s | %-6s | %-10s | %-6s | %-12s",
        "Variant", "Total", "Detected", "Reachable", "DR%", "Activated", "AR%", "Avg Time(s)",
    )
    log.info("-" * 95)

    for mr in metrics.values():
        if mr.total_injected == 0:
            continue
        log.info(
            "%-20s | %-6d | %-9d | %-11d | %-5.1f%% | %-10d | %-5.1f%% | %-12.2f",
            mr.variant,
            mr.total_injected,
            mr.total_detected,
            mr.total_reachable,
            mr.detection_rate * 100,
            mr.total_activated,
            mr.activation_rate * 100,
            mr.avg_detection_time,
        )

    log.info(sep)


# ---------------------------------------------------------------------------
# Shared plot utilities
# ---------------------------------------------------------------------------

def _apply_dark_theme(fig, ax_or_axes) -> None:
    """Apply the shared dark background and grid style to a figure."""
    fig.patch.set_facecolor(_BG_FIGURE)
    axes = ax_or_axes if isinstance(ax_or_axes, (list, np.ndarray)) else [ax_or_axes]
    for ax in np.ravel(axes):
        ax.set_facecolor(_BG_AXES)
        ax.tick_params(colors="white")
        for spine in ax.spines.values():
            spine.set_color(_SPINE_COLOR)


def _save(fig, path: str) -> None:
    """Save a figure and close it."""
    plt.savefig(path, dpi=140, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)
    log.info("  ✓ Chart saved : %s", os.path.basename(path))


# ---------------------------------------------------------------------------
# Chart 1 — Detection & Activation Rate grouped horizontal bar
# ---------------------------------------------------------------------------

def _chart_rate_comparison(
    metrics: Dict[str, MetricResult],
    output_dir: str,
) -> str:
    """
    Grouped horizontal bar chart comparing Detection Rate vs Activation Rate
    for each variant side-by-side.

    Best for: quick visual comparison of two key rates across variants.
    """
    fig, ax = plt.subplots(figsize=(9, 4.5))
    _apply_dark_theme(fig, ax)

    bar_h   = 0.32
    y       = np.arange(len(_PER_VARIANT))
    dr_vals = [metrics[v].detection_rate * 100  for v in _PER_VARIANT]
    ar_vals = [metrics[v].activation_rate * 100 for v in _PER_VARIANT]

    b1 = ax.barh(y + bar_h / 2, dr_vals, bar_h, label="Detection Rate",  color="#4C72B0", zorder=3)
    b2 = ax.barh(y - bar_h / 2, ar_vals, bar_h, label="Activation Rate", color="#DD8452", zorder=3)

    for bar in (*b1, *b2):
        w = bar.get_width()
        ax.text(
            w + 1, bar.get_y() + bar.get_height() / 2,
            f"{w:.1f}%", va="center", ha="left", fontsize=8.5, color="white",
        )

    ax.set_yticks(y)
    ax.set_yticklabels(
        [v.replace("_", " ").title() for v in _PER_VARIANT], color="white", fontsize=10
    )
    ax.set_xlabel("Rate (%)", color="white", fontsize=10)
    ax.set_xlim(0, 118)
    ax.set_title("Detection & Activation Rate by Variant", color="white", fontsize=13, pad=12)
    ax.xaxis.grid(True, color=_GRID_COLOR, linestyle="--", linewidth=0.6, zorder=0)
    ax.legend(facecolor=_BG_LEGEND, labelcolor="white", fontsize=9, loc="lower right")

    plt.tight_layout()
    path = os.path.join(output_dir, "chart1_rate_comparison.png")
    _save(fig, path)
    return path


# ---------------------------------------------------------------------------
# Chart 2 — Detection time distribution: violin + strip
# ---------------------------------------------------------------------------

def _chart_detection_time_dist(
    echidna_results: list,
    output_dir: str,
) -> Optional[str]:
    """
    Violin plot with individual data points overlaid (strip chart).

    Best for: showing the full distribution shape + spread of detection times,
              not just the mean — reveals bimodal or skewed distributions.
    """
    detected = [
        r for r in echidna_results
        if r.get("property_broken") and r.get("detection_time_sec", -1) > 0
    ]
    if len(detected) < 3:
        log.warning("Chart 2 skipped: fewer than 3 detected results with timing data.")
        return None

    labels = sorted({r["variant"] for r in detected})
    groups = [[r["detection_time_sec"] for r in detected if r["variant"] == lbl] for lbl in labels]

    fig, ax = plt.subplots(figsize=(8, 5))
    _apply_dark_theme(fig, ax)

    parts = ax.violinplot(groups, positions=range(len(labels)), widths=0.6, showmedians=True)
    for i, (body, lbl) in enumerate(zip(parts["bodies"], labels)):
        body.set_facecolor(_VARIANT_COLORS.get(lbl, "#888888"))
        body.set_alpha(0.5)
    parts["cmedians"].set_color("white")
    for key in ("cbars", "cmaxes", "cmins"):
        parts[key].set_color("#888888")

    rng = np.random.default_rng(42)
    for i, (lbl, vals) in enumerate(zip(labels, groups)):
        jitter = rng.uniform(-0.08, 0.08, size=len(vals))
        ax.scatter(
            i + jitter, vals,
            color=_VARIANT_COLORS.get(lbl, "#888888"),
            edgecolors="white", linewidths=0.4, s=32, zorder=3, alpha=0.85,
        )

    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels([l.replace("_", " ").title() for l in labels], color="white", fontsize=10)
    ax.set_ylabel("Detection Time (s)", color="white", fontsize=10)
    ax.set_title("Detection Time Distribution by Variant", color="white", fontsize=13, pad=12)
    ax.yaxis.grid(True, color=_GRID_COLOR, linestyle="--", linewidth=0.6)

    plt.tight_layout()
    path = os.path.join(output_dir, "chart2_detection_time_dist.png")
    _save(fig, path)
    return path


# ---------------------------------------------------------------------------
# Chart 3 — Status breakdown stacked bar
# ---------------------------------------------------------------------------

def _chart_status_breakdown(
    metrics: Dict[str, MetricResult],
    output_dir: str,
) -> str:
    """
    Stacked bar chart showing how each variant's contracts are distributed
    across outcome categories: Detected, Reachable, Unreachable, Timeout, Error.

    Best for: understanding where contracts "fall off" in the detection funnel.
    """
    fig, ax = plt.subplots(figsize=(9, 5))
    _apply_dark_theme(fig, ax)

    x     = np.arange(len(_PER_VARIANT))
    xlbls = [v.replace("_", " ").title() for v in _PER_VARIANT]

    # Segment definitions: (label, extractor_fn, color)
    segments = [
        ("Detected",              lambda v: metrics[v].total_detected,
         "#2ecc71"),
        ("Reachable (not broken)", lambda v: max(0, metrics[v].total_reachable),
         "#3498db"),
        ("Unreachable",           lambda v: max(0, metrics[v].to_dict()["total_not_detected"] - max(0, metrics[v].total_reachable)),
         "#e74c3c"),
        ("Timeout",               lambda v: metrics[v].total_timeout,
         "#f39c12"),
        ("Error",                 lambda v: metrics[v].total_error,
         "#95a5a6"),
    ]

    bottoms = np.zeros(len(_PER_VARIANT))
    for label, extractor, color in segments:
        vals = np.array([extractor(v) for v in _PER_VARIANT], dtype=float)
        bars = ax.bar(x, vals, bottom=bottoms, color=color, label=label, width=0.5, zorder=3)
        for bar, v in zip(bars, vals):
            if v > 0:
                ax.text(
                    bar.get_x() + bar.get_width() / 2,
                    bar.get_y() + bar.get_height() / 2,
                    str(int(v)), ha="center", va="center",
                    fontsize=8.5, color="white", fontweight="bold",
                )
        bottoms += vals

    ax.set_xticks(x)
    ax.set_xticklabels(xlbls, color="white", fontsize=10)
    ax.set_ylabel("Number of Contracts", color="white", fontsize=10)
    ax.set_title("Result Status Breakdown by Variant", color="white", fontsize=13, pad=12)
    ax.yaxis.grid(True, color=_GRID_COLOR, linestyle="--", linewidth=0.6, zorder=0)
    ax.legend(facecolor=_BG_LEGEND, labelcolor="white", fontsize=8.5,
              loc="upper right", ncol=2)

    plt.tight_layout()
    path = os.path.join(output_dir, "chart3_status_breakdown.png")
    _save(fig, path)
    return path


# ---------------------------------------------------------------------------
# Chart 4 — Per-contract detection time (sorted line + scatter)
# ---------------------------------------------------------------------------

def _chart_detection_time_scatter(
    echidna_results: list,
    output_dir: str,
) -> str:
    """
    Each contract is plotted as a point sorted by detection time.
    A connecting line shows the cumulative curve.
    Detected contracts (●) and non-detected (✕) use distinct markers.

    Best for: showing how quickly the fuzzer converges and which contracts
              are hardest to detect, analogous to a learning curve.
    """
    fig, ax = plt.subplots(figsize=(11, 5))
    _apply_dark_theme(fig, ax)

    for vname in _PER_VARIANT:
        color  = _VARIANT_COLORS.get(vname, "#888888")
        subset = sorted(
            [r for r in echidna_results if r.get("variant") == vname],
            key=lambda r: r.get("detection_time_sec", ECHIDNA_TIMEOUT),
        )
        xs  = list(range(len(subset)))
        ys  = [r.get("detection_time_sec", ECHIDNA_TIMEOUT) for r in subset]
        det = [bool(r.get("property_broken")) for r in subset]

        # Faint connecting line
        ax.plot(xs, ys, color=color, linewidth=1.2, alpha=0.35, zorder=2)

        xs_d = [x for x, d in zip(xs, det) if d]
        ys_d = [y for y, d in zip(ys, det) if d]
        xs_n = [x for x, d in zip(xs, det) if not d]
        ys_n = [y for y, d in zip(ys, det) if not d]

        label = vname.replace("_", " ").title()
        ax.scatter(xs_d, ys_d, color=color, edgecolors="white",
                   linewidths=0.5, s=50, zorder=4, label=f"{label} — Detected")
        ax.scatter(xs_n, ys_n, color=color, s=50, zorder=4,
                   alpha=0.45, marker="x", label=f"{label} — Not Detected")

    ax.axhline(
        y=ECHIDNA_TIMEOUT, color="#e74c3c", linewidth=1.2,
        linestyle="--", label=f"Timeout ({ECHIDNA_TIMEOUT}s)",
    )
    ax.set_xlabel("Contract Index (sorted by detection time)", color="white", fontsize=10)
    ax.set_ylabel("Detection Time (s)", color="white", fontsize=10)
    ax.set_title("Per-Contract Detection Time", color="white", fontsize=13, pad=12)
    ax.yaxis.grid(True, color=_GRID_COLOR, linestyle="--", linewidth=0.6, zorder=0)
    ax.legend(facecolor=_BG_LEGEND, labelcolor="white", fontsize=8.5,
              loc="upper left", ncol=2)

    plt.tight_layout()
    path = os.path.join(output_dir, "chart4_detection_time_scatter.png")
    _save(fig, path)
    return path


# ---------------------------------------------------------------------------
# Chart 5 — Overall outcome donut chart
# ---------------------------------------------------------------------------

def _chart_overall_donut(
    metrics: Dict[str, MetricResult],
    output_dir: str,
) -> str:
    """
    Donut chart showing the proportion of each outcome category across ALL contracts.
    The hole displays the total contract count.

    Best for: executive-level summary — a single glance at the overall health of
              the detection campaign.
    """
    ov = metrics["overall"]

    detected     = ov.total_detected
    reachable    = max(0, ov.total_reachable)
    unreachable  = max(0, ov.to_dict()["total_not_detected"] - reachable)
    timeout      = ov.total_timeout
    error        = ov.total_error

    raw = [
        ("Detected",               detected,    "#2ecc71"),
        ("Reachable\n(not broken)", reachable,   "#3498db"),
        ("Unreachable",            unreachable,  "#e74c3c"),
        ("Timeout",                timeout,      "#f39c12"),
        ("Error",                  error,        "#95a5a6"),
    ]
    filtered = [(lbl, s, c) for lbl, s, c in raw if s > 0]
    if not filtered:
        log.warning("Chart 5 skipped: no data for overall donut.")
        return ""

    labels, sizes, colors = zip(*filtered)

    fig, ax = plt.subplots(figsize=(6.5, 6.5))
    fig.patch.set_facecolor(_BG_FIGURE)
    ax.set_facecolor(_BG_FIGURE)

    wedges, _, autotexts = ax.pie(
        sizes, labels=None, colors=colors, autopct="%1.1f%%",
        startangle=90, pctdistance=0.78,
        wedgeprops=dict(width=0.5, edgecolor=_BG_FIGURE, linewidth=2),
    )
    for at in autotexts:
        at.set_color("white")
        at.set_fontsize(9)

    ax.legend(
        wedges, [f"{l.replace(chr(10),' ')}  ({s})" for l, s in zip(labels, sizes)],
        loc="lower center", bbox_to_anchor=(0.5, -0.06),
        facecolor=_BG_LEGEND, labelcolor="white", fontsize=9, ncol=3,
    )
    ax.text(0, 0, f"{ov.total_injected}\nTotal",
            ha="center", va="center", color="white", fontsize=14, fontweight="bold")
    ax.set_title("Overall Outcome Distribution", color="white", fontsize=13, pad=10)

    plt.tight_layout()
    path = os.path.join(output_dir, "chart5_overall_donut.png")
    _save(fig, path)
    return path


# ---------------------------------------------------------------------------
# Chart 6 — Multi-metric radar / spider chart
# ---------------------------------------------------------------------------

def _chart_radar(
    metrics: Dict[str, MetricResult],
    output_dir: str,
) -> str:
    """
    Spider/radar chart overlaying all variants across five normalised metrics.

    Axes: Detection Rate | Activation Rate | Reachable Ratio | Timeout Ratio | Error Ratio

    Best for: holistic comparison — seeing which variant is harder to detect
              and where each variant's "weak spots" are.
    """
    cats   = ["Detection\nRate", "Activation\nRate", "Reachable\nRatio",
              "Timeout\nRatio", "Error\nRatio"]
    n_cats = len(cats)
    angles = [n / n_cats * 2 * math.pi for n in range(n_cats)] + [0]  # close the polygon

    fig, ax = plt.subplots(figsize=(6.5, 6.5), subplot_kw=dict(polar=True))
    fig.patch.set_facecolor(_BG_FIGURE)
    ax.set_facecolor(_BG_AXES)

    for vname in _PER_VARIANT:
        color = _VARIANT_COLORS.get(vname, "#888888")
        m     = metrics[vname]
        total = m.total_injected or 1   # avoid /0

        vals = [
            m.detection_rate,
            m.activation_rate,
            max(0, m.total_reachable)  / total,
            m.total_timeout            / total,
            m.total_error              / total,
        ]
        vals += [vals[0]]   # close the polygon

        label = vname.replace("_", " ").title()
        ax.plot(angles, vals, color=color, linewidth=2, label=label)
        ax.fill(angles, vals, color=color, alpha=0.18)

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(cats, color="white", fontsize=9)
    ax.yaxis.set_tick_params(labelcolor="white", labelsize=7)
    ax.spines["polar"].set_color(_SPINE_COLOR)
    ax.set_rlabel_position(30)
    for grid_line in ax.yaxis.get_gridlines():
        grid_line.set_color(_SPINE_COLOR)
    for grid_line in ax.xaxis.get_gridlines():
        grid_line.set_color(_SPINE_COLOR)

    ax.set_title("Multi-Metric Radar Comparison", color="white", fontsize=13, pad=20)
    ax.legend(facecolor=_BG_LEGEND, labelcolor="white", fontsize=9,
              loc="upper right", bbox_to_anchor=(1.35, 1.12))

    plt.tight_layout()
    path = os.path.join(output_dir, "chart6_radar.png")
    _save(fig, path)
    return path


# ---------------------------------------------------------------------------
# Visualization runner
# ---------------------------------------------------------------------------

def generate_charts(
    metrics: Dict[str, MetricResult],
    echidna_results: list,
    output_dir: str,
    timestamp: str,
) -> List[str]:
    """
    Render all six charts and save them to *output_dir*.

    Args:
        metrics         : Computed MetricResult objects keyed by variant name.
        echidna_results : Raw list of per-contract Echidna result dicts.
        output_dir      : Directory where chart PNGs are written.
        timestamp       : Timestamp string used for the charts sub-folder name.

    Returns:
        List of file paths for every chart that was successfully generated.
    """
    charts_dir = os.path.join(output_dir, f"charts_{timestamp}")
    os.makedirs(charts_dir, exist_ok=True)

    log.info("")
    log.info("Generating charts → %s", charts_dir)

    saved: List[str] = []

    chart_fns = [
        ("Rate comparison (grouped bar)",     lambda: _chart_rate_comparison(metrics, charts_dir)),
        ("Detection time distribution",        lambda: _chart_detection_time_dist(echidna_results, charts_dir)),
        ("Status breakdown (stacked bar)",     lambda: _chart_status_breakdown(metrics, charts_dir)),
        ("Per-contract detection time",        lambda: _chart_detection_time_scatter(echidna_results, charts_dir)),
        ("Overall outcome (donut)",            lambda: _chart_overall_donut(metrics, charts_dir)),
        ("Multi-metric radar",                 lambda: _chart_radar(metrics, charts_dir)),
    ]

    for name, fn in chart_fns:
        try:
            path = fn()
            if path:
                saved.append(path)
        except Exception as exc:
            log.warning("Chart '%s' failed: %s", name, exc)

    log.info("Charts generated: %d / %d", len(saved), len(chart_fns))
    return saved


# ---------------------------------------------------------------------------
# CSV / JSON export
# ---------------------------------------------------------------------------

def export_metrics_csv(metrics: Dict[str, MetricResult], output_path: str) -> None:
    """Export the metrics summary to a CSV file."""
    fieldnames = [
        "variant", "total_injected", "total_detected", "total_reachable",
        "total_not_detected", "total_activated", "total_timeout", "total_error",
        "detection_rate", "detection_rate_pct",
        "activation_rate", "activation_rate_pct",
        "avg_detection_time_sec",
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for mr in metrics.values():
            if mr.total_injected == 0:
                continue
            writer.writerow({k: mr.to_dict().get(k, "") for k in fieldnames})
    log.info("Metrics CSV     : %s", output_path)


def export_detail_csv(echidna_results: list, output_path: str) -> None:
    """Export per-contract results to a CSV file."""
    fieldnames = [
        "source_file", "contract_name", "variant",
        "status", "property_broken", "bug_line_hit",
        "detection_time_sec", "error_message",
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in echidna_results:
            writer.writerow({k: r.get(k, "") for k in fieldnames})
    log.info("Detail CSV      : %s", output_path)


def export_summary_json(
    metrics: Dict[str, MetricResult],
    echidna_results: list,
    output_path: str,
) -> None:
    """Write a comprehensive JSON summary file."""
    summary = {
        "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "tool":        "Dynamic Reentrancy Bug Injection Tool",
        "description": "Evaluation of Echidna's effectiveness in detecting reentrancy via bug injection",
        "reference":   "Ghaleb & Pattabiraman (2020) — SolidiFI, adapted for dynamic analysis",
        "metrics_per_variant": {
            variant: mr.to_dict()
            for variant, mr in metrics.items()
            if mr.total_injected > 0
        },
        "raw_results": echidna_results,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    log.info("Summary JSON    : %s", output_path)


# ---------------------------------------------------------------------------
# Main analysis runner
# ---------------------------------------------------------------------------

def run_analysis(
    echidna_results_json: Optional[str] = None,
    injection_log_json: Optional[str]   = None,
    output_dir: str                     = ANALYSIS_RESULTS_DIR,
) -> Dict[str, MetricResult]:
    """
    Run the full analysis pipeline on Echidna results.

    Steps performed:
        1. Load raw Echidna results JSON
        2. Compute per-variant and overall metrics
        3. Print a summary table to the console / log
        4. Export metrics CSV, detail CSV, and summary JSON
        5. Generate all six visualization charts

    Args:
        echidna_results_json : Path to the Echidna results JSON
                               (default: logs/echidna_results.json).
        injection_log_json   : Path to the injection log JSON
                               (default: logs/injection_log.json).
        output_dir           : Directory where all output files are written.

    Returns:
        Dict mapping variant name → MetricResult.
    """
    if echidna_results_json is None:
        echidna_results_json = os.path.join(LOGS_DIR, "echidna_results.json")
    if injection_log_json is None:
        injection_log_json = os.path.join(LOGS_DIR, "injection_log.json")

    os.makedirs(output_dir, exist_ok=True)

    log.info("=" * 60)
    log.info("STEP 5: RESULTS ANALYSIS")
    log.info("=" * 60)

    echidna_results = load_echidna_results(echidna_results_json)
    if not echidna_results:
        log.error("No Echidna results available for analysis.")
        return {}

    log.info("Results loaded: %d entries", len(echidna_results))

    # Compute & display
    metrics = compute_metrics(echidna_results)
    print_metrics_table(metrics)

    # Export tabular data
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    export_metrics_csv(metrics,        os.path.join(output_dir, f"metrics_summary_{ts}.csv"))
    export_detail_csv(echidna_results, os.path.join(output_dir, f"results_detail_{ts}.csv"))
    export_summary_json(
        metrics, echidna_results, os.path.join(output_dir, f"summary_{ts}.json")
    )

    # Generate charts
    chart_paths = generate_charts(metrics, echidna_results, output_dir, ts)

    # Key insights log block
    overall = metrics.get("overall")
    if overall and overall.total_injected > 0:
        log.info("")
        log.info("KEY INSIGHTS:")
        log.info(
            "  Detection Rate  : %.2f%%  (%d / %d)",
            overall.detection_rate * 100, overall.total_detected, overall.total_injected,
        )
        log.info(
            "  Activation Rate : %.2f%%  (%d / %d)",
            overall.activation_rate * 100, overall.total_activated, overall.total_injected,
        )
        log.info(
            "  Reachable       : %d / %d",
            overall.total_reachable, overall.total_injected,
        )
        log.info(
            "  Avg Detect Time : %.2f seconds",
            overall.avg_detection_time,
        )

        if overall.not_detected_files:
            log.info("")
            log.info(
                "  Undetected bugs (%d contract(s)) [mostly Reachable]:",
                len(overall.not_detected_files),
            )
            for fname in overall.not_detected_files[:10]:
                log.info("    - %s", fname)
            if len(overall.not_detected_files) > 10:
                log.info("    ... and %d more", len(overall.not_detected_files) - 10)

    if chart_paths:
        log.info("")
        log.info("Charts saved to : %s", os.path.join(output_dir, f"charts_{ts}"))

    return metrics


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    echidna_json   = sys.argv[1] if len(sys.argv) > 1 else None
    injection_json = sys.argv[2] if len(sys.argv) > 2 else None
    metrics = run_analysis(echidna_json, injection_json)
    sys.exit(0 if metrics else 1)