"""
STEP 5 — RESULTS ANALYSIS
===========================
Analyzes Echidna test results and computes evaluation metrics:

    1. Detection Rate     : bugs detected / total bugs injected
    2. Activation Rate    : bug lines reached by fuzzer / total bugs injected
    3. Avg Detection Time : mean detection time per bug variant (seconds)

Visualization output (PNG, dark theme):
    chart1_rate_comparison.png     — Detection & Activation Rate grouped horizontal bar
    chart2_detection_time_dist.png — Detection time violin + strip plot
    chart3_ecdf_detection_time.png — ECDF cumulative detection over time
                                     (both variants combined into one curve)
"""

import csv
import json
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
# Visual constants
# ---------------------------------------------------------------------------

_BG_FIGURE   = "#ffffff"    # Outermost figure background
_BG_AXES     = "#ffffff"    # Individual axes background
_BG_LEGEND   = "#f5f5f5"    # Legend background
_GRID_COLOR  = "#e0e0e0"    # Major grid lines
_SPINE_COLOR = "#888888"    # Axis spine color
_TEXT_COLOR  = "#111111"

_VARIANT_COLORS = {
    "single_function": "#4C72B0",
    "cross_function":  "#DD8452",
}

# Variants to include in per-variant charts (excludes the "overall" aggregate)
_PER_VARIANT = list(BUG_VARIANTS)


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
        self.detection_times:    List[float] = []
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
        Average Detection Time (Chapter 2.5.3).
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
        Indicates compiler-level protection (e.g. Solidity 0.8+ underflow revert).
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

        # Detection rate counters
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

        # Activation rate counters
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
    fig.patch.set_facecolor(_BG_FIGURE)
    axes = ax_or_axes if isinstance(ax_or_axes, (list, np.ndarray)) else [ax_or_axes]
    for ax in np.ravel(axes):
        ax.set_facecolor(_BG_AXES)
        ax.tick_params(colors=_TEXT_COLOR)
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
            f"{w:.1f}%", va="center", ha="left", fontsize=8.5, color=_TEXT_COLOR,
        )

    ax.set_yticks(y)
    ax.set_yticklabels(
        [v.replace("_", " ").title() for v in _PER_VARIANT], color=_TEXT_COLOR, fontsize=10
    )
    ax.set_xlabel("Rate (%)", color=_TEXT_COLOR, fontsize=10)
    ax.set_xlim(0, 118)
    ax.set_title("Detection & Activation Rate by Variant", color=_TEXT_COLOR, fontsize=13, pad=12)
    ax.xaxis.grid(True, color=_GRID_COLOR, linestyle="--", linewidth=0.6, zorder=0)
    ax.legend(facecolor=_BG_LEGEND, labelcolor=_TEXT_COLOR, fontsize=9, loc="lower right")

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
    Skipped when fewer than 3 detected results with timing data are available.
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
    for body, lbl in zip(parts["bodies"], labels):
        body.set_facecolor(_VARIANT_COLORS.get(lbl, "#888888"))
        body.set_alpha(0.5)
    parts["cmedians"].set_color(_TEXT_COLOR)
    for key in ("cbars", "cmaxes", "cmins"):
        parts[key].set_color("#888888")

    rng = np.random.default_rng(42)
    for i, (lbl, vals) in enumerate(zip(labels, groups)):
        jitter = rng.uniform(-0.08, 0.08, size=len(vals))
        ax.scatter(
            i + jitter, vals,
            color=_VARIANT_COLORS.get(lbl, "#888888"),
            edgecolors="black", linewidths=0.4, s=32, zorder=3, alpha=0.85,
        )

    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels([l.replace("_", " ").title() for l in labels], color=_TEXT_COLOR, fontsize=10)
    ax.set_ylabel("Detection Time (s)", color=_TEXT_COLOR, fontsize=10)
    ax.set_title("Detection Time Distribution by Variant", color=_TEXT_COLOR, fontsize=13, pad=12)
    ax.yaxis.grid(True, color=_GRID_COLOR, linestyle="--", linewidth=0.6)

    plt.tight_layout()
    path = os.path.join(output_dir, "chart2_detection_time_dist.png")
    _save(fig, path)
    return path


# ---------------------------------------------------------------------------
# Chart 3 — ECDF of detection time (both variants combined)
# ---------------------------------------------------------------------------

def _chart_ecdf_combined(
    echidna_results: list,
    metrics: Dict[str, MetricResult],
    output_dir: str,
) -> str:
    """
    ECDF (Empirical Cumulative Distribution Function) for detection time.

    Both variants (single_function and cross_function) are combined into a
    single curve representing the overall detection performance of this run.

    x-axis : elapsed time in seconds, from 0 to ECHIDNA_TIMEOUT
    y-axis : cumulative percentage of injected bugs detected by time T
    """
    fig, ax = plt.subplots(figsize=(10, 5))
    _apply_dark_theme(fig, ax)

    # Collect detection times from both variants
    all_det_times = sorted([
        r["detection_time_sec"]
        for r in echidna_results
        if r.get("property_broken") and r.get("detection_time_sec", -1) > 0
    ])

    total_injected = sum(
        metrics[v].total_injected
        for v in _PER_VARIANT
        if v in metrics
    ) or 1

    # Build ECDF step function: start at (0, 0), step up on each detection
    ecdf_x = [0.0]
    ecdf_y = [0.0]
    for j, t in enumerate(all_det_times):
        ecdf_x.append(t)
        ecdf_y.append((j + 1) / total_injected * 100)
    # Extend to timeout so the curve spans the full x range
    ecdf_x.append(float(ECHIDNA_TIMEOUT))
    ecdf_y.append(len(all_det_times) / total_injected * 100)

    ax.step(
        ecdf_x, ecdf_y,
        where="post",
        color="#55A868",
        linewidth=2.2,
        label=f"All Variants Combined  ({len(all_det_times)} detected)",
        alpha=0.95,
        zorder=3,
    )

    # Overlay individual detection points
    if all_det_times:
        y_pts = [(j + 1) / total_injected * 100 for j in range(len(all_det_times))]
        ax.scatter(
            all_det_times, y_pts,
            color="#55A868", edgecolors="white", linewidths=0.5,
            s=35, zorder=4, alpha=0.85,
        )

    ax.axvline(
        x=ECHIDNA_TIMEOUT, color="#e74c3c",
        linewidth=1.2, linestyle=":", alpha=0.75,
        label=f"Timeout ({ECHIDNA_TIMEOUT}s)",
    )

    final_pct = len(all_det_times) / total_injected * 100
    ax.annotate(
        f"  {final_pct:.1f}% detected",
        xy=(ECHIDNA_TIMEOUT, final_pct),
        xytext=(ECHIDNA_TIMEOUT * 0.75, final_pct + 5),
        color="white", fontsize=9,
        arrowprops=dict(arrowstyle="->", color=_TEXT_COLOR, lw=0.8),
    )

    ax.set_xlabel("Time (seconds)", color=_TEXT_COLOR, fontsize=10)
    ax.set_ylabel("Cumulative bugs detected (%)", color=_TEXT_COLOR, fontsize=10)
    ax.set_title(
        "ECDF — Cumulative Detection Rate over Time\n"
        "(single_function + cross_function combined)",
        color=_TEXT_COLOR, fontsize=12, pad=12,
    )
    ax.set_xlim(0, ECHIDNA_TIMEOUT + 5)
    ax.set_ylim(0, 108)
    ax.yaxis.grid(True, color=_GRID_COLOR, linestyle="--", linewidth=0.5, zorder=0)
    ax.xaxis.grid(True, color=_GRID_COLOR, linestyle="--", linewidth=0.5, zorder=0)
    ax.legend(facecolor=_BG_LEGEND, labelcolor=_TEXT_COLOR, fontsize=9, loc="lower right")

    plt.tight_layout()
    path = os.path.join(output_dir, "chart3_ecdf_detection_time.png")
    _save(fig, path)
    return path


# ---------------------------------------------------------------------------
# Chart runner
# ---------------------------------------------------------------------------

def generate_charts(
    metrics: Dict[str, MetricResult],
    echidna_results: list,
    output_dir: str,
    timestamp: str,
) -> List[str]:
    """
    Render all 3 charts and save them to a timestamped subdirectory of *output_dir*.

    Charts:
        1. Detection & Activation Rate (grouped horizontal bar)
        2. Detection Time Distribution (violin + strip)
        3. ECDF — cumulative detection time (both variants combined)

    Returns:
        List of file paths for each chart that was successfully created.
    """
    charts_dir = os.path.join(output_dir, f"charts_{timestamp}")
    os.makedirs(charts_dir, exist_ok=True)

    log.info("")
    log.info("Generating charts → %s", charts_dir)

    chart_fns = [
        ("Rate comparison (grouped bar)",
         lambda: _chart_rate_comparison(metrics, charts_dir)),
        ("Detection time distribution (violin + strip)",
         lambda: _chart_detection_time_dist(echidna_results, charts_dir)),
        ("ECDF cumulative detection time (combined variants)",
         lambda: _chart_ecdf_combined(echidna_results, metrics, charts_dir)),
    ]

    saved: List[str] = []
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
        3. Print a summary table to the log
        4. Export metrics CSV, detail CSV, and summary JSON
        5. Generate 3 visualization charts

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

    metrics = compute_metrics(echidna_results)
    print_metrics_table(metrics)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    export_metrics_csv(metrics,        os.path.join(output_dir, f"metrics_summary_{ts}.csv"))
    export_detail_csv(echidna_results, os.path.join(output_dir, f"results_detail_{ts}.csv"))
    export_summary_json(
        metrics, echidna_results, os.path.join(output_dir, f"summary_{ts}.json")
    )

    chart_paths = generate_charts(metrics, echidna_results, output_dir, ts)

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
                "  Undetected bugs (%d contract(s)):",
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