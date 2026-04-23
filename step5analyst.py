"""
STEP 5 — RESULTS ANALYSIS
===========================
Analyzes Echidna test results and computes evaluation metrics:

    1. Detection Rate     : bugs detected / total bugs injected
    2. Activation Rate    : bug lines reached by fuzzer / total bugs injected
    3. Avg Detection Time : mean detection time per bug variant (seconds)
"""

import csv
import json
import os
from datetime import datetime
from typing import Dict, List, Optional

from config import ANALYSIS_RESULTS_DIR, BUG_VARIANTS, ECHIDNA_TIMEOUT, LOGS_DIR
from logger import get_logger

log = get_logger("analyzer")


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

    # --- Derived properties ---

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
    def total_neutralized(self) -> int:
        """
        Neutralized = bugs that were activated but did NOT break the property.
        Demonstrates compiler-level protection (e.g. Solidity 0.8+ underflow revert).
        """
        return self.total_activated - self.total_detected

    def to_dict(self) -> dict:
        return {
            "variant":                self.variant,
            "total_injected":         self.total_injected,
            "total_detected":         self.total_detected,
            "total_neutralized":      self.total_neutralized,
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
# Display
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
        "Variant", "Total", "Detected", "Neutralized", "DR%", "Activated", "AR%", "Avg Time(s)",
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
            mr.total_neutralized,
            mr.detection_rate * 100,
            mr.total_activated,
            mr.activation_rate * 100,
            mr.avg_detection_time,
        )

    log.info(sep)


# ---------------------------------------------------------------------------
# Export functions
# ---------------------------------------------------------------------------

def export_metrics_csv(metrics: Dict[str, MetricResult], output_path: str) -> None:
    """Export the metrics summary to a CSV file."""
    fieldnames = [
        "variant", "total_injected", "total_detected", "total_neutralized",
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

    Args:
        echidna_results_json : Path to the Echidna results JSON
                               (default: logs/echidna_results.json).
        injection_log_json   : Path to the injection log JSON
                               (default: logs/injection_log.json).
        output_dir           : Directory where output files will be written.

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

    overall = metrics.get("overall")
    if overall and overall.total_injected > 0:
        log.info("")
        log.info("KEY INSIGHTS:")
        log.info(
            "  Detection Rate  : %.2f%%  (%d / %d)",
            overall.detection_rate * 100,
            overall.total_detected,
            overall.total_injected,
        )
        log.info(
            "  Activation Rate : %.2f%%  (%d / %d)",
            overall.activation_rate * 100,
            overall.total_activated,
            overall.total_injected,
        )
        log.info(
            "  Neutralized     : %d / %d",
            overall.total_neutralized,
            overall.total_injected,
        )
        log.info(
            "  Avg Detect Time : %.2f seconds",
            overall.avg_detection_time,
        )

        if overall.not_detected_files:
            log.info("")
            log.info(
                "  Undetected bugs (%d contract(s)) [mostly Neutralized]:",
                len(overall.not_detected_files),
            )
            for fname in overall.not_detected_files[:10]:
                log.info("    - %s", fname)
            if len(overall.not_detected_files) > 10:
                log.info("    ... and %d more", len(overall.not_detected_files) - 10)

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