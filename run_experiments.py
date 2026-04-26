"""
MULTI-EXPERIMENT ORCHESTRATOR
==============================
Runs the full reentrancy detection pipeline for each experiment
configuration defined in experiment_configs.py, then triggers
a comparative analysis across all results.

Steps 1–3 run once (shared) because their output is identical
across all experiments. Steps 4–5 run per-experiment since they
depend on each experiment's Echidna configuration.

Usage:
    python run_experiments.py                        # Run all experiments
    python run_experiments.py --exp exp1_light       # Run a single experiment
    python run_experiments.py --compare-only         # Skip fuzzing, compare existing results
    python run_experiments.py --from-step 4          # Resume all experiments from step N
    python run_experiments.py --verbose              # Enable DEBUG logging

Output structure:
    experiments/
    ├── _shared/
    │   ├── instrumented_contracts/   ← step 1 output (shared across all experiments)
    │   ├── injected_contracts/       ← step 3 output (shared across all experiments)
    │   └── logs/
    │       ├── shared_state.json
    │       └── injection_log.json
    ├── exp1_light/
    │   ├── echidna_results/
    │   ├── analysis_results/
    │   └── logs/
    ├── exp2_medium/   (same structure)
    ├── exp3_heavy/    (same structure)
    └── comparison/
        ├── comparison_report.json
        ├── comparison_metrics.csv
        └── charts_*/
            ├── cmp_chart1_detection_rate.png
            ├── cmp_chart2_activation_rate.png
            ├── cmp_chart3_ecdf_single_function.png
            ├── cmp_chart4_ecdf_cross_function.png
            └── cmp_chart5_avg_detection_time.png
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _PROJECT_ROOT)

from experiment_configs import EXPERIMENT_MAP, EXPERIMENTS
from logger import get_logger

log = get_logger("experiment_runner")

EXPERIMENTS_ROOT = os.path.join(_PROJECT_ROOT, "experiments")
SHARED_ROOT      = os.path.join(EXPERIMENTS_ROOT, "_shared")


# ---------------------------------------------------------------------------
# Directory helpers
# ---------------------------------------------------------------------------

def _shared_dirs() -> Dict[str, str]:
    """Directories for Steps 1–3 output shared across all experiments."""
    return {
        "instrumented": os.path.join(SHARED_ROOT, "instrumented_contracts"),
        "injected":     os.path.join(SHARED_ROOT, "injected_contracts"),
        "logs":         os.path.join(SHARED_ROOT, "logs"),
    }


def _exp_dirs(exp_name: str) -> Dict[str, str]:
    """Per-experiment output directories (Steps 4–5 only)."""
    root = os.path.join(EXPERIMENTS_ROOT, exp_name)
    return {
        "root":     root,
        "echidna":  os.path.join(root, "echidna_results"),
        "analysis": os.path.join(root, "analysis_results"),
        "logs":     os.path.join(root, "logs"),
    }


def _ensure_dirs(dirs: Dict[str, str]) -> None:
    for d in dirs.values():
        os.makedirs(d, exist_ok=True)


# ---------------------------------------------------------------------------
# Config patching
# ---------------------------------------------------------------------------

def _patch_config(exp_cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Temporarily overwrite the config module with the given experiment's values.
    Only ECHIDNA_CONFIG and ECHIDNA_TIMEOUT are modified — directory paths for
    Steps 4–5 are also updated here and restored after the experiment completes.

    Returns a snapshot of the original config values for restoration.
    """
    import config as cfg

    snapshot = {
        "ECHIDNA_CONFIG":       dict(cfg.ECHIDNA_CONFIG),
        "ECHIDNA_TIMEOUT":      cfg.ECHIDNA_TIMEOUT,
        "INSTRUMENTED_DIR":     cfg.INSTRUMENTED_DIR,
        "INJECTED_DIR":         cfg.INJECTED_DIR,
        "ECHIDNA_RESULTS_DIR":  cfg.ECHIDNA_RESULTS_DIR,
        "ANALYSIS_RESULTS_DIR": cfg.ANALYSIS_RESULTS_DIR,
        "LOGS_DIR":             cfg.LOGS_DIR,
    }

    dirs   = _exp_dirs(exp_cfg["name"])
    shared = _shared_dirs()

    cfg.ECHIDNA_CONFIG.update(exp_cfg["echidna_config"])
    cfg.ECHIDNA_TIMEOUT      = exp_cfg["echidna_timeout"]

    # Steps 1–3 use shared directories
    cfg.INSTRUMENTED_DIR     = shared["instrumented"]
    cfg.INJECTED_DIR         = shared["injected"]

    # Steps 4–5 use per-experiment directories
    cfg.ECHIDNA_RESULTS_DIR  = dirs["echidna"]
    cfg.ANALYSIS_RESULTS_DIR = dirs["analysis"]
    cfg.LOGS_DIR             = dirs["logs"]

    return snapshot


def _restore_config(snapshot: Dict[str, Any]) -> None:
    import config as cfg

    cfg.ECHIDNA_CONFIG.clear()
    cfg.ECHIDNA_CONFIG.update(snapshot["ECHIDNA_CONFIG"])
    cfg.ECHIDNA_TIMEOUT      = snapshot["ECHIDNA_TIMEOUT"]
    cfg.INSTRUMENTED_DIR     = snapshot["INSTRUMENTED_DIR"]
    cfg.INJECTED_DIR         = snapshot["INJECTED_DIR"]
    cfg.ECHIDNA_RESULTS_DIR  = snapshot["ECHIDNA_RESULTS_DIR"]
    cfg.ANALYSIS_RESULTS_DIR = snapshot["ANALYSIS_RESULTS_DIR"]
    cfg.LOGS_DIR             = snapshot["LOGS_DIR"]


# ---------------------------------------------------------------------------
# Phase 1 — Shared Preparation (Steps 1–3), runs once
# ---------------------------------------------------------------------------

def run_shared_preparation(from_step: int = 1) -> Optional[List[dict]]:
    """
    Execute Steps 1–3 once and store the results under experiments/_shared/.
    All experiments reuse this output because Steps 1–3 are independent of
    the Echidna configuration.

    Returns:
        The injection log (list of dicts) on success, or None on failure.
    """
    dirs = _shared_dirs()
    _ensure_dirs(dirs)

    log.info("")
    log.info("━" * 64)
    log.info("  SHARED PREPARATION — Steps 1–3")
    log.info("  (Runs once; output is reused by all experiments)")
    log.info("  Output : %s", SHARED_ROOT)
    log.info("━" * 64)

    import importlib
    import config as cfg
    import step1instrumentor, step2compiler, step3injector

    orig_instrumented = cfg.INSTRUMENTED_DIR
    orig_injected     = cfg.INJECTED_DIR
    orig_logs         = cfg.LOGS_DIR

    cfg.INSTRUMENTED_DIR = dirs["instrumented"]
    cfg.INJECTED_DIR     = dirs["injected"]
    cfg.LOGS_DIR         = dirs["logs"]

    for mod in (step1instrumentor, step2compiler, step3injector):
        importlib.reload(mod)

    try:
        from config import BASE_CONTRACTS_DIR, BUG_VARIANTS

        # ── Step 1: Instrumentation ──────────────────────────────────────
        if from_step <= 1:
            log.info("[Shared Step 1] Oracle Instrumentation")
            results = step1instrumentor.run_instrumentation(
                base_dir=BASE_CONTRACTS_DIR,
                output_dir=dirs["instrumented"],
            )
            if not any(results.values()):
                log.error("Shared Step 1 failed.")
                return None
        else:
            log.info("[Shared Step 1] Skipped")

        # ── Step 2: Compilation Verification ────────────────────────────
        state_path = os.path.join(dirs["logs"], "shared_state.json")

        if from_step <= 2:
            log.info("[Shared Step 2] Compilation Verification")
            compile_results = step2compiler.verify_instrumented_contracts(dirs["instrumented"])
            valid_files     = step2compiler.get_valid_contracts(compile_results)
            if not valid_files:
                log.error("Shared Step 2 failed: no contracts passed compilation.")
                return None
            with open(state_path, "w") as f:
                json.dump({"valid_files": valid_files}, f, indent=2)
        else:
            log.info("[Shared Step 2] Skipped")
            if os.path.isfile(state_path):
                with open(state_path) as f:
                    valid_files = json.load(f).get("valid_files", [])
            else:
                valid_files = [
                    fn for fn in os.listdir(dirs["instrumented"])
                    if fn.endswith(".sol")
                ]
            log.info("  %d valid files loaded from state", len(valid_files))

        # ── Step 3: Bug Injection ────────────────────────────────────────
        injection_log_path = os.path.join(dirs["logs"], "injection_log.json")

        if from_step <= 3:
            log.info("[Shared Step 3] Bug Injection")
            injection_logs = step3injector.run_injection(
                instrumented_dir=dirs["instrumented"],
                output_dir=dirs["injected"],
                valid_files=valid_files,
                variants=BUG_VARIANTS,
            )
            if not injection_logs:
                log.error("Shared Step 3 failed: no bugs were successfully injected.")
                return None
            with open(injection_log_path, "w") as f:
                json.dump(injection_logs, f, indent=2)
        else:
            log.info("[Shared Step 3] Skipped")
            if not os.path.isfile(injection_log_path):
                log.error(
                    "injection_log.json not found at %s. "
                    "Re-run without --from-step, or start from step <= 3.",
                    injection_log_path,
                )
                return None
            with open(injection_log_path) as f:
                injection_logs = json.load(f)
            log.info("  %d injection entries loaded from disk", len(injection_logs))

        log.info("✓ Shared preparation complete.")
        return injection_logs

    except Exception as exc:
        log.error("Shared preparation error: %s", exc, exc_info=True)
        return None

    finally:
        cfg.INSTRUMENTED_DIR = orig_instrumented
        cfg.INJECTED_DIR     = orig_injected
        cfg.LOGS_DIR         = orig_logs
        for mod in (step1instrumentor, step2compiler, step3injector):
            importlib.reload(mod)


# ---------------------------------------------------------------------------
# Phase 2 — Per-Experiment Runner (Steps 4–5 only)
# ---------------------------------------------------------------------------

def run_single_experiment(
    exp_name: str,
    injection_logs: List[dict],
    from_step: int = 4,
) -> bool:
    """
    Execute Steps 4–5 for one experiment.

    Steps 1–3 are already complete from run_shared_preparation(); their output
    lives under experiments/_shared/injected_contracts/.

    Args:
        exp_name       : Experiment name (key in EXPERIMENT_MAP).
        injection_logs : Injection log produced by shared preparation.
        from_step      : Starting step (minimum 4, since 1–3 are shared).

    Returns:
        True if the experiment completes without a critical error.
    """
    exp_cfg = EXPERIMENT_MAP.get(exp_name)
    if exp_cfg is None:
        log.error("Unknown experiment: '%s'. Available: %s",
                  exp_name, list(EXPERIMENT_MAP.keys()))
        return False

    dirs   = _exp_dirs(exp_name)
    shared = _shared_dirs()
    _ensure_dirs(dirs)

    log.info("")
    log.info("━" * 64)
    log.info("  EXPERIMENT : %s", exp_cfg["label"])
    log.info("  Config     : testLimit=%d  seqLen=%d  timeout=%ds",
             exp_cfg["echidna_config"]["testLimit"],
             exp_cfg["echidna_config"]["seqLen"],
             exp_cfg["echidna_config"]["timeout"])
    log.info("  Output dir : %s", dirs["root"])
    log.info("  Injected contracts from : %s", shared["injected"])
    log.info("━" * 64)

    snapshot = _patch_config(exp_cfg)

    try:
        import importlib
        import step4echidna, step5analyst
        for mod in (step4echidna, step5analyst):
            importlib.reload(mod)

        # ── Step 4: Echidna Fuzzing ──────────────────────────────────────
        echidna_results_path = os.path.join(dirs["logs"], "echidna_results.json")

        if from_step <= 4:
            log.info("[Step 4] Echidna Fuzzing (timeout=%ds per contract)",
                     exp_cfg["echidna_timeout"])
            echidna_results = step4echidna.run_echidna_all(
                injected_dir=shared["injected"],
                results_dir=dirs["echidna"],
                injection_log=injection_logs,
            )
            with open(echidna_results_path, "w") as f:
                json.dump([r.to_dict() for r in echidna_results], f, indent=2)
        else:
            log.info("[Step 4] Skipped")

        # ── Step 5: Analysis ─────────────────────────────────────────────
        if from_step <= 5:
            log.info("[Step 5] Results Analysis")
            step5analyst.run_analysis(
                echidna_results_json=echidna_results_path,
                injection_log_json=os.path.join(shared["logs"], "injection_log.json"),
                output_dir=dirs["analysis"],
            )

        state_path = os.path.join(dirs["logs"], "pipeline_state.json")
        with open(state_path, "w") as f:
            json.dump({
                "experiment":   exp_name,
                "completed_at": datetime.now().isoformat(),
            }, f, indent=2)

        log.info("✓ Experiment '%s' complete.", exp_name)
        return True

    except Exception as exc:
        log.error("Experiment '%s' error: %s", exp_name, exc, exc_info=True)
        return False

    finally:
        _restore_config(snapshot)


# ---------------------------------------------------------------------------
# Comparative analysis (Step 6)
# ---------------------------------------------------------------------------

def run_comparison(exp_names: Optional[List[str]] = None) -> None:
    if exp_names is None:
        exp_names = [e["name"] for e in EXPERIMENTS]

    comparison_dir = os.path.join(EXPERIMENTS_ROOT, "comparison")
    os.makedirs(comparison_dir, exist_ok=True)

    log.info("")
    log.info("━" * 64)
    log.info("  STEP 6 — COMPARATIVE ANALYSIS")
    log.info("  Comparing: %s", exp_names)
    log.info("━" * 64)

    all_exp_data: List[Dict[str, Any]] = []

    for exp_name in exp_names:
        exp_cfg = EXPERIMENT_MAP.get(exp_name)
        if exp_cfg is None:
            log.warning("Skipping unknown experiment: %s", exp_name)
            continue

        dirs                 = _exp_dirs(exp_name)
        echidna_results_path = os.path.join(dirs["logs"], "echidna_results.json")

        if not os.path.isfile(echidna_results_path):
            log.warning("Results not found for '%s' — skipping.", exp_name)
            continue

        with open(echidna_results_path) as f:
            echidna_results = json.load(f)

        import step5analyst
        metrics = step5analyst.compute_metrics(echidna_results)

        all_exp_data.append({
            "name":            exp_name,
            "label":           exp_cfg["label"],
            "description":     exp_cfg["description"],
            "echidna_config":  exp_cfg["echidna_config"],
            "echidna_timeout": exp_cfg["echidna_timeout"],
            "metrics":         {k: v.to_dict() for k, v in metrics.items()},
            "raw_results":     echidna_results,
        })
        log.info("  Loaded: %-20s  (%d results)", exp_name, len(echidna_results))

    if len(all_exp_data) < 2:
        log.error("At least 2 completed experiments are required for comparison. Found: %d",
                  len(all_exp_data))
        return

    # ── Export JSON ──────────────────────────────────────────────────────
    ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(comparison_dir, f"comparison_report_{ts}.json")
    with open(report_path, "w") as f:
        json.dump({"generated_at": datetime.now().isoformat(),
                   "experiments": all_exp_data}, f, indent=2, ensure_ascii=False)
    log.info("Comparison JSON : %s", report_path)

    # ── Export CSV ───────────────────────────────────────────────────────
    import csv
    csv_path   = os.path.join(comparison_dir, f"comparison_metrics_{ts}.csv")
    fieldnames = [
        "experiment", "label",
        "testLimit", "seqLen", "timeout_config", "timeout_process",
        "variant",
        "total_injected", "total_detected", "total_activated",
        "detection_rate_pct", "activation_rate_pct",
        "avg_detection_time_sec",
        "total_timeout", "total_error",
    ]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for exp in all_exp_data:
            for variant, m in exp["metrics"].items():
                if m.get("total_injected", 0) == 0:
                    continue
                writer.writerow({
                    "experiment":             exp["name"],
                    "label":                  exp["label"],
                    "testLimit":              exp["echidna_config"]["testLimit"],
                    "seqLen":                 exp["echidna_config"]["seqLen"],
                    "timeout_config":         exp["echidna_config"]["timeout"],
                    "timeout_process":        exp["echidna_timeout"],
                    "variant":                variant,
                    "total_injected":         m.get("total_injected", 0),
                    "total_detected":         m.get("total_detected", 0),
                    "total_activated":        m.get("total_activated", 0),
                    "detection_rate_pct":     m.get("detection_rate_pct", "0.00%"),
                    "activation_rate_pct":    m.get("activation_rate_pct", "0.00%"),
                    "avg_detection_time_sec": m.get("avg_detection_time_sec", -1),
                    "total_timeout":          m.get("total_timeout", 0),
                    "total_error":            m.get("total_error", 0),
                })
    log.info("Comparison CSV  : %s", csv_path)

    # ── Generate charts ──────────────────────────────────────────────────
    _generate_comparison_charts(all_exp_data, comparison_dir, ts)
    log.info("Comparison complete → %s", comparison_dir)


# ---------------------------------------------------------------------------
# Comparison chart generator — 5 charts
# ---------------------------------------------------------------------------

def _generate_comparison_charts(
    all_exp_data: List[Dict[str, Any]],
    output_dir: str,
    timestamp: str,
) -> None:
    """
    Generate five comparison charts:
        1. Detection Rate  — grouped bar chart (variant × experiment)
        2. Activation Rate — grouped bar chart (variant × experiment)
        3. ECDF single_function — one curve per experiment, single_function variant only
        4. ECDF cross_function  — one curve per experiment, cross_function variant only
        5. Average detection time — horizontal grouped bar (experiment × variant)

    Charts 3 and 4 each show one variant in isolation so experiments can be
    compared on the same axis without mixing variants.
    """
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    charts_dir = os.path.join(output_dir, f"charts_{timestamp}")
    os.makedirs(charts_dir, exist_ok=True)

    # ── Visual constants ─────────────────────────────────────────────────
    BG_FIG     = "#ffffff"
    BG_AXES    = "#ffffff"
    BG_LEGEND  = "#f5f5f5"
    GRID       = "#e0e0e0"
    SPINE      = "#888888"
    EXP_COLORS = ["#4C72B0", "#DD8452", "#55A868"]

    from config import BUG_VARIANTS as VARIANTS
    from config import ECHIDNA_TIMEOUT

    n_exp  = len(all_exp_data)
    labels = [e["label"] for e in all_exp_data]

    def _apply_dark(fig, axes):
        fig.patch.set_facecolor(BG_FIG)
        ax_list = axes if hasattr(axes, "__iter__") else [axes]
        for ax in ax_list:
            ax.set_facecolor(BG_AXES)
            ax.tick_params(colors="black")
            for sp in ax.spines.values():
                sp.set_color(SPINE)

    def _save(fig, name):
        path = os.path.join(charts_dir, name)
        plt.savefig(path, dpi=140, bbox_inches="tight", facecolor=fig.get_facecolor())
        plt.close(fig)
        log.info("  ✓ %s", name)

    x       = np.arange(len(VARIANTS))
    bar_w   = 0.22
    offsets = np.linspace(-(n_exp - 1) * bar_w / 2, (n_exp - 1) * bar_w / 2, n_exp)

    # ── Chart 1: Detection Rate ──────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(10, 5))
    _apply_dark(fig, ax)
    for i, (exp, color) in enumerate(zip(all_exp_data, EXP_COLORS)):
        vals = [
            exp["metrics"].get(v, {}).get("detection_rate", 0) * 100
            for v in VARIANTS
        ]
        bars = ax.bar(x + offsets[i], vals, bar_w, color=color, label=exp["label"], zorder=3)
        for b in bars:
            h = b.get_height()
            if h > 0:
                ax.text(
                    b.get_x() + b.get_width() / 2, h + 0.5,
                    f"{h:.0f}%", ha="center", va="bottom", fontsize=7.5, color="black",
                )
    ax.set_xticks(x)
    ax.set_xticklabels([v.replace("_", " ").title() for v in VARIANTS], color="black")
    ax.set_ylabel("Detection Rate (%)", color="black")
    ax.set_title("Detection Rate by Variant & Experiment", color="black", fontsize=13, pad=12)
    ax.yaxis.grid(True, color=GRID, linestyle="--", linewidth=0.6, zorder=0)
    ax.set_ylim(0, 115)
    ax.legend(facecolor=BG_LEGEND, labelcolor="black", fontsize=9)
    plt.tight_layout()
    _save(fig, "cmp_chart1_detection_rate.png")

    # ── Chart 2: Activation Rate ─────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(10, 5))
    _apply_dark(fig, ax)
    for i, (exp, color) in enumerate(zip(all_exp_data, EXP_COLORS)):
        vals = [
            exp["metrics"].get(v, {}).get("activation_rate", 0) * 100
            for v in VARIANTS
        ]
        bars = ax.bar(x + offsets[i], vals, bar_w, color=color, label=exp["label"], zorder=3)
        for b in bars:
            h = b.get_height()
            if h > 0:
                ax.text(
                    b.get_x() + b.get_width() / 2, h + 0.5,
                    f"{h:.0f}%", ha="center", va="bottom", fontsize=7.5, color="black",
                )
    ax.set_xticks(x)
    ax.set_xticklabels([v.replace("_", " ").title() for v in VARIANTS], color="black")
    ax.set_ylabel("Activation Rate (%)", color="black")
    ax.set_title("Activation Rate by Variant & Experiment", color="black", fontsize=13, pad=12)
    ax.yaxis.grid(True, color=GRID, linestyle="--", linewidth=0.6, zorder=0)
    ax.set_ylim(0, 115)
    ax.legend(facecolor=BG_LEGEND, labelcolor="black", fontsize=9)
    plt.tight_layout()
    _save(fig, "cmp_chart2_activation_rate.png")

    # ── Charts 3 & 4: ECDF per variant ──────────────────────────────────
    #
    # x-axis : Echidna fuzzing time per contract (seconds)
    # y-axis : cumulative % of injected bugs detected by time T
    #
    # One chart per variant so experiments can be overlaid on the same axes.
    # This differs from the per-experiment ECDF in step5, which combines
    # both variants into a single curve.

    for variant_idx, variant in enumerate(VARIANTS):
        variant_label = variant.replace("_", " ").title()
        chart_num     = variant_idx + 3   # chart 3 = single_function, chart 4 = cross_function

        fig, ax = plt.subplots(figsize=(11, 5))
        _apply_dark(fig, ax)

        for i, (exp, color) in enumerate(zip(all_exp_data, EXP_COLORS)):
            raw_results = exp["raw_results"]

            det_times = sorted([
                r["detection_time_sec"]
                for r in raw_results
                if r.get("variant") == variant
                and r.get("property_broken")
                and r.get("detection_time_sec", -1) > 0
            ])

            total_injected = exp["metrics"].get(variant, {}).get("total_injected", 1) or 1

            # Build ECDF step function: start at (0, 0), step up on each detection
            ecdf_x = [0.0]
            ecdf_y = [0.0]
            for j, t in enumerate(det_times):
                ecdf_x.append(t)
                ecdf_y.append((j + 1) / total_injected * 100)
            # Extend to timeout so the curve spans the full x range
            ecdf_x.append(float(ECHIDNA_TIMEOUT))
            ecdf_y.append(len(det_times) / total_injected * 100)

            final_pct = len(det_times) / total_injected * 100
            ax.step(
                ecdf_x, ecdf_y,
                where="post",
                color=color,
                linewidth=1.8,
                label=f"{exp['label']}  ({final_pct:.0f}% detected)",
                alpha=0.9,
                zorder=3,
            )

        ax.axvline(
            x=ECHIDNA_TIMEOUT, color="#e74c3c",
            linewidth=1.0, linestyle=":", alpha=0.7,
            label=f"Timeout ({ECHIDNA_TIMEOUT}s)",
        )
        ax.set_xlabel("Time (seconds)", color="black", fontsize=10)
        ax.set_ylabel("Cumulative bugs detected (%)", color="black", fontsize=10)
        ax.set_title(
            f"ECDF — Cumulative Detection Rate over Time\n"
            f"Variant: {variant_label}",
            color="black", fontsize=12, pad=12,
        )
        ax.set_xlim(0, ECHIDNA_TIMEOUT + 5)
        ax.set_ylim(0, 108)
        ax.yaxis.grid(True, color=GRID, linestyle="--", linewidth=0.5, zorder=0)
        ax.xaxis.grid(True, color=GRID, linestyle="--", linewidth=0.5, zorder=0)
        ax.legend(facecolor=BG_LEGEND, labelcolor="black", fontsize=9, loc="lower right")
        plt.tight_layout()
        _save(fig, f"cmp_chart{chart_num}_ecdf_{variant}.png")

    # ── Chart 5: Average detection time — horizontal grouped bar ─────────
    #
    # One group of bars per experiment; one bar per variant within each group.
    # Shorter bars indicate faster detection.

    n_variants  = len(VARIANTS)
    bar_h       = 0.25
    y_base      = np.arange(n_exp)
    var_offsets = np.linspace(
        -(n_variants - 1) * bar_h / 2,
         (n_variants - 1) * bar_h / 2,
        n_variants,
    )
    VARIANT_COLORS = ["#a8c4e0", "#f5c08a"]

    fig, ax = plt.subplots(figsize=(10, max(4, n_exp * 1.6)))
    _apply_dark(fig, ax)

    for vi, (variant, vcolor) in enumerate(zip(VARIANTS, VARIANT_COLORS)):
        avg_times = []
        for exp in all_exp_data:
            t = exp["metrics"].get(variant, {}).get("avg_detection_time_sec", -1)
            avg_times.append(max(t, 0))   # display 0 instead of -1 when no detection occurred

        y_positions = y_base + var_offsets[vi]
        bars = ax.barh(
            y_positions, avg_times,
            height=bar_h,
            color=vcolor,
            label=variant.replace("_", " ").title(),
            zorder=3,
            edgecolor=SPINE,
            linewidth=0.5,
        )
        for bar, val in zip(bars, avg_times):
            if val > 0:
                ax.text(
                    val + ECHIDNA_TIMEOUT * 0.01,
                    bar.get_y() + bar.get_height() / 2,
                    f"{val:.1f}s",
                    va="center", ha="left", fontsize=8, color="black",
                )

    ax.set_yticks(y_base)
    ax.set_yticklabels(labels, color="black", fontsize=10)
    ax.set_xlabel("Average detection time (s)", color="black", fontsize=10)
    ax.set_xlim(0, ECHIDNA_TIMEOUT * 1.15)
    ax.set_title(
        "Average Detection Time per Experiment & Variant\n"
        "(lower = faster detection)",
        color="black", fontsize=12, pad=12,
    )
    ax.xaxis.grid(True, color=GRID, linestyle="--", linewidth=0.5, zorder=0)
    ax.axvline(
        x=ECHIDNA_TIMEOUT, color="#e74c3c",
        linewidth=1.0, linestyle=":", alpha=0.7,
        label=f"Timeout ({ECHIDNA_TIMEOUT}s)",
    )
    ax.legend(facecolor=BG_LEGEND, labelcolor="black", fontsize=9, loc="lower right")
    plt.tight_layout()
    _save(fig, "cmp_chart5_avg_detection_time.png")

    log.info("All comparison charts saved → %s", charts_dir)


# ---------------------------------------------------------------------------
# Prerequisite check
# ---------------------------------------------------------------------------

def _check_prereqs() -> bool:
    import subprocess
    import config as cfg

    issues = []
    if not os.path.isdir(cfg.BASE_CONTRACTS_DIR):
        issues.append(f"Contracts directory not found: {cfg.BASE_CONTRACTS_DIR}")
    try:
        subprocess.run(["solc", "--version"], capture_output=True, timeout=5)
    except FileNotFoundError:
        issues.append("solc not found.")

    if issues:
        for issue in issues:
            log.error("  ✗ %s", issue)
        return False
    return True


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

_BANNER = """
╔══════════════════════════════════════════════════════════════════╗
║     MULTI-EXPERIMENT ORCHESTRATOR                                ║
║     Dynamic Reentrancy Bug Injection — Comparative Evaluation    ║
╚══════════════════════════════════════════════════════════════════╝
"""


def main() -> None:
    print(_BANNER)

    parser = argparse.ArgumentParser(
        description="Run multiple Echidna fuzzing experiments and compare results.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_experiments.py                         # Run all experiments
  python run_experiments.py --exp exp1_light        # Run one experiment only
  python run_experiments.py --compare-only          # Compare existing results
  python run_experiments.py --from-step 4           # Resume all experiments from step 4
  python run_experiments.py --list                  # List available experiments
        """,
    )
    parser.add_argument("--exp",          type=str,  help="Run a single named experiment")
    parser.add_argument("--from-step",    type=int,  default=1, choices=range(1, 6), metavar="N",
                        help="Start from step N (1–5)")
    parser.add_argument("--compare-only", action="store_true",
                        help="Skip experiment runs; generate comparison charts only")
    parser.add_argument("--list",         action="store_true",
                        help="List available experiments and exit")
    parser.add_argument("--verbose",      action="store_true", help="Enable DEBUG logging")
    args = parser.parse_args()

    if args.verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)

    if args.list:
        log.info("Available experiments:")
        for exp in EXPERIMENTS:
            log.info("  %-20s  %s", exp["name"], exp["description"])
        sys.exit(0)

    start_total = time.time()
    log.info("Start time : %s", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    if args.compare_only:
        run_comparison()
        sys.exit(0)

    if not _check_prereqs():
        log.error("Prerequisites not met. Aborting.")
        sys.exit(1)

    exps_to_run = [args.exp] if args.exp else [e["name"] for e in EXPERIMENTS]
    log.info("Experiments to run: %s", exps_to_run)

    # ── Phase 1: Shared Preparation (Steps 1–3) — runs once ──────────────
    injection_logs = run_shared_preparation(from_step=args.from_step)
    if injection_logs is None:
        log.error("Shared preparation failed. Aborting.")
        sys.exit(1)

    # ── Phase 2: Per-Experiment Fuzzing (Steps 4–5) ───────────────────────
    exp_from_step = max(args.from_step, 4)

    results_summary: Dict[str, bool] = {}
    for exp_name in exps_to_run:
        t0 = time.time()
        ok = run_single_experiment(
            exp_name,
            injection_logs=injection_logs,
            from_step=exp_from_step,
        )
        elapsed = time.time() - t0
        results_summary[exp_name] = ok
        log.info("  %-20s  %s  (%.0fs)",
                 exp_name, "✓ OK" if ok else "✗ FAILED", elapsed)

    # ── Comparative Analysis ──────────────────────────────────────────────
    completed = [name for name, ok in results_summary.items() if ok]
    if len(completed) >= 2:
        run_comparison(completed)
    elif len(completed) == 1:
        log.warning("Only 1 experiment completed — comparison requires at least 2.")
    else:
        log.error("No experiments completed successfully.")

    # ── Final Summary ─────────────────────────────────────────────────────
    total_elapsed = time.time() - start_total
    log.info("")
    log.info("╔══════════════════════════════════════════════════════════╗")
    log.info("║  EXPERIMENTS COMPLETE                                    ║")
    log.info("╠══════════════════════════════════════════════════════════╣")
    log.info("║  Total time : %-42s║",
             f"{total_elapsed:.0f}s  ({total_elapsed / 60:.1f} min)")
    for name, ok in results_summary.items():
        log.info("║  %s %-54s║", "✓" if ok else "✗", name)
    log.info("║  Shared     : %-42s║", "experiments/_shared/")
    log.info("║  Output     : %-42s║", "experiments/")
    log.info("║  Comparison : %-42s║", "experiments/comparison/")
    log.info("╚══════════════════════════════════════════════════════════╝")

    sys.exit(0 if all(results_summary.values()) else 1)


if __name__ == "__main__":
    main()