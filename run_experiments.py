"""
MULTI-EXPERIMENT ORCHESTRATOR
==============================
Runs the full reentrancy detection pipeline for each experiment
configuration defined in experiment_configs.py, then triggers
a comparative analysis across all results.

Step 1–3 dijalankan SEKALI (shared), karena hasilnya identik
di semua experiment. Step 4–5 dijalankan per-experiment karena
bergantung pada Echidna config yang berbeda-beda.

Usage:
    python run_experiments.py                        # Run all 3 experiments
    python run_experiments.py --exp exp1_light       # Run a single experiment
    python run_experiments.py --compare-only         # Skip fuzzing, compare existing results
    python run_experiments.py --from-step 4          # Resume all experiments from step N
    python run_experiments.py --verbose              # Enable DEBUG logging

Output structure:
    experiments/
    ├── _shared/
    │   ├── instrumented_contracts/   ← hasil step 1 (dipakai semua exp)
    │   ├── injected_contracts/       ← hasil step 3 (dipakai semua exp)
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
    """Direktori untuk hasil Step 1–3 yang dipakai bersama semua experiment."""
    return {
        "instrumented": os.path.join(SHARED_ROOT, "instrumented_contracts"),
        "injected":     os.path.join(SHARED_ROOT, "injected_contracts"),
        "logs":         os.path.join(SHARED_ROOT, "logs"),
    }


def _exp_dirs(exp_name: str) -> Dict[str, str]:
    """Direktori output khusus per-experiment (hanya step 4–5)."""
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
    Monkey-patch config module dengan nilai experiment tertentu.
    Hanya mengubah ECHIDNA_CONFIG dan ECHIDNA_TIMEOUT — path direktori
    step 4–5 diatur langsung saat memanggil fungsi step.
    """
    import config as cfg

    snapshot = {
        "ECHIDNA_CONFIG":     dict(cfg.ECHIDNA_CONFIG),
        "ECHIDNA_TIMEOUT":    cfg.ECHIDNA_TIMEOUT,
        "INSTRUMENTED_DIR":   cfg.INSTRUMENTED_DIR,
        "INJECTED_DIR":       cfg.INJECTED_DIR,
        "ECHIDNA_RESULTS_DIR": cfg.ECHIDNA_RESULTS_DIR,
        "ANALYSIS_RESULTS_DIR": cfg.ANALYSIS_RESULTS_DIR,
        "LOGS_DIR":           cfg.LOGS_DIR,
    }

    dirs   = _exp_dirs(exp_cfg["name"])
    shared = _shared_dirs()

    cfg.ECHIDNA_CONFIG.update(exp_cfg["echidna_config"])
    cfg.ECHIDNA_TIMEOUT      = exp_cfg["echidna_timeout"]

    # Step 1–3 pakai shared dirs
    cfg.INSTRUMENTED_DIR     = shared["instrumented"]
    cfg.INJECTED_DIR         = shared["injected"]

    # Step 4–5 pakai per-experiment dirs
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
# FASE 1 — Shared Preparation (Step 1–3), dijalankan SEKALI
# ---------------------------------------------------------------------------

def run_shared_preparation(from_step: int = 1) -> Optional[List[dict]]:
    """
    Jalankan Step 1–3 sekali dan simpan hasilnya di experiments/_shared/.
    Semua experiment akan memakai hasil yang sama, karena Step 1–3
    tidak bergantung pada Echidna config sama sekali.

    Returns:
        injection_logs (list) jika berhasil, None jika gagal.
    """
    dirs = _shared_dirs()
    _ensure_dirs(dirs)

    log.info("")
    log.info("━" * 64)
    log.info("  SHARED PREPARATION — Step 1–3")
    log.info("  (Dijalankan sekali, dipakai semua experiment)")
    log.info("  Output : %s", SHARED_ROOT)
    log.info("━" * 64)

    import importlib
    import config as cfg
    import step1instrumentor, step2compiler, step3injector

    # Patch hanya path direktori yang relevan untuk step 1–3
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
                log.error("Shared Step 1 gagal.")
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
                log.error("Shared Step 2 gagal: tidak ada contract yang valid.")
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
            log.info("  %d valid files dimuat dari state", len(valid_files))

        # ── Step 3: Bug Injection ────────────────────────────────────────
        inj_log_path = os.path.join(dirs["logs"], "injection_log.json")

        if from_step <= 3:
            log.info("[Shared Step 3] Bug Injection")
            injection_logs = step3injector.run_injection(
                instrumented_dir=dirs["instrumented"],
                output_dir=dirs["injected"],
                valid_files=valid_files,
                variants=BUG_VARIANTS,
            )
            if not injection_logs:
                log.error("Shared Step 3 gagal: tidak ada bug yang berhasil diinjeksi.")
                return None
            with open(inj_log_path, "w") as f:
                json.dump(injection_logs, f, indent=2)
        else:
            log.info("[Shared Step 3] Skipped")
            if not os.path.isfile(inj_log_path):
                log.error(
                    "injection_log.json tidak ditemukan di %s. "
                    "Jalankan ulang tanpa --from-step, atau dari step <= 3.",
                    inj_log_path,
                )
                return None
            with open(inj_log_path) as f:
                injection_logs = json.load(f)
            log.info("  %d injection entries dimuat dari disk", len(injection_logs))

        log.info("✓ Shared preparation selesai.")
        return injection_logs

    except Exception as exc:
        log.error("Shared preparation error: %s", exc, exc_info=True)
        return None

    finally:
        # Kembalikan config seperti semula
        cfg.INSTRUMENTED_DIR = orig_instrumented
        cfg.INJECTED_DIR     = orig_injected
        cfg.LOGS_DIR         = orig_logs
        for mod in (step1instrumentor, step2compiler, step3injector):
            importlib.reload(mod)


# ---------------------------------------------------------------------------
# FASE 2 — Per-Experiment Runner (Step 4–5 saja)
# ---------------------------------------------------------------------------

def run_single_experiment(
    exp_name: str,
    injection_logs: List[dict],
    from_step: int = 4,
) -> bool:
    """
    Jalankan Step 4–5 untuk satu experiment.

    Step 1–3 sudah selesai di run_shared_preparation() dan hasilnya
    ada di experiments/_shared/injected_contracts/.

    Args:
        exp_name       : Nama experiment (key di EXPERIMENT_MAP).
        injection_logs : Hasil injection dari shared preparation.
        from_step      : Step awal (minimal 4, karena 1–3 sudah shared).

    Returns:
        True jika experiment selesai tanpa error kritis.
    """
    exp_cfg = EXPERIMENT_MAP.get(exp_name)
    if exp_cfg is None:
        log.error("Unknown experiment: '%s'. Available: %s",
                  exp_name, list(EXPERIMENT_MAP.keys()))
        return False

    dirs = _exp_dirs(exp_name)
    _ensure_dirs(dirs)

    shared = _shared_dirs()

    log.info("")
    log.info("━" * 64)
    log.info("  EXPERIMENT : %s", exp_cfg["label"])
    log.info("  Config     : testLimit=%d  seqLen=%d  timeout=%ds",
             exp_cfg["echidna_config"]["testLimit"],
             exp_cfg["echidna_config"]["seqLen"],
             exp_cfg["echidna_config"]["timeout"])
    log.info("  Output dir : %s", dirs["root"])
    log.info("  Injected contracts dari : %s", shared["injected"])
    log.info("━" * 64)

    snapshot = _patch_config(exp_cfg)

    try:
        import importlib
        import step4echidna, step5analyst
        for mod in (step4echidna, step5analyst):
            importlib.reload(mod)

        # ── Step 4: Echidna Fuzzing ──────────────────────────────────────
        er_path = os.path.join(dirs["logs"], "echidna_results.json")

        if from_step <= 4:
            log.info("[Step 4] Echidna Fuzzing (timeout=%ds per contract)",
                     exp_cfg["echidna_timeout"])
            echidna_results = step4echidna.run_echidna_all(
                injected_dir=shared["injected"],   # ← pakai shared injected dir
                results_dir=dirs["echidna"],
                injection_log=injection_logs,
            )
            with open(er_path, "w") as f:
                json.dump([r.to_dict() for r in echidna_results], f, indent=2)
        else:
            log.info("[Step 4] Skipped")

        # ── Step 5: Analysis ─────────────────────────────────────────────
        if from_step <= 5:
            log.info("[Step 5] Results Analysis")
            step5analyst.run_analysis(
                echidna_results_json=er_path,
                injection_log_json=os.path.join(shared["logs"], "injection_log.json"),
                output_dir=dirs["analysis"],
            )

        # Simpan state experiment
        state_path = os.path.join(dirs["logs"], "pipeline_state.json")
        with open(state_path, "w") as f:
            json.dump({
                "experiment":   exp_name,
                "completed_at": datetime.now().isoformat(),
            }, f, indent=2)

        log.info("✓ Experiment '%s' selesai.", exp_name)
        return True

    except Exception as exc:
        log.error("Experiment '%s' error: %s", exp_name, exc, exc_info=True)
        return False

    finally:
        _restore_config(snapshot)


# ---------------------------------------------------------------------------
# Comparative analysis (Step 6) — tidak berubah
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

        dirs    = _exp_dirs(exp_name)
        er_path = os.path.join(dirs["logs"], "echidna_results.json")

        if not os.path.isfile(er_path):
            log.warning("Results tidak ditemukan untuk '%s' — skipping.", exp_name)
            continue

        with open(er_path) as f:
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
        log.error("Butuh minimal 2 experiment selesai untuk comparison. Found: %d",
                  len(all_exp_data))
        return

    ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(comparison_dir, f"comparison_report_{ts}.json")
    with open(report_path, "w") as f:
        json.dump({"generated_at": datetime.now().isoformat(),
                   "experiments": all_exp_data}, f, indent=2, ensure_ascii=False)
    log.info("Comparison JSON : %s", report_path)

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
                    "experiment":           exp["name"],
                    "label":               exp["label"],
                    "testLimit":           exp["echidna_config"]["testLimit"],
                    "seqLen":              exp["echidna_config"]["seqLen"],
                    "timeout_config":      exp["echidna_config"]["timeout"],
                    "timeout_process":     exp["echidna_timeout"],
                    "variant":             variant,
                    "total_injected":      m.get("total_injected", 0),
                    "total_detected":      m.get("total_detected", 0),
                    "total_activated":     m.get("total_activated", 0),
                    "detection_rate_pct":  m.get("detection_rate_pct", "0.00%"),
                    "activation_rate_pct": m.get("activation_rate_pct", "0.00%"),
                    "avg_detection_time_sec": m.get("avg_detection_time_sec", -1),
                    "total_timeout":       m.get("total_timeout", 0),
                    "total_error":         m.get("total_error", 0),
                })
    log.info("Comparison CSV  : %s", csv_path)

    _generate_comparison_charts(all_exp_data, comparison_dir, ts)
    log.info("Comparison selesai → %s", comparison_dir)


# ---------------------------------------------------------------------------
# Comparison chart generator — tidak berubah dari versi asli
# ---------------------------------------------------------------------------

def _generate_comparison_charts(
    all_exp_data: List[Dict[str, Any]],
    output_dir: str,
    timestamp: str,
) -> None:
    import math
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    charts_dir = os.path.join(output_dir, f"charts_{timestamp}")
    os.makedirs(charts_dir, exist_ok=True)

    BG_FIG    = "#0f1117"
    BG_AXES   = "#1a1d27"
    BG_LEGEND = "#2a2d3e"
    GRID      = "#2d3142"
    SPINE     = "#3a3f52"
    EXP_COLORS = ["#4C72B0", "#DD8452", "#55A868"]

    from config import BUG_VARIANTS as VARIANTS

    labels  = [e["label"] for e in all_exp_data]
    n_exp   = len(all_exp_data)

    def _dark(fig, axes):
        fig.patch.set_facecolor(BG_FIG)
        for ax in (axes if hasattr(axes, "__iter__") else [axes]):
            ax.set_facecolor(BG_AXES)
            ax.tick_params(colors="white")
            for sp in ax.spines.values():
                sp.set_color(SPINE)

    def _save(fig, name):
        path = os.path.join(charts_dir, name)
        plt.savefig(path, dpi=140, bbox_inches="tight", facecolor=fig.get_facecolor())
        plt.close(fig)
        log.info("  ✓ %s", name)

    x       = np.arange(len(VARIANTS))
    w       = 0.22
    offsets = np.linspace(-(n_exp - 1) * w / 2, (n_exp - 1) * w / 2, n_exp)

    # Chart 1
    fig, ax = plt.subplots(figsize=(10, 5))
    _dark(fig, ax)
    for i, (exp, color) in enumerate(zip(all_exp_data, EXP_COLORS)):
        vals = [exp["metrics"].get(v, {}).get("detection_rate", 0) * 100 for v in VARIANTS]
        bars = ax.bar(x + offsets[i], vals, w, color=color, label=exp["label"], zorder=3)
        for b in bars:
            h = b.get_height()
            if h > 0:
                ax.text(b.get_x() + b.get_width() / 2, h + 0.5,
                        f"{h:.0f}%", ha="center", va="bottom", fontsize=7.5, color="white")
    ax.set_xticks(x)
    ax.set_xticklabels([v.replace("_", " ").title() for v in VARIANTS], color="white")
    ax.set_ylabel("Detection Rate (%)", color="white")
    ax.set_title("Detection Rate by Variant & Experiment", color="white", fontsize=13, pad=12)
    ax.yaxis.grid(True, color=GRID, linestyle="--", linewidth=0.6, zorder=0)
    ax.set_ylim(0, 115)
    ax.legend(facecolor=BG_LEGEND, labelcolor="white", fontsize=9)
    plt.tight_layout()
    _save(fig, "cmp_chart1_detection_rate.png")

    # Chart 2
    fig, ax = plt.subplots(figsize=(10, 5))
    _dark(fig, ax)
    for i, (exp, color) in enumerate(zip(all_exp_data, EXP_COLORS)):
        vals = [exp["metrics"].get(v, {}).get("activation_rate", 0) * 100 for v in VARIANTS]
        bars = ax.bar(x + offsets[i], vals, w, color=color, label=exp["label"], zorder=3)
        for b in bars:
            h = b.get_height()
            if h > 0:
                ax.text(b.get_x() + b.get_width() / 2, h + 0.5,
                        f"{h:.0f}%", ha="center", va="bottom", fontsize=7.5, color="white")
    ax.set_xticks(x)
    ax.set_xticklabels([v.replace("_", " ").title() for v in VARIANTS], color="white")
    ax.set_ylabel("Activation Rate (%)", color="white")
    ax.set_title("Activation Rate by Variant & Experiment", color="white", fontsize=13, pad=12)
    ax.yaxis.grid(True, color=GRID, linestyle="--", linewidth=0.6, zorder=0)
    ax.set_ylim(0, 115)
    ax.legend(facecolor=BG_LEGEND, labelcolor="white", fontsize=9)
    plt.tight_layout()
    _save(fig, "cmp_chart2_activation_rate.png")

    # Chart 3
    fig, ax = plt.subplots(figsize=(8, 5))
    _dark(fig, ax)
    y_pos = np.arange(n_exp)
    vals  = [exp["metrics"].get("overall", {}).get("avg_detection_time_sec", -1)
             for exp in all_exp_data]
    bars = ax.barh(y_pos, vals, color=EXP_COLORS[:n_exp], zorder=3, height=0.5)
    for bar, v in zip(bars, vals):
        ax.text(v + 1, bar.get_y() + bar.get_height() / 2,
                f"{v:.1f}s", va="center", ha="left", fontsize=9, color="white")
    ax.set_yticks(y_pos)
    ax.set_yticklabels(labels, color="white", fontsize=10)
    ax.set_xlabel("Avg Detection Time (s)", color="white")
    ax.set_title("Average Detection Time per Experiment (Overall)",
                 color="white", fontsize=13, pad=12)
    ax.xaxis.grid(True, color=GRID, linestyle="--", linewidth=0.6, zorder=0)
    plt.tight_layout()
    _save(fig, "cmp_chart3_detection_time.png")

    # Chart 4
    fig, ax = plt.subplots(figsize=(9, 4))
    _dark(fig, ax)
    matrix = np.array([
        [exp["metrics"].get(v, {}).get("detection_rate", 0) * 100 for v in VARIANTS]
        for exp in all_exp_data
    ])
    im   = ax.imshow(matrix, cmap="RdYlGn", vmin=0, vmax=100, aspect="auto")
    cbar = fig.colorbar(im, ax=ax, pad=0.02)
    cbar.ax.yaxis.set_tick_params(color="white")
    plt.setp(cbar.ax.yaxis.get_ticklabels(), color="white")
    cbar.set_label("Detection Rate (%)", color="white")
    ax.set_xticks(range(len(VARIANTS)))
    ax.set_xticklabels([v.replace("_", " ").title() for v in VARIANTS],
                       color="white", fontsize=9)
    ax.set_yticks(range(n_exp))
    ax.set_yticklabels(labels, color="white", fontsize=9)
    ax.set_title("Detection Rate Heatmap (Experiment × Variant)",
                 color="white", fontsize=13, pad=12)
    for i in range(n_exp):
        for j in range(len(VARIANTS)):
            ax.text(j, i, f"{matrix[i, j]:.0f}%", ha="center", va="center",
                    color="black" if matrix[i, j] > 50 else "white",
                    fontsize=10, fontweight="bold")
    plt.tight_layout()
    _save(fig, "cmp_chart4_status_heatmap.png")

    # Chart 5
    import math as _math
    cats   = ["Detection\nRate", "Activation\nRate", "Reachable\nRatio",
              "Timeout\nRatio", "Error Ratio"]
    n_cats = len(cats)
    angles = [n / n_cats * 2 * _math.pi for n in range(n_cats)] + [0]
    fig, ax = plt.subplots(figsize=(6.5, 6.5), subplot_kw=dict(polar=True))
    fig.patch.set_facecolor(BG_FIG)
    ax.set_facecolor(BG_AXES)
    for exp, color in zip(all_exp_data, EXP_COLORS):
        ov    = exp["metrics"].get("overall", {})
        total = ov.get("total_injected", 1) or 1
        vals  = [
            ov.get("detection_rate", 0),
            ov.get("activation_rate", 0),
            ov.get("total_reachable", 0) / total,
            ov.get("total_timeout",   0) / total,
            ov.get("total_error",     0) / total,
        ]
        vals += [vals[0]]
        ax.plot(angles, vals, color=color, linewidth=2, label=exp["label"])
        ax.fill(angles, vals, color=color, alpha=0.15)
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(cats, color="white", fontsize=9)
    ax.yaxis.set_tick_params(labelcolor="white", labelsize=7)
    ax.spines["polar"].set_color(SPINE)
    for gl in ax.yaxis.get_gridlines():
        gl.set_color(SPINE)
    for gl in ax.xaxis.get_gridlines():
        gl.set_color(SPINE)
    ax.set_title("Multi-Metric Radar: All Experiments", color="white", fontsize=13, pad=20)
    ax.legend(facecolor=BG_LEGEND, labelcolor="white", fontsize=9,
              loc="upper right", bbox_to_anchor=(1.4, 1.15))
    plt.tight_layout()
    _save(fig, "cmp_chart5_radar.png")

    log.info("Semua comparison charts tersimpan → %s", charts_dir)


# ---------------------------------------------------------------------------
# Prerequisite check
# ---------------------------------------------------------------------------

def _check_prereqs() -> bool:
    import subprocess
    import config as cfg

    issues = []
    if not os.path.isdir(cfg.BASE_CONTRACTS_DIR):
        issues.append(f"Contracts dir tidak ditemukan: {cfg.BASE_CONTRACTS_DIR}")
    try:
        subprocess.run(["solc", "--version"], capture_output=True, timeout=5)
    except FileNotFoundError:
        issues.append("solc tidak ditemukan.")

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
  python run_experiments.py                         # Run all 3 experiments
  python run_experiments.py --exp exp1_light        # Run one experiment only
  python run_experiments.py --compare-only          # Compare existing results
  python run_experiments.py --from-step 4           # Resume semua dari step 4
  python run_experiments.py --list                  # List available experiments
        """,
    )
    parser.add_argument("--exp",          type=str,  help="Run satu named experiment")
    parser.add_argument("--from-step",    type=int,  default=1, choices=range(1, 6), metavar="N",
                        help="Mulai dari step N (1–5)")
    parser.add_argument("--compare-only", action="store_true",
                        help="Skip experiment runs; hanya generate comparison charts")
    parser.add_argument("--list",         action="store_true",
                        help="List available experiments dan exit")
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
        log.error("Prerequisites tidak terpenuhi. Aborting.")
        sys.exit(1)

    exps_to_run = [args.exp] if args.exp else [e["name"] for e in EXPERIMENTS]
    log.info("Experiments to run: %s", exps_to_run)

    # ── FASE 1: Shared Preparation (Step 1–3) — dijalankan SEKALI ────────
    shared_step = args.from_step  # bisa 1, 2, atau 3; kalau >= 4 maka di-skip semua
    injection_logs = run_shared_preparation(from_step=shared_step)
    if injection_logs is None:
        log.error("Shared preparation gagal. Aborting.")
        sys.exit(1)

    # ── FASE 2: Per-Experiment Fuzzing (Step 4–5) ─────────────────────────
    # from_step <= 3 berarti step 4 pasti dijalankan (shared sudah selesai)
    # from_step == 4 berarti skip step 1–3, langsung step 4
    # from_step == 5 berarti hanya step 5
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
        log.warning("Hanya 1 experiment selesai — comparison butuh minimal 2.")
    else:
        log.error("Tidak ada experiment yang berhasil.")

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