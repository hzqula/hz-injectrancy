"""
MAIN PIPELINE - ORKESTRASI SEMUA TAHAPAN
=========================================
Menjalankan seluruh pipeline penelitian secara berurutan:

  Step 1: Instrumentasi Oracle
      base_contract → instrumented_contract

  Step 2: Verifikasi Kompilasi
      instrumented_contract → valid / invalid

  Step 3: Bug Injection
      instrumented_contract (valid) → injected_contract

  Step 4: Pengujian Echidna
      injected_contract → echidna_results

  Step 5: Analisis Hasil
      echidna_results → metrik (detection rate, activation rate, avg time)

Penggunaan:
    # Jalankan pipeline penuh
    python main.py

    # Jalankan mulai dari step tertentu
    python main.py --from-step 3

    # Jalankan satu step saja
    python main.py --step 1

    # Mode verbose
    python main.py --verbose
"""

import os
import sys
import json
import argparse
import time
from datetime import datetime

# Pastikan direktori tool ada di Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import (
    BASE_CONTRACTS_DIR,
    INSTRUMENTED_DIR,
    INJECTED_DIR,
    ECHIDNA_RESULTS_DIR,
    ANALYSIS_RESULTS_DIR,
    LOGS_DIR,
    BUG_VARIANTS,
)
from logger import get_logger

# Import semua step
from step1instrumentor    import run_instrumentation
from step2compiler        import verify_instrumented_contracts, get_valid_contracts
from step3injector        import run_injection
from step4echidna  import run_echidna_all
from step5analyst        import run_analysis

log = get_logger("main_pipeline")


# ─── Fungsi Utilitas ──────────────────────────────────────────────────────────

def _print_banner():
    banner = """
╔══════════════════════════════════════════════════════════════╗
║     DYNAMIC REENTRANCY BUG INJECTION TOOL                    ║
║     Evaluasi Analisis Dinamis (Echidna) via Bug Injection    ║
║                                                              ║
║     Referensi: SolidiFI (Ghaleb & Pattabiraman, 2020)        ║
║     Adaptasi  : Analisis Dinamis untuk Reentrancy            ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(banner)


def _print_step_header(step_num: int, step_name: str):
    log.info("")
    log.info("┌" + "─" * 58 + "┐")
    log.info("│  STEP %d: %-48s│", step_num, step_name)
    log.info("└" + "─" * 58 + "┘")


def _check_prerequisites():
    """Memverifikasi semua prasyarat sebelum pipeline dijalankan."""
    issues = []

    # Cek direktori base_contracts
    if not os.path.isdir(BASE_CONTRACTS_DIR):
        issues.append(
            f"Direktori base_contracts tidak ditemukan: {BASE_CONTRACTS_DIR}\n"
            f"  → Buat direktori dan letakkan file .sol di dalamnya."
        )
    elif not any(f.endswith(".sol") for f in os.listdir(BASE_CONTRACTS_DIR)):
        issues.append(
            f"Tidak ada file .sol di direktori: {BASE_CONTRACTS_DIR}\n"
            f"  → Tambahkan minimal satu kontrak Solidity."
        )

    # Cek solc
    import subprocess
    try:
        r = subprocess.run(["solc", "--version"], capture_output=True, timeout=5)
        if r.returncode != 0:
            issues.append("solc tidak merespons dengan benar.")
    except FileNotFoundError:
        issues.append(
            "solc tidak ditemukan.\n"
            "  → Install: https://docs.soliditylang.org/en/latest/installing-solidity.html"
        )
    except Exception:
        issues.append("Gagal memeriksa solc.")

    # Cek echidna (opsional - hanya warning)
    try:
        r = subprocess.run(["echidna", "--version"], capture_output=True, timeout=5)
    except FileNotFoundError:
        log.warning(
            "Echidna tidak ditemukan. Step 4 akan menghasilkan status ERROR.\n"
            "  → Install: https://github.com/crytic/echidna"
        )
    except Exception:
        pass

    if issues:
        log.error("Prasyarat tidak terpenuhi:")
        for issue in issues:
            log.error("  ✗ %s", issue)
        return False

    return True


def _save_pipeline_state(state: dict):
    """Menyimpan state pipeline ke JSON untuk resume."""
    state_path = os.path.join(LOGS_DIR, "pipeline_state.json")
    os.makedirs(LOGS_DIR, exist_ok=True)
    with open(state_path, "w") as f:
        json.dump(state, f, indent=2)


def _load_pipeline_state() -> dict:
    """Memuat state pipeline yang tersimpan."""
    state_path = os.path.join(LOGS_DIR, "pipeline_state.json")
    if os.path.isfile(state_path):
        with open(state_path) as f:
            return json.load(f)
    return {}


# ─── Fungsi Pipeline per Step ─────────────────────────────────────────────────

def run_step1(state: dict) -> bool:
    """Step 1: Instrumentasi Oracle."""
    _print_step_header(1, "INSTRUMENTASI ORACLE")

    results = run_instrumentation(
        base_dir   = BASE_CONTRACTS_DIR,
        output_dir = INSTRUMENTED_DIR,
    )

    success_count = sum(1 for ok in results.values() if ok)
    state["step1"] = {
        "completed":     True,
        "total":         len(results),
        "success":       success_count,
        "failed":        [k for k, v in results.items() if not v],
    }
    _save_pipeline_state(state)

    return success_count > 0


def run_step2(state: dict) -> list:
    """Step 2: Verifikasi Kompilasi."""
    _print_step_header(2, "VERIFIKASI KOMPILASI")

    results = verify_instrumented_contracts(INSTRUMENTED_DIR)
    valid   = get_valid_contracts(results)
    invalid = [f for f, (ok, _) in results.items() if not ok]

    state["step2"] = {
        "completed": True,
        "total":     len(results),
        "valid":     valid,
        "invalid":   invalid,
    }
    _save_pipeline_state(state)

    if not valid:
        log.error("Tidak ada kontrak yang lulus verifikasi kompilasi!")
        return []

    return valid


def run_step3(state: dict, valid_files: list) -> list:
    """Step 3: Bug Injection."""
    _print_step_header(3, "BUG INJECTION (REENTRANCY)")

    injection_logs = run_injection(
        instrumented_dir = INSTRUMENTED_DIR,
        output_dir       = INJECTED_DIR,
        valid_files      = valid_files,
        variants         = BUG_VARIANTS,
    )

    state["step3"] = {
        "completed":    True,
        "total_injected": len(injection_logs),
        "variants":     BUG_VARIANTS,
    }
    _save_pipeline_state(state)

    return injection_logs


def run_step4(state: dict, injection_logs: list) -> list:
    """Step 4: Pengujian Echidna."""
    _print_step_header(4, "PENGUJIAN DENGAN ECHIDNA")

    echidna_results = run_echidna_all(
        injected_dir  = INJECTED_DIR,
        results_dir   = ECHIDNA_RESULTS_DIR,
        injection_log = injection_logs,
    )

    detected = sum(1 for r in echidna_results if r.status == "DETECTED")
    state["step4"] = {
        "completed":     True,
        "total_tested":  len(echidna_results),
        "detected":      detected,
    }
    _save_pipeline_state(state)

    return echidna_results


def run_step5(state: dict) -> dict:
    """Step 5: Analisis Hasil."""
    _print_step_header(5, "ANALISIS HASIL DAN METRIK")

    metrics = run_analysis(
        output_dir = ANALYSIS_RESULTS_DIR,
    )

    state["step5"] = {
        "completed": True,
        "metrics_computed": len(metrics),
    }
    _save_pipeline_state(state)

    return metrics


# ─── Fungsi Pipeline Utama ────────────────────────────────────────────────────

def run_full_pipeline(from_step: int = 1) -> bool:
    """
    Menjalankan pipeline lengkap dari step tertentu.

    Parameter:
        from_step : mulai dari step berapa (1-5, default=1)

    Return:
        True jika pipeline selesai tanpa error kritis
    """
    start_time = time.time()
    state      = _load_pipeline_state() if from_step > 1 else {}

    # ── Step 1 ────────────────────────────────────────────────────────────────
    if from_step <= 1:
        ok = run_step1(state)
        if not ok:
            log.error("Step 1 gagal. Pipeline dihentikan.")
            return False
    else:
        log.info("Melewati Step 1 (from_step=%d)", from_step)

    # ── Step 2 ────────────────────────────────────────────────────────────────
    if from_step <= 2:
        valid_files = run_step2(state)
        if not valid_files:
            log.error("Step 2 gagal. Tidak ada kontrak valid. Pipeline dihentikan.")
            return False
    else:
        valid_files = state.get("step2", {}).get("valid", [])
        log.info("Memuat valid_files dari state: %d file", len(valid_files))

    # ── Step 3 ────────────────────────────────────────────────────────────────
    if from_step <= 3:
        injection_logs = run_step3(state, valid_files)
        if not injection_logs:
            log.error("Step 3 gagal. Tidak ada bug yang berhasil disuntikkan.")
            return False
    else:
        injection_log_path = os.path.join(LOGS_DIR, "injection_log.json")
        if os.path.isfile(injection_log_path):
            with open(injection_log_path) as f:
                injection_logs = json.load(f)
            log.info("Memuat injection log dari file: %d entri", len(injection_logs))
        else:
            injection_logs = []
            log.warning("Injection log tidak ditemukan, lanjutkan tanpa metadata.")

    # ── Step 4 ────────────────────────────────────────────────────────────────
    if from_step <= 4:
        echidna_results = run_step4(state, injection_logs)
        if not echidna_results:
            log.warning("Step 4 tidak menghasilkan output (mungkin Echidna tidak terinstall).")
            # Tidak fatal, tetap lanjutkan ke step 5 jika ada hasil JSON
    else:
        log.info("Melewati Step 4 (from_step=%d)", from_step)
        echidna_results = []

    # ── Step 5 ────────────────────────────────────────────────────────────────
    if from_step <= 5:
        metrics = run_step5(state)
    else:
        log.info("Melewati Step 5 (from_step=%d)", from_step)
        metrics = {}

    # ── Ringkasan Akhir ───────────────────────────────────────────────────────
    elapsed = time.time() - start_time
    log.info("")
    log.info("=" * 60)
    log.info("PIPELINE SELESAI")
    log.info("=" * 60)
    log.info("Waktu total   : %.1f detik (%.1f menit)", elapsed, elapsed / 60)
    log.info("Hasil analisis: %s", ANALYSIS_RESULTS_DIR)
    log.info("Log lengkap   : %s", LOGS_DIR)

    # Print lokasi file output utama
    import glob
    analysis_files = glob.glob(os.path.join(ANALYSIS_RESULTS_DIR, "summary_*.json"))
    if analysis_files:
        latest = sorted(analysis_files)[-1]
        log.info("Ringkasan     : %s", latest)

    return True


def run_single_step(step_num: int) -> bool:
    """Menjalankan satu step saja tanpa step lainnya."""
    state = _load_pipeline_state()

    if step_num == 1:
        return run_step1(state)
    elif step_num == 2:
        valid = run_step2(state)
        return len(valid) > 0
    elif step_num == 3:
        valid_files = state.get("step2", {}).get("valid", [])
        logs = run_step3(state, valid_files)
        return len(logs) > 0
    elif step_num == 4:
        logs = []
        log_path = os.path.join(LOGS_DIR, "injection_log.json")
        if os.path.isfile(log_path):
            with open(log_path) as f:
                logs = json.load(f)
        results = run_step4(state, logs)
        return len(results) > 0
    elif step_num == 5:
        metrics = run_step5(state)
        return len(metrics) > 0
    else:
        log.error("Nomor step tidak valid: %d (harus 1-5)", step_num)
        return False


# ─── Entry Point ──────────────────────────────────────────────────────────────

def main():
    _print_banner()

    parser = argparse.ArgumentParser(
        description="Dynamic Reentrancy Bug Injection Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh penggunaan:
  python main.py                    # Jalankan pipeline penuh (step 1-5)
  python main.py --from-step 3     # Mulai dari step 3
  python main.py --step 2          # Jalankan step 2 saja
  python main.py --check           # Cek prasyarat saja
        """,
    )

    parser.add_argument(
        "--from-step",
        type=int,
        default=1,
        choices=[1, 2, 3, 4, 5],
        help="Mulai pipeline dari step tertentu (default: 1)",
    )
    parser.add_argument(
        "--step",
        type=int,
        choices=[1, 2, 3, 4, 5],
        help="Jalankan satu step saja",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Hanya periksa prasyarat tanpa menjalankan pipeline",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Tampilkan log lebih detail",
    )

    args = parser.parse_args()

    if args.verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)

    # ── Mode check saja ───────────────────────────────────────────────────────
    if args.check:
        log.info("Memeriksa prasyarat...")
        ok = _check_prerequisites()
        if ok:
            log.info("✓ Semua prasyarat terpenuhi!")
        else:
            log.error("✗ Ada prasyarat yang belum terpenuhi.")
        sys.exit(0 if ok else 1)

    # ── Verifikasi prasyarat ──────────────────────────────────────────────────
    if not _check_prerequisites():
        log.error("Pipeline tidak dapat dijalankan. Periksa prasyarat di atas.")
        sys.exit(1)

    # ── Pilih mode running ────────────────────────────────────────────────────
    log.info("Waktu mulai: %s", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    if args.step is not None:
        # Mode satu step
        log.info("Mode: single step (%d)", args.step)
        ok = run_single_step(args.step)
    else:
        # Mode full pipeline (atau mulai dari step tertentu)
        log.info("Mode: pipeline (mulai dari step %d)", args.from_step)
        ok = run_full_pipeline(from_step=args.from_step)

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()