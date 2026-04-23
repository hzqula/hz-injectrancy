"""
MAIN PIPELINE — ORKESTRASI SEMUA TAHAPAN
==========================================
Menjalankan seluruh pipeline penelitian secara berurutan:

    Step 1  Instrumentasi Oracle
            base_contract → instrumented_contract

    Step 2  Verifikasi Kompilasi
            instrumented_contract → valid / invalid

    Step 3  Bug Injection
            instrumented_contract (valid) → injected_contract

    Step 4  Pengujian Echidna
            injected_contract → echidna_results

    Step 5  Analisis Hasil
            echidna_results → metrik (detection rate, activation rate, avg time)

Penggunaan:
    python main.py                   # Pipeline penuh (step 1–5)
    python main.py --from-step 3     # Mulai dari step tertentu
    python main.py --step 1          # Jalankan satu step saja
    python main.py --check           # Periksa prasyarat saja
    python main.py --verbose         # Log lebih detail
"""

import argparse
import glob
import json
import os
import subprocess
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import (
    ANALYSIS_RESULTS_DIR,
    BASE_CONTRACTS_DIR,
    BUG_VARIANTS,
    ECHIDNA_RESULTS_DIR,
    INJECTED_DIR,
    INSTRUMENTED_DIR,
    LOGS_DIR,
)
from logger import get_logger
from step1instrumentor import run_instrumentation
from step2compiler     import get_valid_contracts, verify_instrumented_contracts
from step3injector     import run_injection
from step4echidna      import run_echidna_all
from step5analyst      import run_analysis

log = get_logger("pipeline")


# ---------------------------------------------------------------------------
# Banner & header
# ---------------------------------------------------------------------------

_BANNER = """
╔══════════════════════════════════════════════════════════════╗
║     DYNAMIC REENTRANCY BUG INJECTION TOOL                    ║
║     Evaluasi Analisis Dinamis (Echidna) via Bug Injection    ║
║                                                              ║
║     Referensi: SolidiFI (Ghaleb & Pattabiraman, 2020)        ║
║     Adaptasi : Analisis Dinamis untuk Reentrancy             ║
╚══════════════════════════════════════════════════════════════╝
"""

_STEP_LABELS = {
    1: "INSTRUMENTASI ORACLE",
    2: "VERIFIKASI KOMPILASI",
    3: "BUG INJECTION",
    4: "PENGUJIAN ECHIDNA",
    5: "ANALISIS HASIL",
}


def _step_header(step_num: int) -> None:
    label = _STEP_LABELS.get(step_num, f"STEP {step_num}")
    log.info("")
    log.info("┌─────────────────────────────────────────────────────────┐")
    log.info("│  STEP %d ─ %-46s│", step_num, label)
    log.info("└─────────────────────────────────────────────────────────┘")


# ---------------------------------------------------------------------------
# Prasyarat
# ---------------------------------------------------------------------------

def _check_prerequisites() -> bool:
    """Memeriksa semua prasyarat sebelum pipeline dijalankan."""
    issues = []

    # Direktori contracts
    if not os.path.isdir(BASE_CONTRACTS_DIR):
        issues.append(
            f"Direktori tidak ditemukan: {BASE_CONTRACTS_DIR}\n"
            f"  → Buat direktori dan letakkan file .sol di dalamnya."
        )
    elif not any(f.endswith(".sol") for f in os.listdir(BASE_CONTRACTS_DIR)):
        issues.append(
            f"Tidak ada file .sol di: {BASE_CONTRACTS_DIR}\n"
            f"  → Tambahkan minimal satu kontrak Solidity."
        )

    # solc
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

    # echidna (opsional — hanya peringatan)
    try:
        subprocess.run(["echidna", "--version"], capture_output=True, timeout=5)
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


# ---------------------------------------------------------------------------
# State pipeline
# ---------------------------------------------------------------------------

_STATE_PATH = os.path.join(LOGS_DIR, "pipeline_state.json")


def _save_state(state: dict) -> None:
    os.makedirs(LOGS_DIR, exist_ok=True)
    with open(_STATE_PATH, "w") as f:
        json.dump(state, f, indent=2)


def _load_state() -> dict:
    if os.path.isfile(_STATE_PATH):
        with open(_STATE_PATH) as f:
            return json.load(f)
    return {}


# ---------------------------------------------------------------------------
# Fungsi per step
# ---------------------------------------------------------------------------

def run_step1(state: dict) -> bool:
    _step_header(1)
    results = run_instrumentation(base_dir=BASE_CONTRACTS_DIR, output_dir=INSTRUMENTED_DIR)
    success = sum(results.values())
    state["step1"] = {
        "completed": True,
        "total":     len(results),
        "success":   success,
        "failed":    [k for k, v in results.items() if not v],
    }
    _save_state(state)
    return success > 0


def run_step2(state: dict) -> list:
    _step_header(2)
    results     = verify_instrumented_contracts(INSTRUMENTED_DIR)
    valid_files = get_valid_contracts(results)
    invalid     = [f for f, (ok, _) in results.items() if not ok]
    state["step2"] = {
        "completed": True,
        "total":     len(results),
        "valid":     valid_files,
        "invalid":   invalid,
    }
    _save_state(state)
    if not valid_files:
        log.error("Tidak ada kontrak yang lulus verifikasi kompilasi.")
    return valid_files


def run_step3(state: dict, valid_files: list) -> list:
    _step_header(3)
    logs = run_injection(
        instrumented_dir=INSTRUMENTED_DIR,
        output_dir=INJECTED_DIR,
        valid_files=valid_files,
        variants=BUG_VARIANTS,
    )
    state["step3"] = {
        "completed":      True,
        "total_injected": len(logs),
        "variants":       BUG_VARIANTS,
    }
    _save_state(state)
    return logs


def run_step4(state: dict, injection_logs: list) -> list:
    _step_header(4)
    results  = run_echidna_all(
        injected_dir=INJECTED_DIR,
        results_dir=ECHIDNA_RESULTS_DIR,
        injection_log=injection_logs,
    )
    detected = sum(1 for r in results if r.status == "DETECTED")
    state["step4"] = {
        "completed":    True,
        "total_tested": len(results),
        "detected":     detected,
    }
    _save_state(state)
    return results


def run_step5(state: dict) -> dict:
    _step_header(5)
    metrics = run_analysis(output_dir=ANALYSIS_RESULTS_DIR)
    state["step5"] = {
        "completed":        True,
        "metrics_computed": len(metrics),
    }
    _save_state(state)
    return metrics


# ---------------------------------------------------------------------------
# Fungsi pipeline utama
# ---------------------------------------------------------------------------

def _load_injection_log() -> list:
    """Memuat injection log dari file JSON jika ada."""
    path = os.path.join(LOGS_DIR, "injection_log.json")
    if os.path.isfile(path):
        with open(path) as f:
            data = json.load(f)
        log.info("Injection log dimuat: %d entri", len(data))
        return data
    log.warning("Injection log tidak ditemukan.")
    return []


def run_full_pipeline(from_step: int = 1) -> bool:
    """
    Menjalankan pipeline lengkap mulai dari *from_step*.

    Returns:
        True jika pipeline selesai tanpa error kritis.
    """
    start  = time.time()
    state  = _load_state() if from_step > 1 else {}

    log.info("Mulai pipeline dari step %d", from_step)

    # Step 1
    if from_step <= 1:
        if not run_step1(state):
            log.error("Step 1 gagal. Pipeline dihentikan.")
            return False
    else:
        log.info("⏭  Melewati Step 1")

    # Step 2
    if from_step <= 2:
        valid_files = run_step2(state)
        if not valid_files:
            log.error("Step 2 gagal. Pipeline dihentikan.")
            return False
    else:
        valid_files = state.get("step2", {}).get("valid", [])
        log.info("⏭  Melewati Step 2  (%d file valid dari state)", len(valid_files))

    # Step 3
    if from_step <= 3:
        injection_logs = run_step3(state, valid_files)
        if not injection_logs:
            log.error("Step 3 gagal. Tidak ada bug yang berhasil disuntikkan.")
            return False
    else:
        injection_logs = _load_injection_log() if from_step > 3 else []
        log.info("⏭  Melewati Step 3")

    # Step 4
    if from_step <= 4:
        echidna_results = run_step4(state, injection_logs)
        if not echidna_results:
            log.warning("Step 4 tidak menghasilkan output (mungkin Echidna belum terinstall).")
    else:
        log.info("⏭  Melewati Step 4")

    # Step 5
    if from_step <= 5:
        run_step5(state)
    else:
        log.info("⏭  Melewati Step 5")

    # Ringkasan akhir
    elapsed = time.time() - start
    log.info("")
    log.info("╔══════════════════════════════════════════════════════════╗")
    log.info("║  ✓  PIPELINE SELESAI                                     ║")
    log.info("╠══════════════════════════════════════════════════════════╣")
    log.info("║  Waktu total    : %-37s║", f"{elapsed:.1f}s  ({elapsed / 60:.1f} menit)")
    log.info("║  Hasil analisis : %-37s║", _shorten(ANALYSIS_RESULTS_DIR, 37))
    log.info("║  Log lengkap    : %-37s║", _shorten(LOGS_DIR, 37))

    # Tampilkan file ringkasan terbaru jika ada
    summary_files = sorted(glob.glob(os.path.join(ANALYSIS_RESULTS_DIR, "summary_*.json")))
    if summary_files:
        log.info("║  Ringkasan      : %-37s║", _shorten(summary_files[-1], 37))

    log.info("╚══════════════════════════════════════════════════════════╝")
    return True


def run_single_step(step_num: int) -> bool:
    """Menjalankan satu step saja tanpa step lainnya."""
    state = _load_state()

    dispatch = {
        1: lambda: run_step1(state),
        2: lambda: bool(run_step2(state)),
        3: lambda: bool(run_step3(state, state.get("step2", {}).get("valid", []))),
        4: lambda: bool(run_step4(state, _load_injection_log())),
        5: lambda: bool(run_step5(state)),
    }

    fn = dispatch.get(step_num)
    if fn is None:
        log.error("Nomor step tidak valid: %d (harus 1–5)", step_num)
        return False

    return bool(fn())


# ---------------------------------------------------------------------------
# Utilitas
# ---------------------------------------------------------------------------

def _shorten(path: str, max_len: int) -> str:
    """Memotong path agar tidak melebihi *max_len* karakter."""
    return path if len(path) <= max_len else "…" + path[-(max_len - 1):]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    print(_BANNER)

    parser = argparse.ArgumentParser(
        description="Dynamic Reentrancy Bug Injection Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  python main.py                  # Pipeline penuh (step 1–5)
  python main.py --from-step 3    # Mulai dari step 3
  python main.py --step 2         # Jalankan step 2 saja
  python main.py --check          # Cek prasyarat saja
        """,
    )
    parser.add_argument("--from-step", type=int, default=1,  choices=range(1, 6),
                        metavar="N", help="Mulai pipeline dari step N (1–5, default: 1)")
    parser.add_argument("--step",      type=int, choices=range(1, 6),
                        metavar="N", help="Jalankan satu step saja")
    parser.add_argument("--check",   action="store_true", help="Periksa prasyarat saja")
    parser.add_argument("--verbose", action="store_true", help="Tampilkan log DEBUG")
    args = parser.parse_args()

    if args.verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)

    # Mode check saja
    if args.check:
        ok = _check_prerequisites()
        log.info("✓ Semua prasyarat terpenuhi." if ok else "✗ Ada prasyarat yang belum terpenuhi.")
        sys.exit(0 if ok else 1)

    if not _check_prerequisites():
        log.error("Pipeline tidak dapat dijalankan. Periksa prasyarat di atas.")
        sys.exit(1)

    log.info("Waktu mulai : %s", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    if args.step is not None:
        log.info("Mode        : single step (%d)", args.step)
        ok = run_single_step(args.step)
    else:
        log.info("Mode        : full pipeline (dari step %d)", args.from_step)
        ok = run_full_pipeline(from_step=args.from_step)

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()