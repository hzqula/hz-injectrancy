"""
STEP 4 - PENGUJIAN DENGAN ECHIDNA
=================================
Menjalankan Echidna property-based fuzzer pada setiap kontrak yang
telah disuntikkan bug reentrancy.

Echidna akan:
  1. Membaca kontrak yang telah diinstrumentasi + disuntikkan bug
  2. Menjalankan fuzzing campaign untuk mencari pelanggaran property
  3. Melaporkan jika oracle echidna_cek_saldo() bernilai FALSE
     (yang berarti saldo kontrak < totalDeposits → bug aktif)

Metrik yang diukur:
  - Detection Rate   : apakah Echidna melaporkan FAILED pada property
  - Activation Rate  : apakah baris bug tercapai dalam corpus coverage
  - Detection Time   : waktu hingga property dilanggar pertama kali

Referensi proposal Bab 3.6 (Pengujian dengan Echidna)
"""

import os
import re
import json
import subprocess
import time
import yaml
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict

from config import (
    INJECTED_DIR,
    ECHIDNA_RESULTS_DIR,
    ECHIDNA_CONFIG,
    LOGS_DIR,
    ORACLE_FUNCTION_NAME,
    ECHIDNA_TIMEOUT,
)
from logger import get_logger

log = get_logger("echidna_runner")


# ─── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class EchidnaResult:
    """Hasil pengujian Echidna untuk satu kontrak."""
    source_file:     str = ""
    contract_name:   str = ""
    variant:         str = ""

    # Status deteksi
    status:          str = "UNKNOWN"   # DETECTED / NOT_DETECTED / ERROR / TIMEOUT
    property_broken: bool = False      # True jika oracle dilanggar

    # Waktu
    detection_time_sec: float = -1.0  # -1 jika tidak terdeteksi

    # Coverage (activation)
    lines_covered:   List[int] = field(default_factory=list)
    bug_line_hit:    bool = False      # True jika baris bug tercapai fuzzer

    # Raw output
    echidna_stdout:  str = ""
    echidna_stderr:  str = ""

    # Error info (jika ada)
    error_message:   str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ─── Konfigurasi YAML Echidna ─────────────────────────────────────────────────

def _generate_echidna_config(output_path: str) -> str:
    """
    Menghasilkan file konfigurasi YAML untuk Echidna.
    Referensi: Proposal Bab 3.6.1 (Konfigurasi Echidna)
    """
    config_data = {
        "testLimit":      ECHIDNA_CONFIG["testLimit"],
        "seqLen":         ECHIDNA_CONFIG["seqLen"],
        "shrinkLimit":    ECHIDNA_CONFIG["shrinkLimit"],
        "coverage":       ECHIDNA_CONFIG["coverage"],
        "timeout":        ECHIDNA_CONFIG["timeout"],
        "deployer":       ECHIDNA_CONFIG["deployer"],
        "sender":         ECHIDNA_CONFIG["sender"],
        "balanceAddr":    ECHIDNA_CONFIG["balanceAddr"],
        "balanceContract": ECHIDNA_CONFIG["balanceContract"],
        # Mode testing: property (menguji fungsi echidna_*)
        "testMode":       "property",
    }

    config_str = yaml.dump(config_data, default_flow_style=False)

    config_path = os.path.join(output_path, "echidna_config.yaml")
    with open(config_path, "w") as f:
        f.write(config_str)

    return config_path


# ─── Parsing Output Echidna ───────────────────────────────────────────────────

def _parse_echidna_output(stdout: str, stderr: str) -> Tuple[bool, float, bool]:
    """
    Mem-parse output Echidna untuk mengekstrak:
      - property_broken : apakah oracle dilanggar (FAILED)
      - detection_time  : waktu deteksi dalam detik
      - bug_line_hit    : apakah baris bug tercapai dalam coverage

    Return:
        (property_broken, detection_time_sec, bug_line_hit)
    """
    combined = stdout + "\n" + stderr

    # ── Cek apakah property dilanggar ─────────────────────────────────────────
    # Echidna output: "echidna_cek_saldo: failed!💥"
    property_broken = bool(
        re.search(
            rf"{re.escape(ORACLE_FUNCTION_NAME)}.*failed",
            combined,
            re.IGNORECASE,
        )
    )

    # ── Ekstrak waktu deteksi ──────────────────────────────────────────────────
    # Echidna mencetak "Seed:" dan statistik saat selesai
    # Format waktu bervariasi: "time elapsed: X.XXs" atau dari timestamp
    detection_time = -1.0
    time_match = re.search(r"elapsed.*?(\d+\.?\d*)\s*s", combined, re.IGNORECASE)
    if time_match and property_broken:
        detection_time = float(time_match.group(1))

    # ── Cek bug line hit via coverage ──────────────────────────────────────────
    # Jika Echidna mencetak coverage, baris dengan '*' berarti tercapai
    bug_line_hit = bool(
        re.search(r"bug_reentrancy.*\*", combined, re.IGNORECASE)
    )

    return property_broken, detection_time, bug_line_hit


def _detect_contract_name_in_file(filepath: str) -> Optional[str]:
    """Mendeteksi nama kontrak utama dari file .sol."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()
        for line in source.split("\n"):
            stripped = line.strip()
            if stripped.startswith("contract ") and "{" in stripped:
                parts = stripped.split()
                if len(parts) >= 2:
                    return parts[1].split("(")[0].split("{")[0].strip()
    except Exception:
        pass
    return None


# ─── Fungsi Runner Echidna ────────────────────────────────────────────────────

def run_echidna_on_contract(
    contract_path: str,
    result_dir: str,
    variant: str,
) -> EchidnaResult:
    """
    Menjalankan Echidna pada satu kontrak dan mengumpulkan hasilnya.

    Parameter:
        contract_path : path ke file .sol yang akan diuji
        result_dir    : direktori untuk menyimpan hasil Echidna
        variant       : nama varian bug ("single_function" / "cross_function")

    Return:
        EchidnaResult berisi semua metrik hasil pengujian
    """
    fname         = os.path.basename(contract_path)
    contract_name = _detect_contract_name_in_file(contract_path)

    result = EchidnaResult(
        source_file   = fname,
        contract_name = contract_name or "UNKNOWN",
        variant       = variant,
    )

    if not os.path.isfile(contract_path):
        result.status        = "ERROR"
        result.error_message = f"File tidak ditemukan: {contract_path}"
        log.error(result.error_message)
        return result

    os.makedirs(result_dir, exist_ok=True)

    # ── Generate konfigurasi YAML ──────────────────────────────────────────────
    config_path = _generate_echidna_config(result_dir)

    # ── Jalankan Echidna ───────────────────────────────────────────────────────
    cmd = [
        "echidna",
        contract_path,
        "--config", config_path,
        "--format", "text",
    ]

    if contract_name:
        cmd += ["--contract", contract_name]

    log.info("  Menjalankan Echidna: %s [%s]", fname, variant)
    log.debug("  Command: %s", " ".join(cmd))

    start_time = time.time()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=ECHIDNA_TIMEOUT,
        )
        elapsed = time.time() - start_time
        stdout  = proc.stdout
        stderr  = proc.stderr

        # Simpan raw output
        result.echidna_stdout = stdout
        result.echidna_stderr = stderr

        # ── Parse hasil ────────────────────────────────────────────────────────
        property_broken, detection_time, bug_line_hit = _parse_echidna_output(
            stdout, stderr
        )

        result.property_broken  = property_broken
        result.bug_line_hit     = bug_line_hit

        if property_broken:
            result.status           = "DETECTED"
            result.detection_time_sec = detection_time if detection_time >= 0 else elapsed
            log.info("  ✓ DETECTED   | waktu: %.2fs", result.detection_time_sec)
        else:
            result.status           = "NOT_DETECTED"
            result.detection_time_sec = ECHIDNA_TIMEOUT  # catat sebagai max timeout
            log.info("  ✗ NOT_DETECTED | bug tidak terpicu dalam %ds", ECHIDNA_TIMEOUT)

        if bug_line_hit:
            log.debug("  → Baris bug tercapai (activation confirmed)")

    except subprocess.TimeoutExpired:
        elapsed = time.time() - start_time
        result.status             = "TIMEOUT"
        result.detection_time_sec = ECHIDNA_TIMEOUT
        result.error_message      = f"Echidna timeout setelah {ECHIDNA_TIMEOUT}s"
        log.warning("  ⏱ TIMEOUT    | %s", fname)

    except FileNotFoundError:
        result.status        = "ERROR"
        result.error_message = (
            "Echidna tidak ditemukan. "
            "Pastikan Echidna sudah terinstall dan ada di PATH."
        )
        log.error("  ✗ ERROR      | %s", result.error_message)

    except Exception as e:
        result.status        = "ERROR"
        result.error_message = str(e)
        log.error("  ✗ ERROR      | %s", e)

    # ── Simpan raw output ke file ──────────────────────────────────────────────
    output_log_path = os.path.join(result_dir, f"{os.path.splitext(fname)[0]}_echidna.txt")
    with open(output_log_path, "w", encoding="utf-8") as f:
        f.write("=== STDOUT ===\n")
        f.write(result.echidna_stdout)
        f.write("\n=== STDERR ===\n")
        f.write(result.echidna_stderr)

    return result


def run_echidna_all(
    injected_dir: str       = INJECTED_DIR,
    results_dir: str        = ECHIDNA_RESULTS_DIR,
    injection_log: list     = None,
) -> List[EchidnaResult]:
    """
    Menjalankan Echidna pada semua kontrak ter-inject dalam direktori.

    Parameter:
        injected_dir  : direktori berisi kontrak yang sudah diinjeksi bug
        results_dir   : direktori output untuk hasil Echidna
        injection_log : log dari step 3 (untuk metadata varian)

    Return:
        list EchidnaResult untuk setiap kontrak yang diuji
    """
    os.makedirs(results_dir, exist_ok=True)

    # Buat lookup dari injection log
    variant_lookup: Dict[str, str] = {}
    if injection_log:
        for entry in injection_log:
            output_file = entry.get("output_file", "")
            variant     = entry.get("variant", "unknown")
            if output_file:
                variant_lookup[output_file] = variant

    sol_files = sorted([
        f for f in os.listdir(injected_dir)
        if f.endswith(".sol") and not f.startswith(".")
    ])

    if not sol_files:
        log.warning("Tidak ada kontrak ter-inject di: %s", injected_dir)
        return []

    log.info("=" * 60)
    log.info("STEP 4: PENGUJIAN DENGAN ECHIDNA")
    log.info("=" * 60)
    log.info("Jumlah kontrak yang akan diuji: %d", len(sol_files))

    all_results: List[EchidnaResult] = []

    for fname in sol_files:
        contract_path = os.path.join(injected_dir, fname)

        # Tentukan varian dari nama file atau lookup
        variant = variant_lookup.get(fname, "unknown")
        if variant == "unknown":
            # Coba deteksi dari nama file
            if "single_function" in fname:
                variant = "single_function"
            elif "cross_function" in fname:
                variant = "cross_function"

        # Direktori hasil per kontrak
        result_subdir = os.path.join(results_dir, os.path.splitext(fname)[0])
        os.makedirs(result_subdir, exist_ok=True)

        log.info("")
        log.info("Menguji: %s", fname)

        echidna_result = run_echidna_on_contract(
            contract_path, result_subdir, variant
        )
        all_results.append(echidna_result)

    # ── Simpan semua hasil ke JSON ─────────────────────────────────────────────
    results_log_path = os.path.join(LOGS_DIR, "echidna_results.json")
    os.makedirs(LOGS_DIR, exist_ok=True)
    with open(results_log_path, "w", encoding="utf-8") as f:
        json.dump(
            [r.to_dict() for r in all_results],
            f, indent=2, ensure_ascii=False
        )

    detected = sum(1 for r in all_results if r.status == "DETECTED")
    timeout  = sum(1 for r in all_results if r.status == "TIMEOUT")
    error    = sum(1 for r in all_results if r.status == "ERROR")

    log.info("")
    log.info("Ringkasan Echidna:")
    log.info("  DETECTED     : %d", detected)
    log.info("  NOT_DETECTED : %d", len(all_results) - detected - timeout - error)
    log.info("  TIMEOUT      : %d", timeout)
    log.info("  ERROR        : %d", error)
    log.info("Hasil tersimpan di: %s", results_log_path)

    return all_results


# ─── Entry Point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    if len(sys.argv) == 2:
        # Mode satu file
        result = run_echidna_on_contract(
            sys.argv[1],
            ECHIDNA_RESULTS_DIR,
            variant="unknown",
        )
        print(f"Status : {result.status}")
        print(f"Detected: {result.property_broken}")
    else:
        results = run_echidna_all()
        sys.exit(0 if results else 1)