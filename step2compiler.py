"""
STEP 2 - VERIFIKASI KOMPILASI
=================================
Mastiin semua kontrak yang udah diinstrumentasi dapat dikompilasi
tanpa error sebelum dilanjutin ke tahap injeksi bug.

Kontrak yang gagal dikompilasi ga akan dilanjutin ke tahap berikutnya
dan akan dicatat sebagai error dalam log.

Alur:
  instrumented_contract  →  [verifikasi solc]  →  valid / invalid
"""

import os
import subprocess
import json
from typing import Tuple, Dict

from config import (
    INSTRUMENTED_DIR,
    SOLC_BINARY,
    COMPILATION_TIMEOUT,
)
from logger import get_logger

log = get_logger("compiler")


# ─── Fungsi Inti ──────────────────────────────────────────────────────────────

def compile_contract(filepath: str) -> Tuple[bool, str]:
    """
    Mencoba mengkompilasi satu file kontrak Solidity menggunakan solc.

    Parameter:
        filepath : path lengkap ke file .sol

    Return:
        (True, "")          jika kompilasi berhasil tanpa error
        (False, "pesan")    jika ada error kompilasi
    """
    if not os.path.isfile(filepath):
        return False, f"File tidak ditemukan: {filepath}"

    try:
        result = subprocess.run(
            [SOLC_BINARY, "--no-color", filepath],
            capture_output=True,
            text=True,
            timeout=COMPILATION_TIMEOUT,
        )
    except FileNotFoundError:
        return False, f"Compiler '{SOLC_BINARY}' tidak ditemukan. Pastikan solc terinstall."
    except subprocess.TimeoutExpired:
        return False, f"Timeout ({COMPILATION_TIMEOUT}s) saat mengkompilasi: {os.path.basename(filepath)}"
    except Exception as e:
        return False, f"Error tidak terduga: {e}"

    stdout_combined = result.stdout + result.stderr

    if result.returncode != 0:
        error_lines = [
            line for line in stdout_combined.split("\n")
            if "Error" in line or "error" in line
        ]
        error_msg = "\n".join(error_lines) if error_lines else stdout_combined[:500]
        return False, error_msg

    return True, ""


def verify_instrumented_contracts(
    instrumented_dir: str = INSTRUMENTED_DIR,
) -> Dict[str, Tuple[bool, str]]:
    """
    Memverifikasi semua kontrak terinstrumentasi dalam direktori.

    Return:
        dict: {"filename.sol": (True/False, "error_message"), ...}
    """
    results: Dict[str, Tuple[bool, str]] = {}

    sol_files = sorted([
        f for f in os.listdir(instrumented_dir)
        if f.endswith(".sol") and not f.startswith(".")
    ])

    if not sol_files:
        log.warning("Tidak ada file .sol di direktori: %s", instrumented_dir)
        return results

    log.info("=" * 60)
    log.info("STEP 2: VERIFIKASI KOMPILASI")
    log.info("=" * 60)
    log.info("Jumlah kontrak yang akan diverifikasi: %d", len(sol_files))

    valid_count   = 0
    invalid_count = 0

    for fname in sol_files:
        fpath = os.path.join(instrumented_dir, fname)
        ok, err_msg = compile_contract(fpath)
        results[fname] = (ok, err_msg)

        if ok:
            valid_count += 1
            log.info("  ✓ VALID     : %s", fname)
        else:
            invalid_count += 1
            log.warning("  ✗ INVALID   : %s", fname)
            # Tampilkan maksimal 3 baris pesan error
            for line in err_msg.split("\n")[:3]:
                if line.strip():
                    log.warning("              %s", line.strip())

    log.info("")
    log.info("Hasil verifikasi: %d valid, %d invalid (dari %d total)",
             valid_count, invalid_count, len(sol_files))

    return results


def get_valid_contracts(verification_results: Dict[str, Tuple[bool, str]]) -> list:
    """
    Menyaring hanya kontrak yang lulus verifikasi kompilasi.

    Return:
        list nama file yang valid: ["file1.sol", "file2.sol", ...]
    """
    return [fname for fname, (ok, _) in verification_results.items() if ok]


def get_invalid_contracts(verification_results: Dict[str, Tuple[bool, str]]) -> list:
    """
    Menyaring kontrak yang gagal verifikasi kompilasi.

    Return:
        list nama file yang invalid: ["file1.sol", "file2.sol", ...]
    """
    return [fname for fname, (ok, _) in verification_results.items() if not ok]


# ─── Entry Point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    if len(sys.argv) == 2:
        # Mode satu file
        ok, msg = compile_contract(sys.argv[1])
        if ok:
            print(f"✓ Kompilasi berhasil: {sys.argv[1]}")
        else:
            print(f"✗ Kompilasi gagal:\n{msg}")
            sys.exit(1)
    else:
        # Mode batch: verifikasi semua kontrak di instrumented_contracts/
        results = verify_instrumented_contracts()

        valid   = get_valid_contracts(results)
        invalid = get_invalid_contracts(results)

        if invalid:
            log.warning("Kontrak yang GAGAL dikompilasi:")
            for f in invalid:
                _, err = results[f]
                log.warning("  - %s: %s", f, err[:100])

        sys.exit(0 if not invalid else 1)