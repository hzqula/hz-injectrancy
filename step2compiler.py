"""
STEP 2 — VERIFIKASI KOMPILASI
================================
Memastikan semua kontrak yang sudah diinstrumentasi dapat dikompilasi
tanpa error sebelum dilanjutkan ke tahap injeksi bug.

Kontrak yang gagal dikompilasi tidak diteruskan ke tahap berikutnya
dan dicatat sebagai error dalam log.

Alur:
    instrumented_contract  →  [verifikasi solc]  →  valid / invalid
"""

import os
import subprocess
from typing import Dict, Tuple

from config import INSTRUMENTED_DIR, SOLC_BINARY, COMPILATION_TIMEOUT
from logger import get_logger

log = get_logger("compiler")


# ---------------------------------------------------------------------------
# Fungsi inti
# ---------------------------------------------------------------------------

def compile_contract(filepath: str) -> Tuple[bool, str]:
    """
    Mencoba mengkompilasi satu file kontrak Solidity menggunakan solc.

    Args:
        filepath: Path lengkap ke file .sol.

    Returns:
        (True, "")           jika kompilasi berhasil.
        (False, pesan_error) jika terjadi kesalahan.
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
        return False, f"Timeout ({COMPILATION_TIMEOUT}s): {os.path.basename(filepath)}"
    except Exception as e:
        return False, f"Error tidak terduga: {e}"

    if result.returncode != 0:
        combined = result.stdout + result.stderr
        error_lines = [
            line for line in combined.splitlines()
            if "Error" in line or "error" in line
        ]
        error_msg = "\n".join(error_lines) if error_lines else combined[:500]
        return False, error_msg

    return True, ""


def verify_instrumented_contracts(
    instrumented_dir: str = INSTRUMENTED_DIR,
) -> Dict[str, Tuple[bool, str]]:
    """
    Memverifikasi semua kontrak terinstrumentasi di dalam *instrumented_dir*.

    Returns:
        Dict { "filename.sol": (berhasil, pesan_error) }
    """
    sol_files = sorted(
        f for f in os.listdir(instrumented_dir)
        if f.endswith(".sol") and not f.startswith(".")
    )

    if not sol_files:
        log.warning("Tidak ada file .sol di: %s", instrumented_dir)
        return {}

    log.info("=" * 60)
    log.info("STEP 2: VERIFIKASI KOMPILASI")
    log.info("=" * 60)
    log.info("Total kontrak: %d", len(sol_files))

    results: Dict[str, Tuple[bool, str]] = {}
    valid_count = invalid_count = 0

    for fname in sol_files:
        fpath = os.path.join(instrumented_dir, fname)
        ok, err_msg = compile_contract(fpath)
        results[fname] = (ok, err_msg)

        if ok:
            valid_count += 1
            log.info("  ✓ VALID   : %s", fname)
        else:
            invalid_count += 1
            log.warning("  ✗ INVALID : %s", fname)
            for line in err_msg.splitlines()[:3]:
                if line.strip():
                    log.warning("            %s", line.strip())

    log.info("Hasil: %d valid, %d invalid.", valid_count, invalid_count)
    return results


# ---------------------------------------------------------------------------
# Fungsi pembantu
# ---------------------------------------------------------------------------

def get_valid_contracts(results: Dict[str, Tuple[bool, str]]) -> list:
    """Mengembalikan daftar nama file yang lulus verifikasi."""
    return [fname for fname, (ok, _) in results.items() if ok]


def get_invalid_contracts(results: Dict[str, Tuple[bool, str]]) -> list:
    """Mengembalikan daftar nama file yang gagal verifikasi."""
    return [fname for fname, (ok, _) in results.items() if not ok]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    if len(sys.argv) == 2:
        ok, msg = compile_contract(sys.argv[1])
        if ok:
            print(f"✓ Kompilasi berhasil: {sys.argv[1]}")
        else:
            print(f"✗ Kompilasi gagal:\n{msg}")
            sys.exit(1)
    else:
        results = verify_instrumented_contracts()
        invalid = get_invalid_contracts(results)
        if invalid:
            log.warning("Kontrak yang gagal dikompilasi:")
            for f in invalid:
                _, err = results[f]
                log.warning("  - %s: %s", f, err[:100])
        sys.exit(1 if invalid else 0)