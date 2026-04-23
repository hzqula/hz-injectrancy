"""
STEP 1 — INSTRUMENTASI ORACLE
===============================
Menyisipkan mekanisme oracle ke dalam kontrak bersih (base contract).
Oracle adalah fungsi Echidna yang mendeteksi pelanggaran invariant saat runtime.

Alur:
    base_contract  →  [instrumentasi]  →  instrumented_contract

Yang disisipkan:
    1. State reentrancy : hz_is_reentered (publik) dan hz_locked (privat)
    2. Fungsi oracle    : mengembalikan !hz_is_reentered
"""

import os
import re
from typing import Optional

from config import BASE_CONTRACTS_DIR, INSTRUMENTED_DIR, ORACLE_FUNCTION_NAME
from logger import get_logger

log = get_logger("instrumentor")


# ---------------------------------------------------------------------------
# Template kode yang disisipkan
# ---------------------------------------------------------------------------

TRACKER_VAR_TEMPLATE = """
    // [ORACLE] Variabel pelacak reentrancy
    bool public  hz_is_reentered = false;
    bool private hz_locked       = false;
"""

ORACLE_FUNCTION_TEMPLATE = """
    // [ORACLE] Property Echidna — pelanggaran berarti fuzzer berhasil re-enter
    function {oracle_name}() public view returns (bool) {{
        return !hz_is_reentered;
    }}
"""


# ---------------------------------------------------------------------------
# Utilitas internal
# ---------------------------------------------------------------------------

def _detect_contract_name(source: str) -> Optional[str]:
    """Mendeteksi nama kontrak pertama (bukan interface/library)."""
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("contract ") and "{" in stripped:
            parts = stripped.split()
            if len(parts) >= 2:
                return parts[1].split("(")[0].split("{")[0].strip()
    return None


def _insert_after_contract_open(source: str, contract_name: str, code: str) -> str:
    """Menyisipkan *code* tepat setelah baris pembuka blok kontrak."""
    lines = source.splitlines()
    insert_idx: Optional[int] = None

    # Cari baris pembuka kontrak yang cocok dengan nama
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith("contract ") and contract_name in s and "{" in s:
            insert_idx = i + 1
            break

    # Fallback: ambil kontrak pertama yang ditemukan
    if insert_idx is None:
        log.warning("Kontrak '%s' tidak ditemukan, gunakan kontrak pertama.", contract_name)
        for i, line in enumerate(lines):
            if line.strip().startswith("contract ") and "{" in line:
                insert_idx = i + 1
                break

    if insert_idx is None:
        log.error("Tidak dapat menemukan lokasi sisipan variabel pelacak.")
        return source

    lines.insert(insert_idx, code)
    log.debug("Kode disisipkan setelah baris %d.", insert_idx)
    return "\n".join(lines)


def _insert_before_contract_close(source: str, contract_name: str, code: str) -> str:
    """Menyisipkan *code* tepat sebelum kurung kurawal penutup kontrak."""
    pattern = r"contract\s+" + re.escape(contract_name) + r"\s*\{"
    match = re.search(pattern, source)

    if not match:
        # Fallback: sisipkan sebelum kurung kurawal terakhir
        last = source.rfind("}")
        return source[:last] + "\n" + code + "\n" + source[last:]

    start = match.end() - 1
    depth = 0

    for i in range(start, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[:i] + "\n" + code + "\n" + source[i:]

    return source


# ---------------------------------------------------------------------------
# Fungsi publik
# ---------------------------------------------------------------------------

def instrument_contract(input_path: str, output_path: str) -> bool:
    """
    Menginstrumentasi satu file kontrak Solidity.

    Menyisipkan variabel pelacak dan fungsi oracle ke dalam kontrak,
    lalu menyimpan hasilnya ke *output_path*.

    Returns:
        True jika berhasil, False jika terjadi kesalahan.
    """
    log.info("Menginstumentasi: %s", os.path.basename(input_path))

    if not os.path.isfile(input_path):
        log.error("File tidak ditemukan: %s", input_path)
        return False

    with open(input_path, encoding="utf-8", errors="ignore") as f:
        source = f.read()

    contract_name = _detect_contract_name(source)
    if contract_name is None:
        log.error("Tidak dapat mendeteksi nama kontrak: %s", input_path)
        return False

    log.debug("Kontrak terdeteksi: %s", contract_name)

    source = _insert_after_contract_open(source, contract_name, TRACKER_VAR_TEMPLATE)
    source = _insert_before_contract_close(
        source,
        contract_name,
        ORACLE_FUNCTION_TEMPLATE.format(oracle_name=ORACLE_FUNCTION_NAME),
    )

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(source)

    log.info("  ✓ %s", os.path.basename(output_path))
    return True


def run_instrumentation(
    base_dir: str = BASE_CONTRACTS_DIR,
    output_dir: str = INSTRUMENTED_DIR,
) -> dict:
    """
    Menginstrumentasi semua file .sol di *base_dir* dan menyimpannya ke *output_dir*.

    Returns:
        Dict { "filename.sol": True/False } hasil instrumentasi per file.
    """
    os.makedirs(output_dir, exist_ok=True)

    sol_files = sorted(
        f for f in os.listdir(base_dir)
        if f.endswith(".sol") and not f.startswith(".")
    )

    if not sol_files:
        log.warning("Tidak ada file .sol di: %s", base_dir)
        return {}

    log.info("=" * 60)
    log.info("STEP 1: INSTRUMENTASI ORACLE")
    log.info("=" * 60)
    log.info("Total kontrak: %d", len(sol_files))

    results = {}
    for fname in sol_files:
        ok = instrument_contract(
            input_path=os.path.join(base_dir, fname),
            output_path=os.path.join(output_dir, fname),
        )
        results[fname] = ok

    success = sum(results.values())
    log.info("Selesai: %d/%d berhasil.", success, len(sol_files))
    return results


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    if len(sys.argv) == 3:
        ok = instrument_contract(sys.argv[1], sys.argv[2])
        sys.exit(0 if ok else 1)
    else:
        results = run_instrumentation()
        failed = [k for k, v in results.items() if not v]
        if failed:
            log.warning("Gagal: %s", failed)
            sys.exit(1)
        sys.exit(0)