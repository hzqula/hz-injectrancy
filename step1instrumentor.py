"""
STEP 1 - INSTRUMENTASI ORACLE
=================================
Menyisipkan mekanisme oracle ke dalam kontrak bersih (base contract).
Oracle adalah fungsi Echidna yang akan mendeteksi pelanggaran invariant
pada saat runtime.

Alur:
  base_contract  →  [instrumentasi]  →  instrumented_contract

Apa yang disisipkan:
  1. State reentrancy: hz_is_reentered dan hz_locked
  2. Fungsi oracle Echidna : Mengembalikan nilai !hz_is_reentered
"""

import os
import re
from typing import Optional

from config import (
    BASE_CONTRACTS_DIR,
    INSTRUMENTED_DIR,
    ORACLE_FUNCTION_NAME,
)
from logger import get_logger

log = get_logger("instrumentor")


# Template Kode yang Disisipkan

TRACKER_VAR_TEMPLATE = """
    // Deteksi pelacak
    bool public hz_is_reentered = false;
    bool private hz_locked = false;
"""

ORACLE_FUNCTION_TEMPLATE = """
    // [ORACLE] Echidna property
    // Pelanggaran invariant ini menandakan fuzzer berhasil melakukan eksekusi ganda (reentrant)
    function {oracle_name}() public view returns (bool) {{
        return !hz_is_reentered;
    }}
"""

# Utilitas Regex
CONTRACT_OPEN_PATTERN = re.compile(
    r"^(contract\s+\w+[^{]*)\{",
    re.MULTILINE,
)

# Fungsi Utama

def _insert_tracker_variable(source: str, contract_name: str) -> str:
    """
    Menyisipkan variabel pelacak (hz_locked & hz_is_reentered) tepat setelah
    pembukaan blok kontrak utama.
    """
    lines = source.split("\n")
    insert_idx = None

    for i, line in enumerate(lines):
        stripped = line.strip()
        if (
            stripped.startswith("contract ")
            and contract_name in stripped
            and "{" in stripped
        ):
            insert_idx = i + 1
            break

    if insert_idx is None:
        log.warning("Tidak menemukan blok kontrak '%s', sisipkan di awal file.", contract_name)
        for i, line in enumerate(lines):
            if line.strip().startswith("contract ") and "{" in line:
                insert_idx = i + 1
                break

    if insert_idx is None:
        log.error("Gagal menemukan lokasi sisipan variabel pelacak.")
        return source

    lines.insert(insert_idx, TRACKER_VAR_TEMPLATE)
    log.debug("Variabel pelacak disisipkan pada baris %d.", insert_idx + 1)
    return "\n".join(lines)


def _insert_at_end_of_contract(source: str, contract_name: str, code_to_insert: str) -> str:
    """
    Mencari akhir dari kontrak utama yang spesifik menggunakan brace matching.
    """
    import re
    pattern = r"contract\s+" + re.escape(contract_name) + r"\s*\{"
    match = re.search(pattern, source)
    
    if not match:
        last_brace = source.rfind("}")
        return source[:last_brace] + "\n" + code_to_insert + "\n" + source[last_brace:]

    start_idx = match.end() - 1
    brace_count = 0
    
    for i in range(start_idx, len(source)):
        if source[i] == '{':
            brace_count += 1
        elif source[i] == '}':
            brace_count -= 1
            if brace_count == 0:
                return source[:i] + "\n" + code_to_insert + "\n" + source[i:]
                
    return source

def _insert_oracle_function(source: str, contract_name: str) -> str:
    """
    Menyisipkan fungsi oracle Echidna di dalam blok kontrak utama.
    """
    oracle_code = ORACLE_FUNCTION_TEMPLATE.format(
        oracle_name=ORACLE_FUNCTION_NAME
    )
    result = _insert_at_end_of_contract(source, contract_name, oracle_code)
    log.debug("Fungsi oracle '%s' berhasil disisipkan.", ORACLE_FUNCTION_NAME)
    return result


def _detect_contract_name(source: str) -> Optional[str]:
    """Mendeteksi nama kontrak utama (non-interface, non-library)."""
    for line in source.split("\n"):
        stripped = line.strip()
        if stripped.startswith("contract ") and "{" in stripped:
            parts = stripped.split()
            if len(parts) >= 2:
                return parts[1].split("(")[0].split("{")[0].strip()
    return None


def instrument_contract(input_path: str, output_path: str) -> bool:
    log.info("Menginstumentasi: %s", os.path.basename(input_path))

    if not os.path.isfile(input_path):
        log.error("File tidak ditemukan: %s", input_path)
        return False

    with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
        source = f.read()

    contract_name = _detect_contract_name(source)
    if contract_name is None:
        log.error("Tidak dapat mendeteksi nama kontrak pada: %s", input_path)
        return False
    log.debug("Nama kontrak terdeteksi: %s", contract_name)

    # Sisipkan Pelacak & Oracle
    source = _insert_tracker_variable(source, contract_name)
    source = _insert_oracle_function(source, contract_name)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(source)

    log.info("  ✓ Hasil instrumentasi → %s", os.path.basename(output_path))
    return True


def run_instrumentation(base_dir: str = BASE_CONTRACTS_DIR, output_dir: str = INSTRUMENTED_DIR) -> dict:
    os.makedirs(output_dir, exist_ok=True)
    results = {}

    sol_files = sorted([
        f for f in os.listdir(base_dir)
        if f.endswith(".sol") and not f.startswith(".")
    ])

    if not sol_files:
        log.warning("Tidak ada file .sol ditemukan di: %s", base_dir)
        return results

    log.info("=" * 60)
    log.info("STEP 1: INSTRUMENTASI ORACLE")
    log.info("=" * 60)
    log.info("Jumlah kontrak yang akan diinstrumentasi: %d", len(sol_files))

    success_count = 0
    for fname in sol_files:
        input_path  = os.path.join(base_dir, fname)
        output_path = os.path.join(output_dir, fname)
        ok = instrument_contract(input_path, output_path)
        results[fname] = ok
        if ok:
            success_count += 1

    log.info("")
    log.info("Instrumentasi selesai: %d/%d berhasil", success_count, len(sol_files))
    return results

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