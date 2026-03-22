"""
STEP 1 - INSTRUMENTASI ORACLE
=================================
Menyisipkan mekanisme oracle ke dalam kontrak bersih (base contract).
Oracle adalah fungsi Echidna yang akan mendeteksi pelanggaran invariant
pada saat runtime.

Alur:
  base_contract  →  [instrumentasi]  →  instrumented_contract

Apa yang disisipkan:
  1. State variable pelacak  : uint256 public totalDeposits;
  2. Logika pelacak           : totalDeposits += msg.value;  (pada setiap deposit)
  3. Fungsi oracle Echidna    : function echidna_cek_saldo() public view returns (bool)

Referensi proposal Bab 3.3.2 (Instrumentasi Oracle)
"""

import os
import re
import shutil
from typing import Optional

from config import (
    BASE_CONTRACTS_DIR,
    INSTRUMENTED_DIR,
    TRACKER_VAR_NAME,
    ORACLE_FUNCTION_NAME,
)
from logger import get_logger

log = get_logger("instrumentor")


# ─── Template Kode yang Disisipkan ────────────────────────────────────────────

TRACKER_VAR_TEMPLATE = "    uint256 public {var};\n"

ORACLE_FUNCTION_TEMPLATE = """
    // [ORACLE] Echidna property: saldo kontrak harus >= totalDeposits
    // Pelanggaran invariant ini menandakan aktivasi kerentanan reentrancy
    function {oracle_name}() public view returns (bool) {{
        return address(this).balance >= {var};
    }}
"""


# ─── Utilitas Regex ───────────────────────────────────────────────────────────

# Menemukan mapping(address => uint256) yang berkaitan dengan balance/deposit
MAPPING_PATTERN = re.compile(
    r"mapping\s*\(\s*address\s*=>\s*uint256\s*\)\s+(?:public\s+)?(\w+)\s*;",
    re.IGNORECASE,
)

# Menemukan pembukaan blok kontrak utama (hanya yang bukan interface/library)
CONTRACT_OPEN_PATTERN = re.compile(
    r"^(contract\s+\w+[^{]*)\{",
    re.MULTILINE,
)

# Menemukan penutup blok kontrak (kurung kurawal terakhir)
LAST_BRACE_PATTERN = re.compile(r"\}\s*$", re.DOTALL)

# Menemukan operasi += msg.value  (deposit ether)
DEPOSIT_PATTERN = re.compile(
    r"([\w\[\]\.]+\s*\+=\s*msg\.value\s*;)",
    re.MULTILINE,
)

# payable function yang mungkin menerima ether
PAYABLE_FUNC_PATTERN = re.compile(
    r"function\s+(\w+)\s*\([^)]*\)\s+(?:[a-zA-Z\s]*)?payable(?:[a-zA-Z\s]*)?\{",
    re.MULTILINE,
)


# ─── Fungsi Utama ─────────────────────────────────────────────────────────────

def _find_target_mapping(source: str) -> Optional[str]:
    """
    Mencari nama mapping variabel yang paling relevan untuk dijadikan
    target pelacakan. Prioritas: nama yang mengandung kata 'balance',
    'deposit', 'contribution'. Jika tidak ada, gunakan yang pertama.
    """
    matches = MAPPING_PATTERN.findall(source)
    if not matches:
        return None

    priority_keywords = ["balance", "deposit", "contribution", "amount", "fund"]
    for kw in priority_keywords:
        for name in matches:
            if kw.lower() in name.lower():
                return name

    return matches[0]


def _insert_tracker_variable(source: str, contract_name: str) -> str:
    """
    Menyisipkan variabel pelacak (totalDeposits) tepat setelah
    pembukaan blok kontrak utama.
    """
    # Cari pembukaan blok kontrak (bukan interface/library)
    lines = source.split("\n")
    insert_idx = None

    for i, line in enumerate(lines):
        stripped = line.strip()
        # Tandai baris 'contract NamaKontrak {' (bukan interface/library)
        if (
            stripped.startswith("contract ")
            and contract_name in stripped
            and "{" in stripped
        ):
            insert_idx = i + 1
            break

    if insert_idx is None:
        log.warning("Tidak menemukan blok kontrak '%s', sisipkan di awal file.", contract_name)
        # Fallback: sisipkan setelah baris pragma
        for i, line in enumerate(lines):
            if line.strip().startswith("contract ") and "{" in line:
                insert_idx = i + 1
                break

    if insert_idx is None:
        log.error("Gagal menemukan lokasi sisipan variabel tracker.")
        return source

    tracker_line = TRACKER_VAR_TEMPLATE.format(var=TRACKER_VAR_NAME)
    lines.insert(insert_idx, tracker_line)
    log.debug("Variabel '%s' disisipkan pada baris %d.", TRACKER_VAR_NAME, insert_idx + 1)
    return "\n".join(lines)


def _insert_tracking_logic(source: str, mapping_var: str) -> str:
    """
    Menyisipkan logika pelacak setelah setiap operasi += msg.value
    yang ditemukan dalam kode sumber.
    Tracking: totalDeposits += msg.value;
    """
    tracker_stmt = f"        {TRACKER_VAR_NAME} += msg.value; // [TRACKER]\n"

    def replacer(match):
        original = match.group(1)
        return original + "\n" + tracker_stmt.rstrip()

    result, count = DEPOSIT_PATTERN.subn(replacer, source)
    if count > 0:
        log.debug("Logika pelacak disisipkan pada %d lokasi deposit.", count)
    else:
        log.warning(
            "Tidak ditemukan operasi '+= msg.value'. "
            "Pelacak mungkin tidak optimal untuk kontrak ini."
        )
    return result


def _insert_oracle_function(source: str) -> str:
    """
    Menyisipkan fungsi oracle Echidna sebelum kurung kurawal penutup
    kontrak terakhir.
    """
    oracle_code = ORACLE_FUNCTION_TEMPLATE.format(
        oracle_name=ORACLE_FUNCTION_NAME,
        var=TRACKER_VAR_NAME,
    )

    # Temukan posisi kurung tutup terakhir
    last_brace_pos = source.rfind("}")
    if last_brace_pos == -1:
        log.error("Tidak menemukan kurung kurawal penutup kontrak.")
        return source

    result = source[:last_brace_pos] + oracle_code + "\n" + source[last_brace_pos:]
    log.debug("Fungsi oracle '%s' berhasil disisipkan.", ORACLE_FUNCTION_NAME)
    return result


def _detect_contract_name(source: str) -> Optional[str]:
    """Mendeteksi nama kontrak utama (non-interface, non-library)."""
    for line in source.split("\n"):
        stripped = line.strip()
        if stripped.startswith("contract ") and "{" in stripped:
            # Ambil nama kontrak
            parts = stripped.split()
            if len(parts) >= 2:
                return parts[1].split("(")[0].split("{")[0].strip()
    return None


def instrument_contract(
    input_path: str,
    output_path: str,
) -> bool:
    """
    Melakukan instrumentasi oracle pada satu kontrak.

    Parameter:
        input_path  : path ke kontrak bersih (base contract)
        output_path : path tujuan kontrak yang sudah diinstrumentasi

    Return:
        True  jika berhasil
        False jika gagal
    """
    log.info("Menginstumentasi: %s", os.path.basename(input_path))

    if not os.path.isfile(input_path):
        log.error("File tidak ditemukan: %s", input_path)
        return False

    with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
        source = f.read()

    # ── 1. Deteksi nama kontrak utama ──────────────────────────────────────
    contract_name = _detect_contract_name(source)
    if contract_name is None:
        log.error("Tidak dapat mendeteksi nama kontrak pada: %s", input_path)
        return False
    log.debug("Nama kontrak terdeteksi: %s", contract_name)

    # ── 2. Deteksi mapping variabel target ─────────────────────────────────
    mapping_var = _find_target_mapping(source)
    if mapping_var:
        log.debug("Mapping variabel target: %s", mapping_var)
    else:
        log.warning("Tidak ada mapping variabel ditemukan. Pelacak akan mengandalkan msg.value.")
        mapping_var = "contributors"  # default fallback

    # ── 3. Sisipkan variabel pelacak ───────────────────────────────────────
    source = _insert_tracker_variable(source, contract_name)

    # ── 4. Sisipkan logika pelacak ─────────────────────────────────────────
    source = _insert_tracking_logic(source, mapping_var)

    # ── 5. Sisipkan fungsi oracle ──────────────────────────────────────────
    source = _insert_oracle_function(source)

    # ── 6. Tulis file hasil ────────────────────────────────────────────────
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(source)

    log.info("  ✓ Hasil instrumentasi → %s", os.path.basename(output_path))
    return True


def run_instrumentation(base_dir: str = BASE_CONTRACTS_DIR,
                        output_dir: str = INSTRUMENTED_DIR) -> dict:
    """
    Menjalankan instrumentasi untuk semua kontrak dalam direktori base.

    Return:
        dict berisi hasil per file: {"filename": True/False, ...}
    """
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


# ─── Entry Point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    if len(sys.argv) == 3:
        # Mode satu file: python step1_instrumentor.py <input.sol> <output.sol>
        ok = instrument_contract(sys.argv[1], sys.argv[2])
        sys.exit(0 if ok else 1)
    else:
        # Mode batch: instrumentasi semua kontrak di base_contracts/
        results = run_instrumentation()
        failed = [k for k, v in results.items() if not v]
        if failed:
            log.warning("Gagal: %s", failed)
            sys.exit(1)
        sys.exit(0)