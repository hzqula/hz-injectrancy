"""
STEP 3 - BUG INJECTION
=================================
Menyisipkan pola kerentanan reentrancy ke dalam kontrak yang telah
diinstrumentasi. Menghasilkan dua varian kontrak per base contract:
  - single_function reentrancy
  - cross_function reentrancy

Diadaptasi dari SolidiFI (Ghaleb & Pattabiraman, 2020) dengan
penyesuaian untuk:
  1. Fokus hanya pada kerentanan reentrancy (sesuai proposal)
  2. Template-based injection (bukan all-location injection)
  3. Menghasilkan injection log dalam format JSON

Alur:
  instrumented_contract  →  [bug injection]  →  injected_contract(s)
                                              →  injection_log.json

Referensi proposal Bab 3.5 (Bug Injection)
"""

import os
import re
import json
import shutil
from typing import Optional, Dict, List, Tuple

from config import (
    INSTRUMENTED_DIR,
    INJECTED_DIR,
    BUG_VARIANTS,
    TRACKER_VAR_NAME,
    ORACLE_FUNCTION_NAME,
    LOGS_DIR,
)
from logger import get_logger

log = get_logger("injector")


# ─── Template Bug Reentrancy ───────────────────────────────────────────────────
# Referensi: Proposal Bab 2.2.2 (Jenis-Jenis Reentrancy) &
#            SolidiFI paper Figure 8 (Re-entrancy example)

SINGLE_FUNCTION_TEMPLATE = """
    // [BUG-INJECTED] Single-Function Reentrancy
    // Pola: CEI (Check-Effects-Interactions) dilanggar
    // Transfer dilakukan SEBELUM state diperbarui
    function bug_reentrancy_single(uint256 _amount) public {{
        require({mapping_var}[msg.sender] >= _amount, "Saldo tidak cukup");
        // BUG: external call sebelum state update (pelanggaran CEI)
        (bool success, ) = msg.sender.call{{value: _amount}}("");
        require(success, "Transfer gagal");
        // State seharusnya diperbarui SEBELUM external call
        {mapping_var}[msg.sender] -= _amount;
        {tracker_var} -= _amount;
    }}
"""

CROSS_FUNCTION_TEMPLATE = """
    // [BUG-INJECTED] Cross-Function Reentrancy
    // Pola: Dua fungsi berbagi state yang belum konsisten
    // Fungsi pertama: withdraw tanpa update state
    function bug_reentrancy_cross_withdraw(uint256 _amount) public {{
        require({mapping_var}[msg.sender] >= _amount, "Saldo tidak cukup");
        // BUG: state {mapping_var} belum dikurangi, bisa dieksploitasi oleh
        // fungsi lain (bug_reentrancy_cross_getBalance) yang membaca state ini
        (bool success, ) = msg.sender.call{{value: _amount}}("");
        require(success, "Transfer gagal");
        {mapping_var}[msg.sender] -= _amount;
        {tracker_var} -= _amount;
    }}

    // Fungsi kedua: membaca state yang mungkin belum konsisten
    function bug_reentrancy_cross_getBalance() public view returns (uint256) {{
        // BUG: state bisa dibaca saat cross-function reentrancy terjadi
        return {mapping_var}[msg.sender];
    }}
"""

# Constructor/receive function untuk bug yang memerlukan payable
PAYABLE_CONSTRUCTOR_TEMPLATE = """
    // [INJECTED] Receive function untuk mendukung pengiriman ether
    receive() external payable {{
        {tracker_var} += msg.value;
    }}
"""


# ─── Regex Helper ─────────────────────────────────────────────────────────────

MAPPING_PATTERN = re.compile(
    r"mapping\s*\(\s*address\s*=>\s*uint256\s*\)\s+(?:public\s+|private\s+|internal\s+)?(\w+)\s*;",
    re.IGNORECASE,
)

CONTRACT_BODY_END_PATTERN = re.compile(r"\}\s*$", re.DOTALL)

HAS_RECEIVE_PATTERN = re.compile(
    r"receive\s*\(\s*\)\s+external\s+payable",
    re.MULTILINE,
)

HAS_PAYABLE_FALLBACK = re.compile(
    r"fallback\s*\(\s*\)\s+external\s+payable",
    re.MULTILINE,
)


# ─── Fungsi Pembantu ──────────────────────────────────────────────────────────

def _find_mapping_variable(source: str) -> Optional[str]:
    """
    Mencari nama mapping variabel yang paling relevan.
    Prioritas: nama yang mengandung balance/deposit/contribution.
    """
    matches = MAPPING_PATTERN.findall(source)
    if not matches:
        return None

    priority_kw = ["balance", "deposit", "contribution", "amount", "fund"]
    for kw in priority_kw:
        for name in matches:
            if kw.lower() in name.lower():
                return name

    return matches[0]


def _needs_payable_constructor(source: str) -> bool:
    """
    Mengecek apakah kontrak sudah memiliki receive/fallback payable.
    Jika belum, perlu ditambahkan agar bug dapat dieksekusi.
    """
    has_receive  = bool(HAS_RECEIVE_PATTERN.search(source))
    has_fallback = bool(HAS_PAYABLE_FALLBACK.search(source))
    return not (has_receive or has_fallback)


def _insert_before_last_brace(source: str, code_to_insert: str) -> str:
    """Menyisipkan kode sebelum kurung kurawal penutup terakhir."""
    last_brace = source.rfind("}")
    if last_brace == -1:
        log.error("Tidak menemukan kurung kurawal penutup.")
        return source
    return source[:last_brace] + code_to_insert + "\n" + source[last_brace:]


def _get_injection_line(source: str, pattern: str) -> int:
    """Mendapatkan nomor baris di mana pola ditemukan."""
    lines = source.split("\n")
    for i, line in enumerate(lines, 1):
        if pattern in line:
            return i
    return -1


def _detect_main_contract_name(source: str) -> Optional[str]:
    """Mendeteksi nama kontrak utama (non-interface, non-library)."""
    for line in source.split("\n"):
        stripped = line.strip()
        if stripped.startswith("contract ") and "{" in stripped:
            parts = stripped.split()
            if len(parts) >= 2:
                return parts[1].split("(")[0].split("{")[0].strip()
    return None


# ─── Fungsi Injeksi Per Varian ────────────────────────────────────────────────

def inject_single_function(
    source: str,
    mapping_var: str,
    contract_name: str,
) -> Tuple[str, dict]:
    """
    Menyisipkan bug single-function reentrancy.

    Return:
        (source_dengan_bug, injection_log_entry)
    """
    bug_code = SINGLE_FUNCTION_TEMPLATE.format(
        mapping_var=mapping_var,
        tracker_var=TRACKER_VAR_NAME,
    )

    # Tambahkan receive() jika belum ada
    if _needs_payable_constructor(source):
        receive_code = PAYABLE_CONSTRUCTOR_TEMPLATE.format(
            tracker_var=TRACKER_VAR_NAME
        )
        source = _insert_before_last_brace(source, receive_code)

    injected_source = _insert_before_last_brace(source, bug_code)

    # Cari nomor baris fungsi bug yang disisipkan
    injection_line = _get_injection_line(
        injected_source, "bug_reentrancy_single"
    )

    log_entry = {
        "variant":        "single_function",
        "contract_name":  contract_name,
        "mapping_var":    mapping_var,
        "tracker_var":    TRACKER_VAR_NAME,
        "oracle_function": ORACLE_FUNCTION_NAME,
        "injected_function": "bug_reentrancy_single",
        "injection_line": injection_line,
        "bug_description": (
            "Transfer dilakukan sebelum state diperbarui (pelanggaran CEI). "
            "Penyerang dapat memanggil fungsi ini berulang sebelum saldo dikurangi."
        ),
    }

    return injected_source, log_entry


def inject_cross_function(
    source: str,
    mapping_var: str,
    contract_name: str,
) -> Tuple[str, dict]:
    """
    Menyisipkan bug cross-function reentrancy.

    Return:
        (source_dengan_bug, injection_log_entry)
    """
    bug_code = CROSS_FUNCTION_TEMPLATE.format(
        mapping_var=mapping_var,
        tracker_var=TRACKER_VAR_NAME,
    )

    # Tambahkan receive() jika belum ada
    if _needs_payable_constructor(source):
        receive_code = PAYABLE_CONSTRUCTOR_TEMPLATE.format(
            tracker_var=TRACKER_VAR_NAME
        )
        source = _insert_before_last_brace(source, receive_code)

    injected_source = _insert_before_last_brace(source, bug_code)

    injection_line = _get_injection_line(
        injected_source, "bug_reentrancy_cross_withdraw"
    )

    log_entry = {
        "variant":        "cross_function",
        "contract_name":  contract_name,
        "mapping_var":    mapping_var,
        "tracker_var":    TRACKER_VAR_NAME,
        "oracle_function": ORACLE_FUNCTION_NAME,
        "injected_functions": [
            "bug_reentrancy_cross_withdraw",
            "bug_reentrancy_cross_getBalance",
        ],
        "injection_line": injection_line,
        "bug_description": (
            "Dua fungsi berbagi state yang belum konsisten. "
            "bug_reentrancy_cross_withdraw melakukan transfer sebelum update state, "
            "bug_reentrancy_cross_getBalance membaca state yang mungkin belum konsisten."
        ),
    }

    return injected_source, log_entry


# ─── Dispatcher Utama ─────────────────────────────────────────────────────────

VARIANT_INJECTORS = {
    "single_function": inject_single_function,
    "cross_function":  inject_cross_function,
}


def inject_contract(
    input_path: str,
    output_dir: str,
    variants: List[str] = BUG_VARIANTS,
) -> Dict[str, dict]:
    """
    Menyuntikkan semua varian bug ke satu kontrak.

    Parameter:
        input_path : path ke kontrak terinstrumentasi
        output_dir : direktori output untuk kontrak ter-inject
        variants   : list varian bug yang akan disuntikkan

    Return:
        dict: {"single_function": log_entry, "cross_function": log_entry, ...}
    """
    fname = os.path.basename(input_path)
    stem  = os.path.splitext(fname)[0]   # nama tanpa ekstensi
    results = {}

    if not os.path.isfile(input_path):
        log.error("File tidak ditemukan: %s", input_path)
        return results

    with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
        original_source = f.read()

    # Deteksi nama kontrak dan mapping variabel
    contract_name = _detect_main_contract_name(original_source)
    mapping_var   = _find_mapping_variable(original_source)

    if contract_name is None:
        log.error("Tidak dapat mendeteksi nama kontrak pada: %s", fname)
        return results

    if mapping_var is None:
        log.warning(
            "Tidak ada mapping variabel pada '%s'. "
            "Bug mungkin tidak optimal, menggunakan nama default.", fname
        )
        mapping_var = "balances"  # default fallback

    log.info("  Kontrak : %s | Mapping: %s", contract_name, mapping_var)

    for variant in variants:
        if variant not in VARIANT_INJECTORS:
            log.warning("Varian tidak dikenal: %s", variant)
            continue

        injector = VARIANT_INJECTORS[variant]

        try:
            injected_source, log_entry = injector(
                original_source, mapping_var, contract_name
            )
        except Exception as e:
            log.error("Gagal menyuntikkan varian '%s' pada '%s': %s", variant, fname, e)
            continue

        # Tentukan nama file output
        output_filename = f"{stem}_{variant}.sol"
        output_path     = os.path.join(output_dir, output_filename)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(injected_source)

        log_entry["source_file"]  = fname
        log_entry["output_file"]  = output_filename
        log_entry["output_path"]  = output_path
        log_entry["base_contract"] = stem

        results[variant] = log_entry
        log.info("  ✓ [%s] → %s (injeksi baris %d)",
                 variant, output_filename, log_entry.get("injection_line", -1))

    return results


def run_injection(
    instrumented_dir: str = INSTRUMENTED_DIR,
    output_dir: str       = INJECTED_DIR,
    valid_files: list     = None,
    variants: List[str]   = BUG_VARIANTS,
) -> List[dict]:
    """
    Menjalankan injeksi bug untuk semua kontrak terinstrumentasi yang valid.

    Parameter:
        instrumented_dir : direktori kontrak terinstrumentasi
        output_dir       : direktori output kontrak ter-inject
        valid_files      : list nama file yang lulus verifikasi kompilasi
                           (None = proses semua file .sol di direktori)
        variants         : varian bug yang akan disuntikkan

    Return:
        list semua injection log entries
    """
    os.makedirs(output_dir, exist_ok=True)

    if valid_files is None:
        sol_files = sorted([
            f for f in os.listdir(instrumented_dir)
            if f.endswith(".sol") and not f.startswith(".")
        ])
    else:
        sol_files = sorted(valid_files)

    if not sol_files:
        log.warning("Tidak ada file untuk diproses.")
        return []

    log.info("=" * 60)
    log.info("STEP 3: BUG INJECTION")
    log.info("=" * 60)
    log.info("Jumlah kontrak yang akan diinjeksi: %d", len(sol_files))
    log.info("Varian bug: %s", variants)

    all_logs = []
    total_injected = 0

    for fname in sol_files:
        input_path = os.path.join(instrumented_dir, fname)
        log.info("")
        log.info("Memproses: %s", fname)

        contract_logs = inject_contract(input_path, output_dir, variants)

        for variant, entry in contract_logs.items():
            all_logs.append(entry)
            total_injected += 1

    # ── Simpan injection log ke JSON ──────────────────────────────────────────
    log_path = os.path.join(LOGS_DIR, "injection_log.json")
    os.makedirs(LOGS_DIR, exist_ok=True)
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(all_logs, f, indent=2, ensure_ascii=False)

    log.info("")
    log.info("Total bug berhasil disuntikkan: %d", total_injected)
    log.info("Injection log tersimpan di     : %s", log_path)

    return all_logs


# ─── Entry Point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    if len(sys.argv) == 3:
        # Mode satu file: python step3_injector.py <input.sol> <output_dir/>
        results = inject_contract(sys.argv[1], sys.argv[2])
        if results:
            print(f"Berhasil menyuntikkan {len(results)} varian.")
        else:
            print("Gagal menyuntikkan bug.")
            sys.exit(1)
    else:
        # Mode batch
        logs = run_injection()
        if not logs:
            log.error("Tidak ada bug yang berhasil disuntikkan.")
            sys.exit(1)
        sys.exit(0)