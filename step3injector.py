"""
STEP 3 - BUG INJECTION
=================================
Nyisipin pola kerentanan reentrancy ke dalam kontrak yang udah
diinstrumentasiin. Dan ngasilin dua varian kontrak per base contract:
  - single_function reentrancy
  - cross_function reentrancy
"""

import os
import re
import json
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

# Template Bug Reentrancy

SINGLE_FUNCTION_TEMPLATE = """
    // [INJECTED] Fallback state variable
    {dummy_mapping}

    // [BUG-INJECTED] Single-Function Reentrancy
    // Pola: CEI (Check-Effects-Interactions) dilanggar
    // Transfer dilakukan SEBELUM state diperbarui
    function bug_reentrancy_single(uint256 _amount) public {{
        require(_amount > 0, "Bukan eksploitasi jika amount 0");
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
    // [INJECTED] Fallback state variable
    {dummy_mapping}

    // [BUG-INJECTED] Cross-Function Reentrancy
    // Pola: Dua fungsi berbagi state yang belum konsisten
    // Fungsi pertama: withdraw tanpa update state
    function bug_reentrancy_cross_withdraw(uint256 _amount) public {{
        require(_amount > 0, "Bukan eksploitasi jika amount 0"); 
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

# Constructor/receive function buat bug yang perlu payable
PAYABLE_CONSTRUCTOR_TEMPLATE = """
    // [INJECTED] Receive function untuk mendukung pengiriman ether
    receive() external payable {{
        {tracker_var} += msg.value;
    }}
"""


# Regex

MAPPING_PATTERN = re.compile(
    r"mapping\s*\(\s*address[\s\w]*=>\s*uint(?:256)?[\s\w]*\)\s+(?:public\s+|private\s+|internal\s+)?(\w+)\s*;",
    re.IGNORECASE,
)

HAS_RECEIVE_PATTERN = re.compile(
    r"receive\s*\(\s*\)\s+external\s+payable",
    re.MULTILINE,
)

HAS_PAYABLE_FALLBACK = re.compile(
    r"fallback\s*\(\s*\)\s+external\s+payable",
    re.MULTILINE,
)


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


def _insert_at_end_of_contract(source: str, contract_name: str, code_to_insert: str) -> str:
    """
    Mencari akhir dari kontrak utama yang spesifik menggunakan algoritma
    penghitungan kurung kurawal (brace matching).
    """
    import re
    pattern = r"contract\s+" + re.escape(contract_name) + r"\s*\{"
    match = re.search(pattern, source)
    
    if not match:
        last_brace = source.rfind("}")
        return source[:last_brace] + code_to_insert + "\n" + source[last_brace:]

    start_idx = match.end() - 1
    brace_count = 0
    
    for i in range(start_idx, len(source)):
        if source[i] == '{':
            brace_count += 1
        elif source[i] == '}':
            brace_count -= 1
            if brace_count == 0:
                # KETEMU! Ini adalah penutup dari contract utama
                return source[:i] + "\n" + code_to_insert + "\n" + source[i:]
                
    return source


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


# Fungsi Injeksi Per Varian

def inject_single_function(
    source: str,
    mapping_var: str,
    contract_name: str,
) -> Tuple[str, dict]:
    """Menyisipkan bug single-function reentrancy."""
    
    # Hanya buat mapping palsu JIKA variabelnya bernama "dummyBalancesHZ"
    dummy_code = f"mapping(address => uint256) public {mapping_var};" if mapping_var == "dummyBalancesHZ" else ""

    bug_code = SINGLE_FUNCTION_TEMPLATE.format(
        dummy_mapping=dummy_code, 
        mapping_var=mapping_var,
        tracker_var=TRACKER_VAR_NAME,
    )

    # Tambahkan receive() jika belum ada
    if _needs_payable_constructor(source):
        receive_code = PAYABLE_CONSTRUCTOR_TEMPLATE.format(
            tracker_var=TRACKER_VAR_NAME
        )
        source = _insert_at_end_of_contract(source, contract_name, receive_code)

    injected_source = _insert_at_end_of_contract(source, contract_name, bug_code)

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
    """Menyisipkan bug cross-function reentrancy."""
    
    # Hanya buat mapping palsu JIKA variabelnya bernama "dummyBalancesHZ"
    dummy_code = f"mapping(address => uint256) public {mapping_var};" if mapping_var == "dummyBalancesHZ" else ""

    bug_code = CROSS_FUNCTION_TEMPLATE.format(
        dummy_mapping=dummy_code,     # <--- Tambahan baru
        mapping_var=mapping_var,
        tracker_var=TRACKER_VAR_NAME,
    )

    # Tambahkan receive() jika belum ada
    if _needs_payable_constructor(source):
        receive_code = PAYABLE_CONSTRUCTOR_TEMPLATE.format(
            tracker_var=TRACKER_VAR_NAME
        )
        source = _insert_at_end_of_contract(source, contract_name, receive_code)

    injected_source = _insert_at_end_of_contract(source, contract_name, bug_code)

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


# Dispatcher

VARIANT_INJECTORS = {
    "single_function": inject_single_function,
    "cross_function":  inject_cross_function,
}


def inject_contract(
    input_path: str,
    output_dir: str,
    variants: List[str] = BUG_VARIANTS,
) -> Dict[str, dict]:
    """Menyuntikkan semua varian bug ke satu kontrak."""
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
        mapping_var = "dummyBalancesHZ"

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
    """Menjalankan injeksi bug untuk semua kontrak terinstrumentasi yang valid."""
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

    # Simpan injection log ke JSON
    log_path = os.path.join(LOGS_DIR, "injection_log.json")
    os.makedirs(LOGS_DIR, exist_ok=True)
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(all_logs, f, indent=2, ensure_ascii=False)

    log.info("")
    log.info("Total bug berhasil disuntikkan: %d", total_injected)
    log.info("Injection log tersimpan di     : %s", log_path)

    return all_logs


# Entry Point
if __name__ == "__main__":
    import sys

    if len(sys.argv) == 3:
        results = inject_contract(sys.argv[1], sys.argv[2])
        if results:
            print(f"Berhasil menyuntikkan {len(results)} varian.")
        else:
            print("Gagal menyuntikkan bug.")
            sys.exit(1)
    else:
        logs = run_injection()
        if not logs:
            log.error("Tidak ada bug yang berhasil disuntikkan.")
            sys.exit(1)
        sys.exit(0)