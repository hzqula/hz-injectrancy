"""
STEP 3 — BUG INJECTION
=========================
Menyisipkan pola kerentanan reentrancy ke dalam kontrak yang sudah
diinstrumentasi. Menghasilkan dua varian kontrak per base contract:
    - single_function  : reentrancy dalam satu fungsi
    - cross_function   : reentrancy antar dua fungsi
"""

import os
import re
import json
from typing import Dict, List, Optional, Tuple

from config import (
    INSTRUMENTED_DIR,
    INJECTED_DIR,
    BUG_VARIANTS,
    ORACLE_FUNCTION_NAME,
    LOGS_DIR,
)
from logger import get_logger

log = get_logger("injector")


# ---------------------------------------------------------------------------
# Template bug reentrancy
# ---------------------------------------------------------------------------

# Placeholder {dummy_mapping} diisi hanya jika tidak ada mapping asli di kontrak.
# Placeholder {mapping_var} adalah nama variabel mapping yang digunakan.

SINGLE_FUNCTION_TEMPLATE = """
    // [INJECTED] Mapping saldo (diisi otomatis jika tidak ada di kontrak asli)
    {dummy_mapping}

    // [BUG] Single-Function Reentrancy
    // Transfer dilakukan SEBELUM state diperbarui → melanggar pola CEI
    function bug_reentrancy_single(uint256 _amount) public {{
        // Isi saldo otomatis agar Echidna bisa mencapai fase reentrancy
        if ({mapping_var}[msg.sender] < _amount) {{
            unchecked {{ {mapping_var}[msg.sender] += _amount; }}
        }}

        require(_amount > 0,                              "Amount harus > 0");
        require({mapping_var}[msg.sender] >= _amount,     "Saldo tidak cukup");

        // Jika fungsi dipanggil kembali saat masih terkunci → bug terpicu
        if (hz_locked) {{ hz_is_reentered = true; }}
        hz_locked = true;

        (bool success, ) = msg.sender.call{{value: _amount}}("");
        require(success, "Transfer gagal");

        // unchecked: nonaktifkan proteksi underflow bawaan Solidity 0.8+
        unchecked {{ {mapping_var}[msg.sender] -= _amount; }}

        hz_locked = false;
    }}
"""

CROSS_FUNCTION_TEMPLATE = """
    // [INJECTED] Mapping saldo (diisi otomatis jika tidak ada di kontrak asli)
    {dummy_mapping}

    // [BUG] Cross-Function Reentrancy — fungsi penarikan
    // State belum diperbarui saat external call dilakukan
    function bug_reentrancy_cross_withdraw(uint256 _amount) public {{
        if ({mapping_var}[msg.sender] < _amount) {{
            unchecked {{ {mapping_var}[msg.sender] += _amount; }}
        }}

        require(_amount > 0,                          "Amount harus > 0");
        require({mapping_var}[msg.sender] >= _amount, "Saldo tidak cukup");

        if (hz_locked) {{ hz_is_reentered = true; }}
        hz_locked = true;

        (bool success, ) = msg.sender.call{{value: _amount}}("");
        require(success, "Transfer gagal");

        unchecked {{ {mapping_var}[msg.sender] -= _amount; }}

        hz_locked = false;
    }}

    // [BUG] Cross-Function Reentrancy — fungsi pembaca saldo
    // Membaca state yang mungkin belum konsisten akibat reentrancy di atas
    function bug_reentrancy_cross_getBalance() public view returns (uint256) {{
        return {mapping_var}[msg.sender];
    }}
"""

RECEIVE_FUNCTION_TEMPLATE = """
    // [INJECTED] Receive function agar kontrak dapat menerima Ether
    receive() external payable {{}}
"""


# ---------------------------------------------------------------------------
# Pola regex
# ---------------------------------------------------------------------------

# Mendeteksi mapping(address => uint) yang umum digunakan sebagai saldo
_MAPPING_PATTERN = re.compile(
    r"mapping\s*\(\s*address[\s\w]*=>\s*uint(?:256)?[\s\w]*\)\s+"
    r"(?:public\s+|private\s+|internal\s+)?(\w+)\s*;",
    re.IGNORECASE,
)
_HAS_RECEIVE    = re.compile(r"receive\s*\(\s*\)\s+external\s+payable",  re.MULTILINE)
_HAS_FALLBACK   = re.compile(r"fallback\s*\(\s*\)\s+external\s+payable", re.MULTILINE)


# ---------------------------------------------------------------------------
# Utilitas internal
# ---------------------------------------------------------------------------

def _detect_main_contract_name(source: str) -> Optional[str]:
    """Mendeteksi nama kontrak pertama (bukan interface/library)."""
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("contract ") and "{" in stripped:
            parts = stripped.split()
            if len(parts) >= 2:
                return parts[1].split("(")[0].split("{")[0].strip()
    return None


def _find_mapping_variable(source: str) -> Optional[str]:
    """
    Mencari nama variabel mapping(address => uint) yang paling relevan.
    Prioritas: kata kunci semantik seperti 'balance', 'deposit', dll.
    """
    matches = _MAPPING_PATTERN.findall(source)
    if not matches:
        return None

    priority_keywords = ["balance", "deposit", "contribution", "amount", "fund"]
    for kw in priority_keywords:
        for name in matches:
            if kw.lower() in name.lower():
                return name

    return matches[0]


def _needs_receive_function(source: str) -> bool:
    """Mengembalikan True jika kontrak belum memiliki receive() atau fallback() payable."""
    return not (_HAS_RECEIVE.search(source) or _HAS_FALLBACK.search(source))


def _insert_before_contract_close(source: str, contract_name: str, code: str) -> str:
    """Menyisipkan *code* tepat sebelum kurung kurawal penutup kontrak."""
    pattern = r"contract\s+" + re.escape(contract_name) + r"\s*\{"
    match = re.search(pattern, source)

    if not match:
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


def _find_injection_line(source: str, marker: str) -> int:
    """Mengembalikan nomor baris tempat *marker* pertama kali muncul, atau -1."""
    for i, line in enumerate(source.splitlines(), start=1):
        if marker in line:
            return i
    return -1


# ---------------------------------------------------------------------------
# Injeksi per varian
# ---------------------------------------------------------------------------

def inject_single_function(
    source: str,
    mapping_var: str,
    contract_name: str,
) -> Tuple[str, dict]:
    """Menyuntikkan pola single-function reentrancy."""
    dummy = (
        f"mapping(address => uint256) public {mapping_var};"
        if mapping_var == "dummyBalancesHZ" else ""
    )

    if _needs_receive_function(source):
        source = _insert_before_contract_close(source, contract_name, RECEIVE_FUNCTION_TEMPLATE)

    source = _insert_before_contract_close(
        source,
        contract_name,
        SINGLE_FUNCTION_TEMPLATE.format(dummy_mapping=dummy, mapping_var=mapping_var),
    )

    log_entry = {
        "variant":           "single_function",
        "contract_name":     contract_name,
        "mapping_var":       mapping_var,
        "oracle_function":   ORACLE_FUNCTION_NAME,
        "injected_function": "bug_reentrancy_single",
        "injection_line":    _find_injection_line(source, "bug_reentrancy_single"),
        "bug_description": (
            "Transfer dilakukan sebelum state diperbarui (melanggar pola CEI). "
            "Penyerang dapat memanggil fungsi ini berulang kali sebelum saldo dikurangi."
        ),
    }
    return source, log_entry


def inject_cross_function(
    source: str,
    mapping_var: str,
    contract_name: str,
) -> Tuple[str, dict]:
    """Menyuntikkan pola cross-function reentrancy."""
    dummy = (
        f"mapping(address => uint256) public {mapping_var};"
        if mapping_var == "dummyBalancesHZ" else ""
    )

    if _needs_receive_function(source):
        source = _insert_before_contract_close(source, contract_name, RECEIVE_FUNCTION_TEMPLATE)

    source = _insert_before_contract_close(
        source,
        contract_name,
        CROSS_FUNCTION_TEMPLATE.format(dummy_mapping=dummy, mapping_var=mapping_var),
    )

    log_entry = {
        "variant":            "cross_function",
        "contract_name":      contract_name,
        "mapping_var":        mapping_var,
        "oracle_function":    ORACLE_FUNCTION_NAME,
        "injected_functions": [
            "bug_reentrancy_cross_withdraw",
            "bug_reentrancy_cross_getBalance",
        ],
        "injection_line": _find_injection_line(source, "bug_reentrancy_cross_withdraw"),
        "bug_description": (
            "Dua fungsi berbagi state yang belum konsisten. "
            "bug_reentrancy_cross_withdraw melakukan transfer sebelum update state; "
            "bug_reentrancy_cross_getBalance membaca state yang mungkin belum konsisten."
        ),
    }
    return source, log_entry


# Dispatcher varian → fungsi injeksi
_VARIANT_INJECTORS = {
    "single_function": inject_single_function,
    "cross_function":  inject_cross_function,
}


# ---------------------------------------------------------------------------
# Fungsi publik
# ---------------------------------------------------------------------------

def inject_contract(
    input_path: str,
    output_dir: str,
    variants: List[str] = BUG_VARIANTS,
) -> Dict[str, dict]:
    """
    Menyuntikkan bug reentrancy ke dalam satu kontrak dengan beberapa varian.

    Args:
        input_path : Path ke file .sol terinstrumentasi.
        output_dir : Direktori output untuk file hasil injeksi.
        variants   : Daftar varian bug yang akan disuntikkan.

    Returns:
        Dict { variant: log_entry } untuk setiap varian yang berhasil.
    """
    fname = os.path.basename(input_path)
    stem  = os.path.splitext(fname)[0]
    results: Dict[str, dict] = {}

    if not os.path.isfile(input_path):
        log.error("File tidak ditemukan: %s", input_path)
        return results

    with open(input_path, encoding="utf-8", errors="ignore") as f:
        original_source = f.read()

    contract_name = _detect_main_contract_name(original_source)
    if contract_name is None:
        log.error("Tidak dapat mendeteksi nama kontrak: %s", fname)
        return results

    mapping_var = _find_mapping_variable(original_source)
    if mapping_var is None:
        log.warning("Mapping tidak ditemukan di '%s', gunakan nama default.", fname)
        mapping_var = "dummyBalancesHZ"

    log.info("  Kontrak: %-30s  Mapping: %s", contract_name, mapping_var)

    for variant in variants:
        injector = _VARIANT_INJECTORS.get(variant)
        if injector is None:
            log.warning("Varian tidak dikenal: %s", variant)
            continue

        try:
            injected_source, entry = injector(original_source, mapping_var, contract_name)
        except Exception as e:
            log.error("Gagal menyuntikkan varian '%s' pada '%s': %s", variant, fname, e)
            continue

        output_filename = f"{stem}_{variant}.sol"
        output_path     = os.path.join(output_dir, output_filename)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(injected_source)

        entry.update({
            "source_file":   fname,
            "output_file":   output_filename,
            "output_path":   output_path,
            "base_contract": stem,
        })
        results[variant] = entry

        log.info("  ✓ [%-16s] → %s  (baris %d)",
                 variant, output_filename, entry.get("injection_line", -1))

    return results


def run_injection(
    instrumented_dir: str = INSTRUMENTED_DIR,
    output_dir: str       = INJECTED_DIR,
    valid_files: list     = None,
    variants: List[str]   = BUG_VARIANTS,
) -> List[dict]:
    """
    Menyuntikkan bug reentrancy ke semua kontrak valid.

    Args:
        instrumented_dir : Direktori kontrak terinstrumentasi.
        output_dir       : Direktori output kontrak ter-inject.
        valid_files      : Daftar nama file yang akan diproses (None = semua).
        variants         : Varian bug yang akan disuntikkan.

    Returns:
        List semua log_entry dari injeksi yang berhasil.
    """
    os.makedirs(output_dir, exist_ok=True)

    if valid_files is None:
        sol_files = sorted(
            f for f in os.listdir(instrumented_dir)
            if f.endswith(".sol") and not f.startswith(".")
        )
    else:
        sol_files = sorted(valid_files)

    if not sol_files:
        log.warning("Tidak ada file untuk diproses.")
        return []

    log.info("=" * 60)
    log.info("STEP 3: BUG INJECTION")
    log.info("=" * 60)
    log.info("Total kontrak : %d", len(sol_files))
    log.info("Varian        : %s", variants)

    all_logs: List[dict] = []
    for fname in sol_files:
        log.info("")
        log.info("Memproses: %s", fname)
        for entry in inject_contract(os.path.join(instrumented_dir, fname), output_dir, variants).values():
            all_logs.append(entry)

    log_path = os.path.join(LOGS_DIR, "injection_log.json")
    os.makedirs(LOGS_DIR, exist_ok=True)
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(all_logs, f, indent=2, ensure_ascii=False)

    log.info("")
    log.info("Total bug disuntikkan : %d", len(all_logs))
    log.info("Injection log         : %s", log_path)
    return all_logs


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    if len(sys.argv) == 3:
        results = inject_contract(sys.argv[1], sys.argv[2])
        print(f"Berhasil menyuntikkan {len(results)} varian." if results else "Gagal menyuntikkan bug.")
        sys.exit(0 if results else 1)
    else:
        logs = run_injection()
        sys.exit(0 if logs else 1)