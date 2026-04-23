"""
STEP 4 — PENGUJIAN DENGAN ECHIDNA
====================================
Menjalankan Echidna property-based fuzzer pada setiap kontrak yang
telah disuntikkan bug reentrancy.

Untuk setiap kontrak, pipeline:
    1. Membuat wrapper attacker + proxy Echidna secara otomatis
    2. Menghasilkan konfigurasi YAML Echidna
    3. Menjalankan Echidna dan mem-parsing hasilnya
    4. Menyimpan log teks dan JSON hasil akhir
"""

import os
import re
import json
import subprocess
import time
import yaml
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

from config import (
    INJECTED_DIR,
    ECHIDNA_RESULTS_DIR,
    ECHIDNA_CONFIG,
    LOGS_DIR,
    ORACLE_FUNCTION_NAME,
    ECHIDNA_TIMEOUT,
    RPC_URL,
)
from logger import get_logger

log = get_logger("echidna_runner")


# ---------------------------------------------------------------------------
# Data class hasil Echidna
# ---------------------------------------------------------------------------

@dataclass
class EchidnaResult:
    source_file:        str   = ""
    contract_name:      str   = ""
    variant:            str   = ""
    status:             str   = "UNKNOWN"
    property_broken:    bool  = False
    detection_time_sec: float = -1.0
    lines_covered:      List[int] = field(default_factory=list)
    bug_line_hit:       bool  = False
    echidna_stdout:     str   = ""
    echidna_stderr:     str   = ""
    error_message:      str   = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Konfigurasi YAML Echidna
# ---------------------------------------------------------------------------

def _generate_echidna_config(output_dir: str, contract_path: str, wrapper_path: Optional[str]) -> str:
    """
    Membuat file echidna_config.yaml di *output_dir*.
    Menambahkan rpcUrl jika kontrak menggunakan Chainlink atau oracle eksternal.
    """
    config = {
        "testLimit":       ECHIDNA_CONFIG["testLimit"],
        "seqLen":          ECHIDNA_CONFIG["seqLen"],
        "shrinkLimit":     ECHIDNA_CONFIG["shrinkLimit"],
        "coverage":        True,
        "corpusDir":       os.path.abspath(os.path.join(output_dir, "corpus")),
        "timeout":         ECHIDNA_CONFIG["timeout"],
        "deployer":        ECHIDNA_CONFIG["deployer"],
        "sender":          ECHIDNA_CONFIG["sender"],
        "balanceAddr":     ECHIDNA_CONFIG["balanceAddr"],
        "balanceContract": ECHIDNA_CONFIG["balanceContract"],
        "testMode":        "property",
    }

    if "maxTimeDelay" in ECHIDNA_CONFIG:
        config["maxTimeDelay"] = ECHIDNA_CONFIG["maxTimeDelay"]

    # Tambahkan RPC URL jika ada referensi ke Chainlink / oracle eksternal
    chainlink_markers = [
        "0x694AA1769357215DE4FAC081bf1f309aDC325306",
        "Chainlink",
        "AggregatorV3Interface",
    ]
    paths_to_check = [p for p in [contract_path, wrapper_path] if p]
    needs_rpc = any(
        any(marker in open(p, encoding="utf-8").read() for marker in chainlink_markers)
        for p in paths_to_check
        if os.path.exists(p)
    )

    if RPC_URL and needs_rpc:
        config["rpcUrl"] = RPC_URL

    config_path = os.path.join(output_dir, "echidna_config.yaml")
    with open(config_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False)
    return config_path


# ---------------------------------------------------------------------------
# Parsing output Echidna
# ---------------------------------------------------------------------------

def _parse_echidna_output(stdout: str, stderr: str) -> Tuple[bool, float, bool]:
    """
    Mem-parsing output Echidna untuk menentukan:
        - property_broken : apakah oracle property dilanggar
        - detection_time  : waktu deteksi (detik), -1 jika tidak terdeteksi
        - bug_line_hit    : apakah baris bug berhasil dieksekusi
    """
    combined = stdout + "\n" + stderr

    property_broken = bool(
        re.search(rf"{re.escape(ORACLE_FUNCTION_NAME)}.*failed", combined, re.IGNORECASE)
    )

    detection_time = -1.0
    if property_broken:
        time_match = re.search(r"elapsed.*?(\d+\.?\d*)\s*s", combined, re.IGNORECASE)
        if time_match:
            detection_time = float(time_match.group(1))

    bug_line_hit = property_broken and "bug_reentrancy" in combined

    return property_broken, detection_time, bug_line_hit


# ---------------------------------------------------------------------------
# Deteksi nama kontrak
# ---------------------------------------------------------------------------

def _detect_contract_name(filepath: str) -> Optional[str]:
    """Membaca file dan mengembalikan nama kontrak pertama yang ditemukan."""
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            for line in f.read().splitlines():
                s = line.strip()
                if s.startswith("contract ") and "{" in s:
                    parts = s.split()
                    if len(parts) >= 2:
                        return parts[1].split("(")[0].split("{")[0].strip()
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Pembuatan wrapper Echidna
# ---------------------------------------------------------------------------

def _build_constructor_args(source: str) -> str:
    """
    Mem-parsing parameter konstruktor dan menghasilkan argumen dummy
    yang sesuai dengan tipe data masing-masing parameter.
    """
    match = re.search(r"constructor\s*\((.*?)\)", source, re.DOTALL)
    if not match or not match.group(1).strip():
        return ""

    params = [p.strip() for p in match.group(1).strip().split(",") if p.strip()]
    dummy_args = []

    for param in params:
        parts     = param.split()
        type_raw  = parts[0].strip()
        type_lower = type_raw.lower()
        name_lower = parts[-1].lower() if len(parts) > 1 else ""

        if "[]" in type_lower:
            dummy_args.append(f"new {type_raw.split('[')[0]}[](0)")
        elif "uint" in type_lower or "int" in type_lower:
            value = "9999999999" if any(kw in name_lower for kw in ["time", "deadline", "duration", "end"]) else "1000"
            dummy_args.append(value)
        elif "address" in type_lower:
            if "payable" in param.lower():
                dummy_args.append("payable(address(0x10000))")
            elif any(kw in name_lower for kw in ["price", "feed", "oracle", "aggregator"]):
                dummy_args.append("address(0x694AA1769357215DE4FAC081bf1f309aDC325306)")
            else:
                dummy_args.append("address(0x10000)")
        elif "bytes32" in type_lower:
            dummy_args.append("bytes32(0)")
        elif "bytes" in type_lower:
            dummy_args.append('""')
        elif "bool" in type_lower:
            dummy_args.append("true")
        elif "string" in type_lower:
            dummy_args.append('"Test"')
        else:
            dummy_args.append(f"{type_raw}(address(0))")

    return ", ".join(dummy_args)


def _create_echidna_wrapper(
    contract_path: str,
    result_dir: str,
    contract_name: str,
    variant: str,
) -> Optional[str]:
    """
    Membuat file wrapper Solidity yang berisi:
        - EchidnaAttacker_{name} : kontrak penyerang dengan fallback reentrancy
        - {name}Echidna          : kontrak wrapper yang diuji langsung oleh Echidna

    Returns:
        Path ke file wrapper, atau None jika gagal.
    """
    with open(contract_path, encoding="utf-8") as f:
        source = f.read()

    args_string   = _build_constructor_args(source)
    target_func   = "bug_reentrancy_single" if variant == "single_function" else "bug_reentrancy_cross_withdraw"
    wrapper_name  = f"{contract_name}Echidna"
    wrapper_fname = f"{os.path.basename(contract_path).replace('.sol', '')}_wrapper.sol"
    wrapper_path  = os.path.join(result_dir, wrapper_fname)

    wrapper_code = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "../../injected_contracts/{os.path.basename(contract_path)}";

// Kontrak penyerang — memicu reentrancy melalui fallback receive()
contract EchidnaAttacker_{contract_name} {{
    {contract_name} public target;
    bool private isAttacking;

    constructor({contract_name} _target) {{
        target = _target;
    }}

    function attack(uint256 amount) public {{
        target.{target_func}(amount);
    }}

    // Fallback: dipanggil saat menerima Ether → balik ke target (reentrancy)
    receive() external payable {{
        if (!isAttacking) {{
            isAttacking = true;
            try target.{target_func}(msg.value) {{}} catch {{}}
            isAttacking = false;
        }}
    }}
}}

// Wrapper yang diuji langsung oleh Echidna
contract {wrapper_name} is {contract_name} {{
    EchidnaAttacker_{contract_name} public attacker;

    // payable agar Echidna dapat memberikan modal ETH saat deploy
    constructor() payable {contract_name}({args_string}) {{
        attacker = new EchidnaAttacker_{contract_name}(this);
    }}

    // Tombol fuzzer — dipanggil Echidna untuk memulai serangan
    function fuzz_attack(uint256 amount) public {{
        amount = (amount % 10 ether) + 1;  // Batasi maksimum 10 ether
        attacker.attack(amount);
    }}
}}
"""
    with open(wrapper_path, "w", encoding="utf-8") as f:
        f.write(wrapper_code)

    return wrapper_path


# ---------------------------------------------------------------------------
# Pemeriksaan coverage corpus
# ---------------------------------------------------------------------------

def _check_corpus_coverage(result_dir: str) -> bool:
    """
    Memeriksa direktori corpus Echidna untuk mendeteksi apakah
    baris external call pada fungsi bug berhasil dieksekusi.
    """
    corpus_dir = os.path.join(result_dir, "corpus")
    if not os.path.exists(corpus_dir):
        return False

    for root, _, files in os.walk(corpus_dir):
        for fname in files:
            if not (fname.startswith("covered.") and fname.endswith(".txt")):
                continue
            try:
                with open(os.path.join(root, fname), encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if "msg.sender.call{value:" not in line:
                            continue
                        parts = line.split("|")
                        if len(parts) >= 2:
                            marker = parts[1].strip()
                            if any(c in marker for c in ("*", "r", "e")):
                                return True
            except Exception:
                continue

    return False


# ---------------------------------------------------------------------------
# Fungsi utama pengujian satu kontrak
# ---------------------------------------------------------------------------

def run_echidna_on_contract(contract_path: str, result_dir: str, variant: str) -> EchidnaResult:
    """
    Menjalankan Echidna pada satu file kontrak ter-inject.

    Args:
        contract_path : Path ke file .sol ter-inject.
        result_dir    : Direktori output untuk log dan corpus.
        variant       : Varian bug ("single_function" atau "cross_function").

    Returns:
        EchidnaResult berisi status dan metrik deteksi.
    """
    fname         = os.path.basename(contract_path)
    contract_name = _detect_contract_name(contract_path)

    result = EchidnaResult(
        source_file=fname,
        contract_name=contract_name or "UNKNOWN",
        variant=variant,
    )

    if not os.path.isfile(contract_path):
        result.status        = "ERROR"
        result.error_message = f"File tidak ditemukan: {contract_path}"
        log.error(result.error_message)
        return result

    os.makedirs(result_dir, exist_ok=True)

    wrapper_path  = _create_echidna_wrapper(contract_path, result_dir, contract_name, variant)
    config_path   = _generate_echidna_config(result_dir, contract_path, wrapper_path)

    # Gunakan wrapper sebagai target Echidna
    target_path  = wrapper_path or contract_path
    target_name  = f"{contract_name}Echidna" if wrapper_path else contract_name

    if wrapper_path:
        log.info("  [wrapper] %s", os.path.basename(wrapper_path))

    cmd = ["echidna", target_path, "--config", config_path, "--format", "text"]
    if target_name:
        cmd += ["--contract", target_name]

    log.info("  Menjalankan Echidna: %s [%s]", fname, variant)

    start = time.time()
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=ECHIDNA_TIMEOUT
        )
        elapsed = time.time() - start

        result.echidna_stdout = proc.stdout
        result.echidna_stderr = proc.stderr

        property_broken, detection_time, bug_line_hit = _parse_echidna_output(
            proc.stdout, proc.stderr
        )

        # Cek coverage corpus sebagai fallback jika parsing output tidak cukup
        if not bug_line_hit:
            bug_line_hit = _check_corpus_coverage(result_dir)

        result.property_broken  = property_broken
        result.bug_line_hit     = bug_line_hit

        if proc.returncode != 0 and not property_broken:
            result.status        = "ERROR"
            last_err             = proc.stderr.strip().splitlines()[-1] if proc.stderr else "Unknown"
            result.error_message = f"Echidna crash: {last_err}"
            log.error("  ✗ ERROR: %s", result.error_message)
        else:
            if property_broken:
                result.status             = "DETECTED"
                result.detection_time_sec = detection_time if detection_time >= 0 else elapsed
                log.info("  DETECTED   : YES  (%.2fs)", result.detection_time_sec)
            elif bug_line_hit:
                result.status             = "ACTIVATED"
                result.detection_time_sec = ECHIDNA_TIMEOUT
                log.info("  DETECTED   : NO")
                log.info("  ACTIVATED  : YES")
            else:
                result.status             = "NOT_DETECTED"
                result.detection_time_sec = ECHIDNA_TIMEOUT
                log.info("  DETECTED   : NO")
                log.info("  ACTIVATED  : NO")

    except subprocess.TimeoutExpired:
        result.status             = "TIMEOUT"
        result.detection_time_sec = ECHIDNA_TIMEOUT
        result.error_message      = f"Timeout setelah {ECHIDNA_TIMEOUT}s"
        log.warning("  ⏱ TIMEOUT: %s", fname)

    except FileNotFoundError:
        result.status        = "ERROR"
        result.error_message = "Echidna tidak ditemukan. Pastikan Echidna terinstall."
        log.error("  ✗ ERROR: %s", result.error_message)

    except Exception as e:
        result.status        = "ERROR"
        result.error_message = str(e)
        log.error("  ✗ ERROR: %s", e)

    # Simpan log teks mentah
    log_txt = os.path.join(result_dir, f"{os.path.splitext(fname)[0]}_echidna.txt")
    with open(log_txt, "w", encoding="utf-8") as f:
        f.write("=== STDOUT ===\n")
        f.write(result.echidna_stdout)
        f.write("\n=== STDERR ===\n")
        f.write(result.echidna_stderr)

    return result


# ---------------------------------------------------------------------------
# Fungsi batch pengujian semua kontrak
# ---------------------------------------------------------------------------

def run_echidna_all(
    injected_dir: str   = INJECTED_DIR,
    results_dir: str    = ECHIDNA_RESULTS_DIR,
    injection_log: list = None,
) -> List[EchidnaResult]:
    """
    Menjalankan Echidna pada semua kontrak ter-inject di *injected_dir*.

    Args:
        injected_dir  : Direktori kontrak ter-inject.
        results_dir   : Direktori output hasil Echidna.
        injection_log : Metadata injeksi untuk pemetaan varian per file.

    Returns:
        List EchidnaResult untuk setiap kontrak yang diuji.
    """
    os.makedirs(results_dir, exist_ok=True)

    # Bangun lookup variant dari injection log
    variant_lookup: Dict[str, str] = {}
    if injection_log:
        for entry in injection_log:
            output_file = entry.get("output_file", "")
            if output_file:
                variant_lookup[output_file] = entry.get("variant", "unknown")

    sol_files = sorted(
        f for f in os.listdir(injected_dir)
        if f.endswith(".sol") and not f.startswith(".")
    )

    if not sol_files:
        log.warning("Tidak ada kontrak ter-inject di: %s", injected_dir)
        return []

    log.info("=" * 60)
    log.info("STEP 4: PENGUJIAN DENGAN ECHIDNA")
    log.info("=" * 60)
    log.info("Total kontrak: %d", len(sol_files))

    all_results: List[EchidnaResult] = []

    for fname in sol_files:
        # Tentukan varian dari lookup atau nama file
        variant = variant_lookup.get(fname, "unknown")
        if variant == "unknown":
            if "single_function" in fname:
                variant = "single_function"
            elif "cross_function" in fname:
                variant = "cross_function"

        result_subdir = os.path.join(results_dir, os.path.splitext(fname)[0])
        os.makedirs(result_subdir, exist_ok=True)

        log.info("")
        log.info("Menguji: %s", fname)

        r = run_echidna_on_contract(
            os.path.join(injected_dir, fname), result_subdir, variant
        )
        all_results.append(r)

    # Simpan semua hasil ke JSON
    results_log_path = os.path.join(LOGS_DIR, "echidna_results.json")
    os.makedirs(LOGS_DIR, exist_ok=True)
    with open(results_log_path, "w", encoding="utf-8") as f:
        json.dump([r.to_dict() for r in all_results], f, indent=2, ensure_ascii=False)

    # Ringkasan
    exploited   = sum(1 for r in all_results if r.bug_line_hit and r.property_broken)
    neutralized = sum(1 for r in all_results if r.bug_line_hit and not r.property_broken)
    unreachable = sum(1 for r in all_results if not r.bug_line_hit and not r.property_broken
                      and r.status not in ("TIMEOUT", "ERROR"))
    native_bug  = sum(1 for r in all_results if not r.bug_line_hit and r.property_broken)
    timeout     = sum(1 for r in all_results if r.status == "TIMEOUT")
    error       = sum(1 for r in all_results if r.status == "ERROR")

    log.info("")
    log.info("Ringkasan Analisis Keamanan:")
    log.info("  EXPLOITED   (Act: YES, Det: YES) : %d", exploited)
    log.info("  NEUTRALIZED (Act: YES, Det: NO ) : %d", neutralized)
    log.info("  UNREACHABLE (Act: NO , Det: NO ) : %d", unreachable)
    log.info("  NATIVE_BUG  (Act: NO , Det: YES) : %d", native_bug)
    log.info("  " + "-" * 40)
    log.info("  TIMEOUT                          : %d", timeout)
    log.info("  ERROR                            : %d", error)
    log.info("Hasil tersimpan di: %s", results_log_path)

    return all_results


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    if len(sys.argv) == 2:
        r = run_echidna_on_contract(sys.argv[1], ECHIDNA_RESULTS_DIR, variant="unknown")
        print(f"Status   : {r.status}")
        print(f"Detected : {r.property_broken}")
    else:
        results = run_echidna_all()
        sys.exit(0 if results else 1)