"""
STEP 4 - PENGUJIAN DENGAN ECHIDNA
=================================
Jalanin Echidna property-based fuzzer pada setiap kontrak yang
telah disuntikkan bug reentrancy.

Echidna bakal:
  1. Bacain kontrak yang udah diinstrumentasi + disuntikkan bug
  2. Jalanin fuzzing buat nyari pelanggaran property
  3. Melaporkan jika oracle echidna_cek_saldo() bernilai FALSE
     (artinya saldo kontrak < totalDeposits → bug aktif)

Metrik yang diukur:
  - Detection Rate   : apakah Echidna melaporkan FAILED pada property
  - Activation Rate  : apakah baris bug tercapai dalam corpus coverage
  - Detection Time   : waktu hingga property dilanggar pertama kali
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


# Data Classes 

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


# Konfigurasi YAML Echidna

def _generate_echidna_config(output_path: str, contract_path: str, wrapper_path: Optional[str]) -> str:
    """
    Menghasilkan file konfigurasi YAML untuk Echidna.
    """
    config_data = {
        "testLimit":      ECHIDNA_CONFIG["testLimit"],
        "seqLen":         ECHIDNA_CONFIG["seqLen"],
        "shrinkLimit":    ECHIDNA_CONFIG["shrinkLimit"],
        "coverage":       True, # PAKSA TRUE AGAR BISA MEMBACA ACTIVATED
        "corpusDir":      os.path.abspath(os.path.join(output_path, "corpus")), # BUKU RAHASIA COVERAGE ECHIDNA
        "timeout":        ECHIDNA_CONFIG["timeout"],
        "deployer":       ECHIDNA_CONFIG["deployer"],
        "sender":         ECHIDNA_CONFIG["sender"],
        "balanceAddr":    ECHIDNA_CONFIG["balanceAddr"],
        "balanceContract": ECHIDNA_CONFIG["balanceContract"],
        "testMode":       "property",
    }

    if "maxTimeDelay" in ECHIDNA_CONFIG:
        config_data["maxTimeDelay"] = ECHIDNA_CONFIG["maxTimeDelay"]

    needs_rpc = False

    files_to_check = [contract_path]
    if wrapper_path:
        files_to_check.append(wrapper_path)

    for filepath in files_to_check:
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
                if "0x694AA1769357215DE4FAC081bf1f309aDC325306" in content or "Chainlink" in content or "AggregatorV3Interface" in content:
                    needs_rpc = True
                    break

    from config import RPC_URL 
    
    if RPC_URL and needs_rpc:
        config_data["rpcUrl"] = RPC_URL
        log.info("  [!] Fitur Mainnet Forking Aktif")

    config_str = yaml.dump(config_data, default_flow_style=False)

    config_path = os.path.join(output_path, "echidna_config.yaml")
    with open(config_path, "w") as f:
        f.write(config_str)

    return config_path


# Parsing Output Echidna

def _parse_echidna_output(stdout: str, stderr: str) -> Tuple[bool, float, bool]:
    """
    Mem-parse output Echidna dari terminal (stdout).
    """
    combined = stdout + "\n" + stderr

    # 1. Cek apakah property dilanggar
    property_broken = bool(
        re.search(
            rf"{re.escape(ORACLE_FUNCTION_NAME)}.*failed",
            combined,
            re.IGNORECASE,
        )
    )

    # 2. Ekstrak waktu deteksi
    detection_time = -1.0
    time_match = re.search(r"elapsed.*?(\d+\.?\d*)\s*s", combined, re.IGNORECASE)
    if time_match and property_broken:
        detection_time = float(time_match.group(1))

    # 3. Cek ACTIVATED dari stdout (Hanya ada jika fuzzer mencetak trace gagal)
    bug_line_hit = False
    if property_broken and "bug_reentrancy" in combined:
        bug_line_hit = True

    return property_broken, detection_time, bug_line_hit


def _detect_contract_name_in_file(filepath: str) -> Optional[str]:
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

def _create_echidna_wrapper(contract_path: str, result_dir: str, contract_name: str) -> Optional[str]:
    with open(contract_path, "r", encoding="utf-8") as f:
        source = f.read()

    constructor_match = re.search(r"constructor\s*\((.*?)\)", source, re.DOTALL)
    
    if not constructor_match or not constructor_match.group(1).strip():
        return None

    params_str = constructor_match.group(1).strip()
    params_list = [p.strip() for p in params_str.split(",") if p.strip()]
    
    dummy_args = []
    for param in params_list:
        parts = param.split()
        p_type = parts[0].lower()
        p_name = parts[-1].lower() if len(parts) > 1 else ""
        
        if "uint" in p_type or "int" in p_type:
            if "time" in p_name or "deadline" in p_name or "duration" in p_name or "end" in p_name:
                dummy_args.append("9999999999") 
            else:
                dummy_args.append("1000")        
        elif "address" in p_type:
            if "price" in p_name or "feed" in p_name or "oracle" in p_name or "aggregator" in p_name:
                dummy_args.append("address(0x694AA1769357215DE4FAC081bf1f309aDC325306)")
            else:
                dummy_args.append("address(0x10000)") 
        elif "bool" in p_type:
            dummy_args.append("true")        
        elif "string" in p_type:
            dummy_args.append('"Test"')      
        elif "bytes" in p_type:
            dummy_args.append('""')          
        else:
            dummy_args.append("0")           

    args_string = ", ".join(dummy_args)

    wrapper_name = f"{contract_name}Echidna"
    wrapper_filename = f"{os.path.basename(contract_path).replace('.sol', '')}_wrapper.sol"
    wrapper_path = os.path.join(result_dir, wrapper_filename)

    wrapper_code = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "../../injected_contracts/{os.path.basename(contract_path)}";

contract {wrapper_name} is {contract_name} {{
    // Auto-Generated Constructor Arguments: {args_string}
    constructor() {contract_name}({args_string}) payable {{
    }}
}}
"""
    with open(wrapper_path, "w", encoding="utf-8") as wf:
        wf.write(wrapper_code)
        
    return wrapper_path

def run_echidna_on_contract(
    contract_path: str,
    result_dir: str,
    variant: str,
) -> EchidnaResult:
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

    wrapper_path = _create_echidna_wrapper(contract_path, result_dir, contract_name)
    config_path = _generate_echidna_config(result_dir, contract_path, wrapper_path)

    if wrapper_path:
        log.info(f"  [!] Kontrak butuh konstruktor. Wrapper dibuat: {os.path.basename(wrapper_path)}")
        contract_path = wrapper_path
        contract_name = f"{contract_name}Echidna" 

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

        result.echidna_stdout = stdout
        result.echidna_stderr = stderr

        # ── Parse hasil dari stdout ─────────────────────────────────────
        property_broken, detection_time, bug_line_hit = _parse_echidna_output(
            stdout, stderr
        )

        # ── Parse hasil dari Coverage File Rahasia Echidna ──────────────
        # Jika Echidna diam saja di terminal, kita bongkar file "covered.txt"
        if not bug_line_hit:
            corpus_dir = os.path.join(result_dir, "corpus")
            if os.path.exists(corpus_dir):
                for root, _, files in os.walk(corpus_dir):
                    for file in files:
                        if file.startswith("covered.") and file.endswith(".txt"):
                            with open(os.path.join(root, file), "r", encoding="utf-8", errors="ignore") as f:
                                for line in f:
                                    # KITA CARI PAYLOAD PENCURIANNYA, BUKAN NAMA FUNGSINYA!
                                    if "msg.sender.call{value:" in line:
                                        parts = line.split("|")
                                        if len(parts) >= 2:
                                            marker = parts[1].strip()
                                            # Jika payload tersentuh fuzzer (ada bintang/r/e)
                                            if "*" in marker or "r" in marker or "e" in marker:
                                                bug_line_hit = True
                                                break
                        if bug_line_hit:
                            break
                    if bug_line_hit:
                        break

        result.property_broken  = property_broken
        result.bug_line_hit     = bug_line_hit

        det_status = "YES" if property_broken else "NO"
        act_status = "YES" if bug_line_hit else "NO"

        if proc.returncode != 0 and not property_broken:
            result.status = "ERROR"
            error_msg = stderr.strip().split("\n")[-1] if stderr else "Unknown Error"
            result.error_message = f"Echidna crash: {error_msg}"
            log.error("  ✗ ERROR      | %s", result.error_message)
        else:
            if property_broken:
                result.status = "DETECTED"
                result.detection_time_sec = detection_time if detection_time >= 0 else elapsed
            elif bug_line_hit:
                result.status = "ACTIVATED"
                result.detection_time_sec = ECHIDNA_TIMEOUT
            else:
                result.status = "NOT_DETECTED"
                result.detection_time_sec = ECHIDNA_TIMEOUT

            log.info("  DETECTED   : %s", det_status)
            log.info("  ACTIVATED  : %s", act_status)
            
            if property_broken:
                log.info("  Waktu      : %.2fs", result.detection_time_sec)

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
    os.makedirs(results_dir, exist_ok=True)

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

        echidna_result = run_echidna_on_contract(
            contract_path, result_subdir, variant
        )
        all_results.append(echidna_result)

    results_log_path = os.path.join(LOGS_DIR, "echidna_results.json")
    os.makedirs(LOGS_DIR, exist_ok=True)
    with open(results_log_path, "w", encoding="utf-8") as f:
        json.dump(
            [r.to_dict() for r in all_results],
            f, indent=2, ensure_ascii=False
        )

    detected  = sum(1 for r in all_results if r.property_broken)
    activated = sum(1 for r in all_results if r.bug_line_hit)
    timeout   = sum(1 for r in all_results if r.status == "TIMEOUT")
    error     = sum(1 for r in all_results if r.status == "ERROR")
    not_det   = sum(1 for r in all_results if not r.property_broken and r.status not in ["TIMEOUT", "ERROR"])
    log.info("")
    log.info("Ringkasan Echidna:")
    log.info("  DETECTED     : %d", detected)
    log.info("  ACTIVATED    : %d", activated)
    log.info("  NOT_DETECTED : %d", not_det)
    log.info("  TIMEOUT      : %d", timeout)
    log.info("  ERROR        : %d", error)
    log.info("Hasil tersimpan di: %s", results_log_path)

    return all_results


if __name__ == "__main__":
    import sys

    if len(sys.argv) == 2:
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