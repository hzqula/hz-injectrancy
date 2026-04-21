"""
STEP 4 - PENGUJIAN DENGAN ECHIDNA
=================================
Jalanin Echidna property-based fuzzer pada setiap kontrak yang
telah disuntikkan bug reentrancy.
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
    source_file:     str = ""
    contract_name:   str = ""
    variant:         str = ""
    status:          str = "UNKNOWN"
    property_broken: bool = False
    detection_time_sec: float = -1.0
    lines_covered:   List[int] = field(default_factory=list)
    bug_line_hit:    bool = False
    echidna_stdout:  str = ""
    echidna_stderr:  str = ""
    error_message:   str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# Konfigurasi YAML Echidna

def _generate_echidna_config(output_path: str, contract_path: str, wrapper_path: Optional[str]) -> str:
    config_data = {
        "testLimit":      ECHIDNA_CONFIG["testLimit"],
        "seqLen":         ECHIDNA_CONFIG["seqLen"],
        "shrinkLimit":    ECHIDNA_CONFIG["shrinkLimit"],
        "coverage":       True,
        "corpusDir":      os.path.abspath(os.path.join(output_path, "corpus")),
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
    if wrapper_path: files_to_check.append(wrapper_path)

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

    config_str = yaml.dump(config_data, default_flow_style=False)
    config_path = os.path.join(output_path, "echidna_config.yaml")
    with open(config_path, "w") as f:
        f.write(config_str)
    return config_path


# Parsing Output Echidna

def _parse_echidna_output(stdout: str, stderr: str) -> Tuple[bool, float, bool]:
    combined = stdout + "\n" + stderr
    property_broken = bool(re.search(rf"{re.escape(ORACLE_FUNCTION_NAME)}.*failed", combined, re.IGNORECASE))
    detection_time = -1.0
    time_match = re.search(r"elapsed.*?(\d+\.?\d*)\s*s", combined, re.IGNORECASE)
    if time_match and property_broken:
        detection_time = float(time_match.group(1))

    bug_line_hit = False
    if property_broken and "bug_reentrancy" in combined:
        bug_line_hit = True

    return property_broken, detection_time, bug_line_hit


def _detect_contract_name_in_file(filepath: str) -> Optional[str]:
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f.read().split("\n"):
                stripped = line.strip()
                if stripped.startswith("contract ") and "{" in stripped:
                    parts = stripped.split()
                    if len(parts) >= 2:
                        return parts[1].split("(")[0].split("{")[0].strip()
    except Exception:
        pass
    return None


def _create_echidna_wrapper(contract_path: str, result_dir: str, contract_name: str, variant: str) -> Optional[str]:
    with open(contract_path, "r", encoding="utf-8") as f:
        source = f.read()

    constructor_match = re.search(r"constructor\s*\((.*?)\)", source, re.DOTALL)
    
    args_string = ""
    if constructor_match and constructor_match.group(1).strip():
        params_list = [p.strip() for p in constructor_match.group(1).strip().split(",") if p.strip()]
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
            elif "bool" in p_type: dummy_args.append("true")        
            elif "string" in p_type: dummy_args.append('"Test"')      
            elif "bytes" in p_type: dummy_args.append('""')          
            else: dummy_args.append("0")           
        args_string = ", ".join(dummy_args)

    # Pilih fungsi serangan sesuai varian kontrak
    if variant == "single_function":
        target_func = "bug_reentrancy_single"
    else:
        target_func = "bug_reentrancy_cross_withdraw"

    wrapper_name = f"{contract_name}Echidna"
    wrapper_filename = f"{os.path.basename(contract_path).replace('.sol', '')}_wrapper.sol"
    wrapper_path = os.path.join(result_dir, wrapper_filename)

    wrapper_code = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "../../injected_contracts/{os.path.basename(contract_path)}";

// ATTACKER: Disesuaikan dengan varian ({variant})
contract EchidnaAttacker_{contract_name} {{
    {contract_name} public target;
    bool private isAttacking;

    constructor({contract_name} _target) {{
        target = _target;
    }}

    function attack(uint256 amount) public {{
        target.{target_func}(amount);
    }}

    // Fallback yang memicu reentrancy (Putar balik ke target)
    receive() external payable {{
        if (!isAttacking) {{
            isAttacking = true;
            try target.{target_func}(msg.value) {{}} catch {{}}
            isAttacking = false;
        }}
    }}
}}

// 🎯 KONTRAK WRAPPER: Diuji langsung oleh Echidna
contract {wrapper_name} is {contract_name} {{
    EchidnaAttacker_{contract_name} public attacker;

    // PAYABLE: Agar fuzzer memberikan modal ETH saat deploy
    constructor() payable {contract_name}({args_string}) {{
        attacker = new EchidnaAttacker_{contract_name}(this);
    }}

    // Tombol Fuzzer
    function fuzz_attack(uint256 amount) public {{
        amount = (amount % 10 ether) + 1; // Batasi max 10 ether
        attacker.attack(amount);
    }}
}}
"""
    with open(wrapper_path, "w", encoding="utf-8") as wf:
        wf.write(wrapper_code)
        
    return wrapper_path


def run_echidna_on_contract(contract_path: str, result_dir: str, variant: str) -> EchidnaResult:
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

    # PEMBUATAN WRAPPER OTOMATIS (Meneruskan variabel variant)
    wrapper_path = _create_echidna_wrapper(contract_path, result_dir, contract_name, variant)
    config_path = _generate_echidna_config(result_dir, contract_path, wrapper_path)

    if wrapper_path:
        log.info(f"  [!] Kontrak dibungkus Attacker Proxy: {os.path.basename(wrapper_path)}")
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

        property_broken, detection_time, bug_line_hit = _parse_echidna_output(stdout, stderr)

        # Parse coverage
        if not bug_line_hit:
            corpus_dir = os.path.join(result_dir, "corpus")
            if os.path.exists(corpus_dir):
                for root, _, files in os.walk(corpus_dir):
                    for file in files:
                        if file.startswith("covered.") and file.endswith(".txt"):
                            with open(os.path.join(root, file), "r", encoding="utf-8", errors="ignore") as f:
                                for line in f:
                                    if "msg.sender.call{value:" in line:
                                        parts = line.split("|")
                                        if len(parts) >= 2:
                                            marker = parts[1].strip()
                                            if "*" in marker or "r" in marker or "e" in marker:
                                                bug_line_hit = True
                                                break
                        if bug_line_hit: break
                    if bug_line_hit: break

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
        result.error_message = "Echidna tidak ditemukan."
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

        echidna_result = run_echidna_on_contract(contract_path, result_subdir, variant)
        all_results.append(echidna_result)

    results_log_path = os.path.join(LOGS_DIR, "echidna_results.json")
    os.makedirs(LOGS_DIR, exist_ok=True)
    with open(results_log_path, "w", encoding="utf-8") as f:
        json.dump([r.to_dict() for r in all_results], f, indent=2, ensure_ascii=False)

    exploited   = sum(1 for r in all_results if r.bug_line_hit and r.property_broken)
    neutralized = sum(1 for r in all_results if r.bug_line_hit and not r.property_broken)
    unreachable = sum(1 for r in all_results if not r.bug_line_hit and not r.property_broken and r.status not in ["TIMEOUT", "ERROR"])
    native_bug  = sum(1 for r in all_results if not r.bug_line_hit and r.property_broken)
    
    timeout = sum(1 for r in all_results if r.status == "TIMEOUT")
    error   = sum(1 for r in all_results if r.status == "ERROR")

    log.info("")
    log.info("Ringkasan Analisis Keamanan (Echidna):")
    log.info("  EXPLOITED     (Act: YES, Det: YES) : %d", exploited)
    log.info("  NEUTRALIZED   (Act: YES, Det: NO ) : %d", neutralized)
    log.info("  UNREACHABLE   (Act: NO , Det: NO ) : %d", unreachable)
    log.info("  NATIVE_BUG    (Act: NO , Det: YES) : %d", native_bug)
    log.info("------------------------------------------------------------")
    log.info("  TIMEOUT                            : %d", timeout)
    log.info("  ERROR                              : %d", error)
    log.info("Hasil tersimpan di: %s", results_log_path)

    return all_results


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 2:
        result = run_echidna_on_contract(sys.argv[1], ECHIDNA_RESULTS_DIR, variant="unknown")
        print(f"Status : {result.status}")
        print(f"Detected: {result.property_broken}")
    else:
        results = run_echidna_all()
        sys.exit(0 if results else 1)