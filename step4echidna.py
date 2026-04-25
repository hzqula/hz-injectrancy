"""
STEP 4 — ECHIDNA FUZZING
==========================
Runs the Echidna property-based fuzzer on every contract
that has been injected with a reentrancy bug.

For each contract the pipeline:
    1. Auto-generates an attacker wrapper + Echidna proxy contract
    2. Produces an Echidna YAML configuration file
    3. Runs Echidna and parses the output
    4. Saves the raw text log and a final JSON results file
"""

import json
import os
import re
import subprocess
import time
import yaml
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple

from config import (
    ECHIDNA_CONFIG,
    ECHIDNA_RESULTS_DIR,
    ECHIDNA_TIMEOUT,
    INJECTED_DIR,
    LOGS_DIR,
    ORACLE_FUNCTION_NAME,
    RPC_URL,
)
from logger import get_logger

log = get_logger("echidna_runner")


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class EchidnaResult:
    source_file:        str       = ""
    contract_name:      str       = ""
    variant:            str       = ""
    status:             str       = "UNKNOWN"
    property_broken:    bool      = False
    detection_time_sec: float     = -1.0
    lines_covered:      List[int] = field(default_factory=list)
    bug_line_hit:       bool      = False
    echidna_stdout:     str       = ""
    echidna_stderr:     str       = ""
    error_message:      str       = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Echidna YAML configuration
# ---------------------------------------------------------------------------

def _generate_echidna_config(
    output_dir: str,
    contract_path: str,
    wrapper_path: Optional[str],
) -> str:
    """
    Write an echidna_config.yaml file to *output_dir*.
    Adds rpcUrl when the contract references Chainlink or an external oracle.
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

    # Add RPC URL when the contract uses Chainlink / external price feeds
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
# Output parsing
# ---------------------------------------------------------------------------

def _parse_echidna_output(stdout: str, stderr: str) -> Tuple[bool, float, bool]:
    """
    Parse Echidna's combined output to determine:
        - property_broken : whether the oracle property was violated
        - detection_time  : time of detection in seconds (-1 if not detected)
        - bug_line_hit    : whether the injected bug line was executed
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
# Contract name detection
# ---------------------------------------------------------------------------

def _detect_contract_name(filepath: str) -> Optional[str]:
    """Read a file and return the name of the first contract definition found."""
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
# Echidna wrapper generation
# ---------------------------------------------------------------------------

def _build_constructor_args(source: str) -> str:
    """
    Parse the constructor parameters and produce type-appropriate dummy arguments
    suitable for use inside the generated Solidity wrapper.
    """
    match = re.search(r"constructor\s*\((.*?)\)", source, re.DOTALL)
    if not match or not match.group(1).strip():
        return ""

    params = [p.strip() for p in match.group(1).strip().split(",") if p.strip()]
    dummy_args = []

    for param in params:
        parts      = param.split()
        type_raw   = parts[0].strip()
        type_lower = type_raw.lower()
        name_lower = parts[-1].lower() if len(parts) > 1 else ""

        if "[]" in type_lower:
            dummy_args.append(f"new {type_raw.split('[')[0]}[](0)")
        elif "uint" in type_lower or "int" in type_lower:
            value = (
                "9999999999"
                if any(kw in name_lower for kw in ["time", "deadline", "duration", "end"])
                else "1000"
            )
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
    Generate a Solidity wrapper file containing:
        - EchidnaAttacker_{name} : attacker contract with a reentrancy receive() fallback
        - {name}Echidna          : wrapper contract tested directly by Echidna

    Returns:
        Path to the wrapper file, or None on failure.
    """
    with open(contract_path, encoding="utf-8") as f:
        source = f.read()

    args_string  = _build_constructor_args(source)
    target_func  = (
        "bug_reentrancy_single"
        if variant == "single_function"
        else "bug_reentrancy_cross_withdraw"
    )
    wrapper_name  = f"{contract_name}Echidna"
    wrapper_fname = f"{os.path.basename(contract_path).replace('.sol', '')}_wrapper.sol"
    wrapper_path  = os.path.join(result_dir, wrapper_fname)

    wrapper_code = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "../../injected_contracts/{os.path.basename(contract_path)}";

// Attacker contract — triggers reentrancy via the receive() fallback
contract EchidnaAttacker_{contract_name} {{
    {contract_name} public target;
    bool private isAttacking;

    constructor({contract_name} _target) {{
        target = _target;
    }}

    function attack(uint256 amount) public {{
        target.{target_func}(amount);
    }}

    // Called when receiving Ether → re-enters the target (reentrancy)
    receive() external payable {{
        if (!isAttacking) {{
            isAttacking = true;
            try target.{target_func}(msg.value) {{}} catch {{}}
            isAttacking = false;
        }}
    }}
}}

// Wrapper contract tested directly by Echidna
contract {wrapper_name} is {contract_name} {{
    EchidnaAttacker_{contract_name} public attacker;

    // payable so Echidna can fund the contract with ETH on deployment
    constructor() payable {contract_name}({args_string}) {{
        attacker = new EchidnaAttacker_{contract_name}(this);
    }}

    // Fuzzer entry point — called by Echidna to trigger an attack
    function fuzz_attack(uint256 amount) public {{
        amount = (amount % 10 ether) + 1;  // Cap at 10 ether
        attacker.attack(amount);
    }}
}}
"""
    with open(wrapper_path, "w", encoding="utf-8") as f:
        f.write(wrapper_code)

    return wrapper_path


# ---------------------------------------------------------------------------
# Corpus coverage check
# ---------------------------------------------------------------------------

def _check_corpus_coverage(result_dir: str) -> bool:
    """
    Scan Echidna's corpus directory to determine whether the external call
    inside the injected bug function was ever executed.
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
# Single-contract fuzzing
# ---------------------------------------------------------------------------

def run_echidna_on_contract(
    contract_path: str,
    result_dir: str,
    variant: str,
) -> EchidnaResult:
    """
    Run Echidna on a single injected contract.

    Args:
        contract_path : Path to the injected .sol file.
        result_dir    : Output directory for logs and corpus.
        variant       : Bug variant ("single_function" or "cross_function").

    Returns:
        EchidnaResult containing the detection status and metrics.
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
        result.error_message = f"File not found: {contract_path}"
        log.error(result.error_message)
        return result

    os.makedirs(result_dir, exist_ok=True)

    wrapper_path = _create_echidna_wrapper(contract_path, result_dir, contract_name, variant)
    config_path  = _generate_echidna_config(result_dir, contract_path, wrapper_path)

    # Use the wrapper as Echidna's target
    target_path = wrapper_path or contract_path
    target_name = f"{contract_name}Echidna" if wrapper_path else contract_name

    if wrapper_path:
        log.info("  [wrapper] %s", os.path.basename(wrapper_path))

    cmd = ["echidna", target_path, "--config", config_path, "--format", "text"]
    if target_name:
        cmd += ["--contract", target_name]

    log.info("  Running Echidna: %s [%s]", fname, variant)

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

        # Fall back to corpus coverage check if output parsing is inconclusive
        if not bug_line_hit:
            bug_line_hit = _check_corpus_coverage(result_dir)

        result.property_broken = property_broken
        result.bug_line_hit    = bug_line_hit

        if proc.returncode != 0 and not property_broken:
            result.status        = "ERROR"
            last_err             = proc.stderr.strip().splitlines()[-1] if proc.stderr else "Unknown"
            result.error_message = f"Echidna crashed: {last_err}"
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
        result.error_message      = f"Timed out after {ECHIDNA_TIMEOUT}s"
        log.warning("  ⏱ TIMEOUT: %s", fname)

    except FileNotFoundError:
        result.status        = "ERROR"
        result.error_message = "Echidna not found. Make sure Echidna is installed."
        log.error("  ✗ ERROR: %s", result.error_message)

    except Exception as e:
        result.status        = "ERROR"
        result.error_message = str(e)
        log.error("  ✗ ERROR: %s", e)

    # Save raw text log
    log_txt = os.path.join(result_dir, f"{os.path.splitext(fname)[0]}_echidna.txt")
    with open(log_txt, "w", encoding="utf-8") as f:
        f.write("=== STDOUT ===\n")
        f.write(result.echidna_stdout)
        f.write("\n=== STDERR ===\n")
        f.write(result.echidna_stderr)

    return result


# ---------------------------------------------------------------------------
# Batch fuzzing
# ---------------------------------------------------------------------------

def run_echidna_all(
    injected_dir: str   = INJECTED_DIR,
    results_dir: str    = ECHIDNA_RESULTS_DIR,
    injection_log: list = None,
) -> List[EchidnaResult]:
    """
    Run Echidna on all injected contracts in *injected_dir*.

    Args:
        injected_dir  : Directory containing injected contracts.
        results_dir   : Output directory for Echidna results.
        injection_log : Injection metadata used to map variants to filenames.

    Returns:
        List of EchidnaResult for every tested contract.
    """
    os.makedirs(results_dir, exist_ok=True)

    # Build a filename → variant lookup from the injection log
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
        log.warning("No injected contracts found in: %s", injected_dir)
        return []

    log.info("=" * 60)
    log.info("STEP 4: ECHIDNA FUZZING")
    log.info("=" * 60)
    log.info("Contracts to test: %d", len(sol_files))

    all_results: List[EchidnaResult] = []

    for fname in sol_files:
        # Resolve variant from lookup, or fall back to filename heuristic
        variant = variant_lookup.get(fname, "unknown")
        if variant == "unknown":
            if "single_function" in fname:
                variant = "single_function"
            elif "cross_function" in fname:
                variant = "cross_function"

        result_subdir = os.path.join(results_dir, os.path.splitext(fname)[0])
        os.makedirs(result_subdir, exist_ok=True)

        log.info("")
        log.info("Testing: %s", fname)

        r = run_echidna_on_contract(
            os.path.join(injected_dir, fname), result_subdir, variant
        )
        all_results.append(r)

    # Persist all results to JSON
    results_log_path = os.path.join(LOGS_DIR, "echidna_results.json")
    os.makedirs(LOGS_DIR, exist_ok=True)
    with open(results_log_path, "w", encoding="utf-8") as f:
        json.dump([r.to_dict() for r in all_results], f, indent=2, ensure_ascii=False)

    # Summary
    exploited   = sum(1 for r in all_results if r.bug_line_hit and r.property_broken)
    neutralized = sum(1 for r in all_results if r.bug_line_hit and not r.property_broken)
    unreachable = sum(
        1 for r in all_results
        if not r.bug_line_hit and not r.property_broken
        and r.status not in ("TIMEOUT", "ERROR")
    )
    timeout    = sum(1 for r in all_results if r.status == "TIMEOUT")
    error      = sum(1 for r in all_results if r.status == "ERROR")

    log.info("")
    log.info("Security Analysis Summary:")
    log.info("  EXPLOITED   (Act: YES, Det: YES) : %d", exploited)
    log.info("  NEUTRALIZED (Act: YES, Det: NO ) : %d", neutralized)
    log.info("  UNREACHABLE (Act: NO , Det: NO ) : %d", unreachable)
    log.info("  " + "-" * 40)
    log.info("  TIMEOUT                          : %d", timeout)
    log.info("  ERROR                            : %d", error)
    log.info("Results saved to: %s", results_log_path)

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