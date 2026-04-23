"""
STEP 3 — BUG INJECTION
=========================
Injects reentrancy vulnerability patterns into instrumented contracts.
Produces two bug variants per base contract:
    - single_function : reentrancy within a single function
    - cross_function  : reentrancy across two separate functions
"""

import json
import os
import re
from typing import Dict, List, Optional, Tuple

from config import BUG_VARIANTS, INJECTED_DIR, INSTRUMENTED_DIR, LOGS_DIR, ORACLE_FUNCTION_NAME
from logger import get_logger

log = get_logger("injector")


# ---------------------------------------------------------------------------
# Bug templates
# ---------------------------------------------------------------------------

# {dummy_mapping} is only populated when no existing mapping is found in the contract.
# {mapping_var}   is the name of the balance mapping variable to use.

SINGLE_FUNCTION_TEMPLATE = """
    // [INJECTED] Balance mapping (auto-populated if none exists in the original contract)
    {dummy_mapping}

    // [BUG] Single-Function Reentrancy
    // Transfer is performed BEFORE state is updated — violates the CEI pattern
    function bug_reentrancy_single(uint256 _amount) public {{
        // Auto-fund the sender so Echidna can reach the reentrancy phase
        if ({mapping_var}[msg.sender] < _amount) {{
            unchecked {{ {mapping_var}[msg.sender] += _amount; }}
        }}

        require(_amount > 0,                          "Amount must be > 0");
        require({mapping_var}[msg.sender] >= _amount, "Insufficient balance");

        // If re-entered while locked, trip the alarm
        if (lockedHZ) {{ isReenteredHZ = true; }}
        lockedHZ = true;

        (bool success, ) = msg.sender.call{{value: _amount}}("");
        require(success, "Transfer failed");

        // unchecked: disable Solidity 0.8+ built-in underflow protection
        unchecked {{ {mapping_var}[msg.sender] -= _amount; }}

        lockedHZ = false;
    }}
"""

CROSS_FUNCTION_TEMPLATE = """
    // [INJECTED] Balance mapping (auto-populated if none exists in the original contract)
    {dummy_mapping}

    // [BUG] Cross-Function Reentrancy — withdrawal function
    // State has not been updated when the external call is made
    function bug_reentrancy_cross_withdraw(uint256 _amount) public {{
        if ({mapping_var}[msg.sender] < _amount) {{
            unchecked {{ {mapping_var}[msg.sender] += _amount; }}
        }}

        require(_amount > 0,                          "Amount must be > 0");
        require({mapping_var}[msg.sender] >= _amount, "Insufficient balance");

        if (lockedHZ) {{ isReenteredHZ = true; }}
        lockedHZ = true;

        (bool success, ) = msg.sender.call{{value: _amount}}("");
        require(success, "Transfer failed");

        unchecked {{ {mapping_var}[msg.sender] -= _amount; }}

        lockedHZ = false;
    }}

    // [BUG] Cross-Function Reentrancy — balance reader
    // Reads state that may be inconsistent due to reentrancy in the function above
    function bug_reentrancy_cross_getBalance() public view returns (uint256) {{
        return {mapping_var}[msg.sender];
    }}
"""

RECEIVE_FUNCTION_TEMPLATE = """
    // [INJECTED] Receive function so the contract can accept Ether
    receive() external payable {{}}
"""


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Detects mapping(address => uint) commonly used as a balance store
_MAPPING_PATTERN = re.compile(
    r"mapping\s*\(\s*address[\s\w]*=>\s*uint(?:256)?[\s\w]*\)\s+"
    r"(?:public\s+|private\s+|internal\s+)?(\w+)\s*;",
    re.IGNORECASE,
)
_HAS_RECEIVE  = re.compile(r"receive\s*\(\s*\)\s+external\s+payable",  re.MULTILINE)
_HAS_FALLBACK = re.compile(r"fallback\s*\(\s*\)\s+external\s+payable", re.MULTILINE)


# ---------------------------------------------------------------------------
# Internal utilities
# ---------------------------------------------------------------------------

def _detect_main_contract_name(source: str) -> Optional[str]:
    """Detect the name of the first contract definition (not interface or library)."""
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("contract ") and "{" in stripped:
            parts = stripped.split()
            if len(parts) >= 2:
                return parts[1].split("(")[0].split("{")[0].strip()
    return None


def _find_mapping_variable(source: str) -> Optional[str]:
    """
    Find the most relevant mapping(address => uint) variable name.
    Priority is given to semantically meaningful keywords.
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
    """Return True if the contract has no receive() or payable fallback() function."""
    return not (_HAS_RECEIVE.search(source) or _HAS_FALLBACK.search(source))


def _insert_before_contract_close(source: str, contract_name: str, code: str) -> str:
    """Insert *code* immediately before the closing brace of the target contract."""
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
    """Return the line number where *marker* first appears, or -1 if not found."""
    for i, line in enumerate(source.splitlines(), start=1):
        if marker in line:
            return i
    return -1


# ---------------------------------------------------------------------------
# Per-variant injection functions
# ---------------------------------------------------------------------------

def inject_single_function(
    source: str,
    mapping_var: str,
    contract_name: str,
) -> Tuple[str, dict]:
    """Inject the single-function reentrancy pattern."""
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
            "Transfer is performed before state is updated (violates CEI pattern). "
            "An attacker can call this function repeatedly before the balance is decremented."
        ),
    }
    return source, log_entry


def inject_cross_function(
    source: str,
    mapping_var: str,
    contract_name: str,
) -> Tuple[str, dict]:
    """Inject the cross-function reentrancy pattern."""
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
            "Two functions share state that has not yet been updated consistently. "
            "bug_reentrancy_cross_withdraw transfers before updating state; "
            "bug_reentrancy_cross_getBalance reads state that may be inconsistent."
        ),
    }
    return source, log_entry


# Dispatcher: variant name → injection function
_VARIANT_INJECTORS = {
    "single_function": inject_single_function,
    "cross_function":  inject_cross_function,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def inject_contract(
    input_path: str,
    output_dir: str,
    variants: List[str] = BUG_VARIANTS,
) -> Dict[str, dict]:
    """
    Inject reentrancy bugs into a single contract for each requested variant.

    Args:
        input_path : Path to the instrumented .sol file.
        output_dir : Directory where injected files will be written.
        variants   : List of bug variants to inject.

    Returns:
        Dict mapping { variant: log_entry } for each successfully injected variant.
    """
    fname = os.path.basename(input_path)
    stem  = os.path.splitext(fname)[0]
    results: Dict[str, dict] = {}

    if not os.path.isfile(input_path):
        log.error("File not found: %s", input_path)
        return results

    with open(input_path, encoding="utf-8", errors="ignore") as f:
        original_source = f.read()

    contract_name = _detect_main_contract_name(original_source)
    if contract_name is None:
        log.error("Could not detect contract name in: %s", fname)
        return results

    mapping_var = _find_mapping_variable(original_source)
    if mapping_var is None:
        log.warning("No mapping variable found in '%s' — using default name.", fname)
        mapping_var = "dummyBalancesHZ"

    log.info("  Contract: %-30s  Mapping: %s", contract_name, mapping_var)

    for variant in variants:
        injector = _VARIANT_INJECTORS.get(variant)
        if injector is None:
            log.warning("Unknown variant: %s", variant)
            continue

        try:
            injected_source, entry = injector(original_source, mapping_var, contract_name)
        except Exception as e:
            log.error("Failed to inject variant '%s' into '%s': %s", variant, fname, e)
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

        log.info("  ✓ [%-16s] → %s  (line %d)",
                 variant, output_filename, entry.get("injection_line", -1))

    return results


def run_injection(
    instrumented_dir: str = INSTRUMENTED_DIR,
    output_dir: str       = INJECTED_DIR,
    valid_files: list     = None,
    variants: List[str]   = BUG_VARIANTS,
) -> List[dict]:
    """
    Inject bugs into all valid instrumented contracts.

    Args:
        instrumented_dir : Directory containing instrumented contracts.
        output_dir       : Output directory for injected contracts.
        valid_files      : Filenames to process (None = all files in the directory).
        variants         : Bug variants to inject.

    Returns:
        List of all log entries from successful injections.
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
        log.warning("No files to process.")
        return []

    log.info("=" * 60)
    log.info("STEP 3: BUG INJECTION")
    log.info("=" * 60)
    log.info("Contracts to inject : %d", len(sol_files))
    log.info("Variants            : %s", variants)

    all_logs: List[dict] = []
    for fname in sol_files:
        log.info("")
        log.info("Processing: %s", fname)
        for entry in inject_contract(
            os.path.join(instrumented_dir, fname), output_dir, variants
        ).values():
            all_logs.append(entry)

    log_path = os.path.join(LOGS_DIR, "injection_log.json")
    os.makedirs(LOGS_DIR, exist_ok=True)
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(all_logs, f, indent=2, ensure_ascii=False)

    log.info("")
    log.info("Total bugs injected : %d", len(all_logs))
    log.info("Injection log saved : %s", log_path)
    return all_logs


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    if len(sys.argv) == 3:
        results = inject_contract(sys.argv[1], sys.argv[2])
        print(
            f"Successfully injected {len(results)} variant(s)."
            if results else "Bug injection failed."
        )
        sys.exit(0 if results else 1)
    else:
        logs = run_injection()
        sys.exit(0 if logs else 1)