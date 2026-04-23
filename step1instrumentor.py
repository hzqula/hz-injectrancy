"""
STEP 1 — ORACLE INSTRUMENTATION
=================================
Inserts an oracle mechanism into clean base contracts.
The oracle is an Echidna property function that detects invariant violations at runtime.

Flow:
    base_contract  →  [instrumentation]  →  instrumented_contract

What is inserted:
    1. Reentrancy state variables : isReenteredHZ (public) and lockedHZ (private)
    2. Oracle function            : returns !isReenteredHZ
"""

import os
import re
from typing import Optional

from config import BASE_CONTRACTS_DIR, INSTRUMENTED_DIR, ORACLE_FUNCTION_NAME
from logger import get_logger

log = get_logger("instrumentor")


# ---------------------------------------------------------------------------
# Code templates
# ---------------------------------------------------------------------------

TRACKER_VAR_TEMPLATE = """
    // [ORACLE] Reentrancy tracker variables
    bool public  isReenteredHZ = false;
    bool private lockedHZ      = false;
"""

ORACLE_FUNCTION_TEMPLATE = """
    // [ORACLE] Echidna property — a violation means the fuzzer successfully re-entered
    function {oracle_name}() public view returns (bool) {{
        return !isReenteredHZ;
    }}
"""


# ---------------------------------------------------------------------------
# Internal utilities
# ---------------------------------------------------------------------------

def _detect_contract_name(source: str) -> Optional[str]:
    """Detect the name of the first contract definition (not interface or library)."""
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("contract ") and "{" in stripped:
            parts = stripped.split()
            if len(parts) >= 2:
                return parts[1].split("(")[0].split("{")[0].strip()
    return None


def _insert_after_contract_open(source: str, contract_name: str, code: str) -> str:
    """Insert *code* immediately after the opening brace of the target contract."""
    lines = source.splitlines()
    insert_idx: Optional[int] = None

    # Find the opening line of the named contract
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith("contract ") and contract_name in s and "{" in s:
            insert_idx = i + 1
            break

    # Fallback: use the first contract found
    if insert_idx is None:
        log.warning("Contract '%s' not found — using the first contract instead.", contract_name)
        for i, line in enumerate(lines):
            if line.strip().startswith("contract ") and "{" in line:
                insert_idx = i + 1
                break

    if insert_idx is None:
        log.error("Could not locate insertion point for tracker variables.")
        return source

    lines.insert(insert_idx, code)
    log.debug("Code inserted after line %d.", insert_idx)
    return "\n".join(lines)


def _insert_before_contract_close(source: str, contract_name: str, code: str) -> str:
    """Insert *code* immediately before the closing brace of the target contract."""
    pattern = r"contract\s+" + re.escape(contract_name) + r"\s*\{"
    match = re.search(pattern, source)

    if not match:
        # Fallback: insert before the last closing brace in the file
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


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def instrument_contract(input_path: str, output_path: str) -> bool:
    """
    Instrument a single Solidity contract file.

    Inserts tracker variables and the oracle function into the contract,
    then writes the result to *output_path*.

    Returns:
        True on success, False on any error.
    """
    log.info("Instrumenting: %s", os.path.basename(input_path))

    if not os.path.isfile(input_path):
        log.error("File not found: %s", input_path)
        return False

    with open(input_path, encoding="utf-8", errors="ignore") as f:
        source = f.read()

    contract_name = _detect_contract_name(source)
    if contract_name is None:
        log.error("Could not detect contract name in: %s", input_path)
        return False

    log.debug("Contract detected: %s", contract_name)

    source = _insert_after_contract_open(source, contract_name, TRACKER_VAR_TEMPLATE)
    source = _insert_before_contract_close(
        source,
        contract_name,
        ORACLE_FUNCTION_TEMPLATE.format(oracle_name=ORACLE_FUNCTION_NAME),
    )

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(source)

    log.info("  ✓ %s", os.path.basename(output_path))
    return True


def run_instrumentation(
    base_dir: str = BASE_CONTRACTS_DIR,
    output_dir: str = INSTRUMENTED_DIR,
) -> dict:
    """
    Instrument all .sol files in *base_dir* and write the results to *output_dir*.

    Returns:
        Dict mapping { "filename.sol": True/False } for each processed file.
    """
    os.makedirs(output_dir, exist_ok=True)

    sol_files = sorted(
        f for f in os.listdir(base_dir)
        if f.endswith(".sol") and not f.startswith(".")
    )

    if not sol_files:
        log.warning("No .sol files found in: %s", base_dir)
        return {}

    log.info("=" * 60)
    log.info("STEP 1: ORACLE INSTRUMENTATION")
    log.info("=" * 60)
    log.info("Contracts to instrument: %d", len(sol_files))

    results = {}
    for fname in sol_files:
        ok = instrument_contract(
            input_path=os.path.join(base_dir, fname),
            output_path=os.path.join(output_dir, fname),
        )
        results[fname] = ok

    success = sum(results.values())
    log.info("Done: %d/%d succeeded.", success, len(sol_files))
    return results


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    if len(sys.argv) == 3:
        ok = instrument_contract(sys.argv[1], sys.argv[2])
        sys.exit(0 if ok else 1)
    else:
        results = run_instrumentation()
        failed = [k for k, v in results.items() if not v]
        if failed:
            log.warning("Failed: %s", failed)
            sys.exit(1)
        sys.exit(0)