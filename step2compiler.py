"""
STEP 2 — COMPILATION VERIFICATION
====================================
Ensures all instrumented contracts compile without errors
before proceeding to the bug injection stage.

Contracts that fail to compile are excluded from subsequent steps
and recorded as errors in the log.

Flow:
    instrumented_contract  →  [solc verification]  →  valid / invalid
"""

import os
import subprocess
from typing import Dict, Tuple

from config import COMPILATION_TIMEOUT, INSTRUMENTED_DIR, SOLC_BINARY
from logger import get_logger

log = get_logger("compiler")


# ---------------------------------------------------------------------------
# Core function
# ---------------------------------------------------------------------------

def compile_contract(filepath: str) -> Tuple[bool, str]:
    """
    Attempt to compile a single Solidity contract using solc.

    Args:
        filepath: Absolute path to the .sol file.

    Returns:
        (True, "")            if compilation succeeds.
        (False, error_message) if an error occurs.
    """
    if not os.path.isfile(filepath):
        return False, f"File not found: {filepath}"

    try:
        result = subprocess.run(
            [SOLC_BINARY, "--no-color", filepath],
            capture_output=True,
            text=True,
            timeout=COMPILATION_TIMEOUT,
        )
    except FileNotFoundError:
        return False, f"Compiler '{SOLC_BINARY}' not found. Make sure solc is installed."
    except subprocess.TimeoutExpired:
        return False, f"Timeout ({COMPILATION_TIMEOUT}s): {os.path.basename(filepath)}"
    except Exception as e:
        return False, f"Unexpected error: {e}"

    if result.returncode != 0:
        combined = result.stdout + result.stderr
        error_lines = [
            line for line in combined.splitlines()
            if "Error" in line or "error" in line
        ]
        error_msg = "\n".join(error_lines) if error_lines else combined[:500]
        return False, error_msg

    return True, ""


def verify_instrumented_contracts(
    instrumented_dir: str = INSTRUMENTED_DIR,
) -> Dict[str, Tuple[bool, str]]:
    """
    Verify all instrumented contracts found in *instrumented_dir*.

    Returns:
        Dict mapping { "filename.sol": (success, error_message) }.
    """
    sol_files = sorted(
        f for f in os.listdir(instrumented_dir)
        if f.endswith(".sol") and not f.startswith(".")
    )

    if not sol_files:
        log.warning("No .sol files found in: %s", instrumented_dir)
        return {}

    log.info("=" * 60)
    log.info("STEP 2: COMPILATION VERIFICATION")
    log.info("=" * 60)
    log.info("Contracts to verify: %d", len(sol_files))

    results: Dict[str, Tuple[bool, str]] = {}
    valid_count = invalid_count = 0

    for fname in sol_files:
        fpath = os.path.join(instrumented_dir, fname)
        ok, err_msg = compile_contract(fpath)
        results[fname] = (ok, err_msg)

        if ok:
            valid_count += 1
            log.info("  ✓ VALID   : %s", fname)
        else:
            invalid_count += 1
            log.warning("  ✗ INVALID : %s", fname)
            for line in err_msg.splitlines()[:3]:
                if line.strip():
                    log.warning("            %s", line.strip())

    log.info("Result: %d valid, %d invalid.", valid_count, invalid_count)
    return results


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def get_valid_contracts(results: Dict[str, Tuple[bool, str]]) -> list:
    """Return a list of filenames that passed verification."""
    return [fname for fname, (ok, _) in results.items() if ok]


def get_invalid_contracts(results: Dict[str, Tuple[bool, str]]) -> list:
    """Return a list of filenames that failed verification."""
    return [fname for fname, (ok, _) in results.items() if not ok]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    if len(sys.argv) == 2:
        ok, msg = compile_contract(sys.argv[1])
        if ok:
            print(f"✓ Compilation succeeded: {sys.argv[1]}")
        else:
            print(f"✗ Compilation failed:\n{msg}")
            sys.exit(1)
    else:
        results = verify_instrumented_contracts()
        invalid = get_invalid_contracts(results)
        if invalid:
            log.warning("Contracts that failed to compile:")
            for f in invalid:
                _, err = results[f]
                log.warning("  - %s: %s", f, err[:100])
        sys.exit(1 if invalid else 0)