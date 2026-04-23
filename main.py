"""
MAIN PIPELINE — ORCHESTRATION OF ALL STAGES
=============================================
Runs the full research pipeline in sequence:

    Step 1  Oracle Instrumentation
            base_contract → instrumented_contract

    Step 2  Compilation Verification
            instrumented_contract → valid / invalid

    Step 3  Bug Injection
            instrumented_contract (valid) → injected_contract

    Step 4  Echidna Fuzzing
            injected_contract → echidna_results

    Step 5  Results Analysis
            echidna_results → metrics (detection rate, activation rate, avg time)

Usage:
    python main.py                   # Full pipeline (steps 1–5)
    python main.py --from-step 3     # Resume from a specific step
    python main.py --step 1          # Run a single step only
    python main.py --check           # Check prerequisites only
    python main.py --verbose         # Enable DEBUG logging
"""

import argparse
import glob
import json
import os
import subprocess
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import (
    ANALYSIS_RESULTS_DIR,
    BASE_CONTRACTS_DIR,
    BUG_VARIANTS,
    ECHIDNA_RESULTS_DIR,
    INJECTED_DIR,
    INSTRUMENTED_DIR,
    LOGS_DIR,
)
from logger import get_logger
from step1instrumentor import run_instrumentation
from step2compiler     import get_valid_contracts, verify_instrumented_contracts
from step3injector     import run_injection
from step4echidna      import run_echidna_all
from step5analyst      import run_analysis

log = get_logger("pipeline")


# ---------------------------------------------------------------------------
# Banner & step headers
# ---------------------------------------------------------------------------

_BANNER = """
╔══════════════════════════════════════════════════════════════╗
║     DYNAMIC REENTRANCY BUG INJECTION TOOL                    ║
║     Dynamic Analysis Evaluation (Echidna) via Bug Injection  ║
║                                                              ║
║     Reference: SolidiFI (Ghaleb & Pattabiraman, 2020)        ║
║     Adapted for: Dynamic Reentrancy Analysis                 ║
╚══════════════════════════════════════════════════════════════╝
"""

_STEP_LABELS = {
    1: "ORACLE INSTRUMENTATION",
    2: "COMPILATION VERIFICATION",
    3: "BUG INJECTION",
    4: "ECHIDNA FUZZING",
    5: "RESULTS ANALYSIS",
}


def _step_header(step_num: int) -> None:
    label = _STEP_LABELS.get(step_num, f"STEP {step_num}")
    log.info("")
    log.info("┌─────────────────────────────────────────────────────────┐")
    log.info("│  STEP %d ─ %-46s│", step_num, label)
    log.info("└─────────────────────────────────────────────────────────┘")


# ---------------------------------------------------------------------------
# Prerequisites check
# ---------------------------------------------------------------------------

def _check_prerequisites() -> bool:
    """Verify all prerequisites before running the pipeline."""
    issues = []

    # Contracts directory
    if not os.path.isdir(BASE_CONTRACTS_DIR):
        issues.append(
            f"Directory not found: {BASE_CONTRACTS_DIR}\n"
            f"  → Create the directory and place your .sol files inside."
        )
    elif not any(f.endswith(".sol") for f in os.listdir(BASE_CONTRACTS_DIR)):
        issues.append(
            f"No .sol files found in: {BASE_CONTRACTS_DIR}\n"
            f"  → Add at least one Solidity contract."
        )

    # solc
    try:
        r = subprocess.run(["solc", "--version"], capture_output=True, timeout=5)
        if r.returncode != 0:
            issues.append("solc did not respond correctly.")
    except FileNotFoundError:
        issues.append(
            "solc not found.\n"
            "  → Install: https://docs.soliditylang.org/en/latest/installing-solidity.html"
        )
    except Exception:
        issues.append("Failed to check solc.")

    # echidna (optional — warning only)
    try:
        subprocess.run(["echidna", "--version"], capture_output=True, timeout=5)
    except FileNotFoundError:
        log.warning(
            "Echidna not found. Step 4 will produce ERROR status.\n"
            "  → Install: https://github.com/crytic/echidna"
        )
    except Exception:
        pass

    if issues:
        log.error("Prerequisites not met:")
        for issue in issues:
            log.error("  ✗ %s", issue)
        return False

    return True


# ---------------------------------------------------------------------------
# Pipeline state persistence
# ---------------------------------------------------------------------------

_STATE_PATH = os.path.join(LOGS_DIR, "pipeline_state.json")


def _save_state(state: dict) -> None:
    """Persist pipeline state to JSON for resumability."""
    os.makedirs(LOGS_DIR, exist_ok=True)
    with open(_STATE_PATH, "w") as f:
        json.dump(state, f, indent=2)


def _load_state() -> dict:
    """Load previously saved pipeline state."""
    if os.path.isfile(_STATE_PATH):
        with open(_STATE_PATH) as f:
            return json.load(f)
    return {}


# ---------------------------------------------------------------------------
# Per-step runners
# ---------------------------------------------------------------------------

def run_step1(state: dict) -> bool:
    _step_header(1)
    results = run_instrumentation(base_dir=BASE_CONTRACTS_DIR, output_dir=INSTRUMENTED_DIR)
    success = sum(results.values())
    state["step1"] = {
        "completed": True,
        "total":     len(results),
        "success":   success,
        "failed":    [k for k, v in results.items() if not v],
    }
    _save_state(state)
    return success > 0


def run_step2(state: dict) -> list:
    _step_header(2)
    results     = verify_instrumented_contracts(INSTRUMENTED_DIR)
    valid_files = get_valid_contracts(results)
    invalid     = [f for f, (ok, _) in results.items() if not ok]
    state["step2"] = {
        "completed": True,
        "total":     len(results),
        "valid":     valid_files,
        "invalid":   invalid,
    }
    _save_state(state)
    if not valid_files:
        log.error("No contracts passed compilation verification.")
    return valid_files


def run_step3(state: dict, valid_files: list) -> list:
    _step_header(3)
    logs = run_injection(
        instrumented_dir=INSTRUMENTED_DIR,
        output_dir=INJECTED_DIR,
        valid_files=valid_files,
        variants=BUG_VARIANTS,
    )
    state["step3"] = {
        "completed":      True,
        "total_injected": len(logs),
        "variants":       BUG_VARIANTS,
    }
    _save_state(state)
    return logs


def run_step4(state: dict, injection_logs: list) -> list:
    _step_header(4)
    results  = run_echidna_all(
        injected_dir=INJECTED_DIR,
        results_dir=ECHIDNA_RESULTS_DIR,
        injection_log=injection_logs,
    )
    detected = sum(1 for r in results if r.status == "DETECTED")
    state["step4"] = {
        "completed":    True,
        "total_tested": len(results),
        "detected":     detected,
    }
    _save_state(state)
    return results


def run_step5(state: dict) -> dict:
    _step_header(5)
    metrics = run_analysis(output_dir=ANALYSIS_RESULTS_DIR)
    state["step5"] = {
        "completed":        True,
        "metrics_computed": len(metrics),
    }
    _save_state(state)
    return metrics


# ---------------------------------------------------------------------------
# Full pipeline orchestration
# ---------------------------------------------------------------------------

def _load_injection_log() -> list:
    """Load the injection log from disk if available."""
    path = os.path.join(LOGS_DIR, "injection_log.json")
    if os.path.isfile(path):
        with open(path) as f:
            data = json.load(f)
        log.info("Injection log loaded: %d entries", len(data))
        return data
    log.warning("Injection log not found.")
    return []


def run_full_pipeline(from_step: int = 1) -> bool:
    """
    Execute the full pipeline starting from *from_step*.

    Returns:
        True if the pipeline completes without a critical error.
    """
    start = time.time()
    state = _load_state() if from_step > 1 else {}

    log.info("Starting pipeline from step %d", from_step)

    # Step 1
    if from_step <= 1:
        if not run_step1(state):
            log.error("Step 1 failed. Pipeline aborted.")
            return False
    else:
        log.info("⏭  Skipping Step 1")

    # Step 2
    if from_step <= 2:
        valid_files = run_step2(state)
        if not valid_files:
            log.error("Step 2 failed. Pipeline aborted.")
            return False
    else:
        valid_files = state.get("step2", {}).get("valid", [])
        log.info("⏭  Skipping Step 2  (%d valid files from state)", len(valid_files))

    # Step 3
    if from_step <= 3:
        injection_logs = run_step3(state, valid_files)
        if not injection_logs:
            log.error("Step 3 failed. No bugs were successfully injected.")
            return False
    else:
        injection_logs = _load_injection_log() if from_step > 3 else []
        log.info("⏭  Skipping Step 3")

    # Step 4
    if from_step <= 4:
        echidna_results = run_step4(state, injection_logs)
        if not echidna_results:
            log.warning("Step 4 produced no output (Echidna may not be installed).")
    else:
        log.info("⏭  Skipping Step 4")

    # Step 5
    if from_step <= 5:
        run_step5(state)
    else:
        log.info("⏭  Skipping Step 5")

    # Final summary box
    elapsed = time.time() - start
    log.info("")
    log.info("╔══════════════════════════════════════════════════════════╗")
    log.info("║  ✓  PIPELINE COMPLETE                                    ║")
    log.info("╠══════════════════════════════════════════════════════════╣")
    log.info("║  Total time     : %-37s║", f"{elapsed:.1f}s  ({elapsed / 60:.1f} min)")
    log.info("║  Analysis output: %-37s║", _shorten(ANALYSIS_RESULTS_DIR, 37))
    log.info("║  Full log       : %-37s║", _shorten(LOGS_DIR, 37))

    summary_files = sorted(glob.glob(os.path.join(ANALYSIS_RESULTS_DIR, "summary_*.json")))
    if summary_files:
        log.info("║  Latest summary : %-37s║", _shorten(summary_files[-1], 37))

    log.info("╚══════════════════════════════════════════════════════════╝")
    return True


def run_single_step(step_num: int) -> bool:
    """Run exactly one pipeline step without executing any other steps."""
    state = _load_state()

    dispatch = {
        1: lambda: run_step1(state),
        2: lambda: bool(run_step2(state)),
        3: lambda: bool(run_step3(state, state.get("step2", {}).get("valid", []))),
        4: lambda: bool(run_step4(state, _load_injection_log())),
        5: lambda: bool(run_step5(state)),
    }

    fn = dispatch.get(step_num)
    if fn is None:
        log.error("Invalid step number: %d (must be 1–5)", step_num)
        return False

    return bool(fn())


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _shorten(path: str, max_len: int) -> str:
    """Truncate *path* to at most *max_len* characters for display."""
    return path if len(path) <= max_len else "…" + path[-(max_len - 1):]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    print(_BANNER)

    parser = argparse.ArgumentParser(
        description="Dynamic Reentrancy Bug Injection Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                  # Full pipeline (steps 1–5)
  python main.py --from-step 3    # Resume from step 3
  python main.py --step 2         # Run step 2 only
  python main.py --check          # Check prerequisites only
        """,
    )
    parser.add_argument(
        "--from-step", type=int, default=1, choices=range(1, 6), metavar="N",
        help="Start the pipeline from step N (1–5, default: 1)",
    )
    parser.add_argument(
        "--step", type=int, choices=range(1, 6), metavar="N",
        help="Run a single step only",
    )
    parser.add_argument("--check",   action="store_true", help="Check prerequisites only")
    parser.add_argument("--verbose", action="store_true", help="Enable DEBUG logging")
    args = parser.parse_args()

    if args.verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)

    # Prerequisites-only mode
    if args.check:
        ok = _check_prerequisites()
        log.info(
            "✓ All prerequisites met." if ok
            else "✗ Some prerequisites are not satisfied."
        )
        sys.exit(0 if ok else 1)

    if not _check_prerequisites():
        log.error("Pipeline cannot start. Address the issues listed above.")
        sys.exit(1)

    log.info("Start time : %s", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    if args.step is not None:
        log.info("Mode       : single step (%d)", args.step)
        ok = run_single_step(args.step)
    else:
        log.info("Mode       : full pipeline (from step %d)", args.from_step)
        ok = run_full_pipeline(from_step=args.from_step)

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()