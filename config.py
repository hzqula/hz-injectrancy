"""
Main configuration for the Dynamic Reentrancy Bug Injection Tool.
Adapted from SolidiFI for dynamic analysis evaluation with Echidna.
"""

import os
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------------
BASE_DIR             = os.path.dirname(os.path.abspath(__file__))
BASE_CONTRACTS_DIR   = os.path.join(BASE_DIR, "contracts")
INSTRUMENTED_DIR     = os.path.join(BASE_DIR, "instrumented_contracts")
INJECTED_DIR         = os.path.join(BASE_DIR, "injected_contracts")
ECHIDNA_RESULTS_DIR  = os.path.join(BASE_DIR, "echidna_results")
ANALYSIS_RESULTS_DIR = os.path.join(BASE_DIR, "analysis_results")
BUG_PATTERNS_DIR     = os.path.join(BASE_DIR, "bug_patterns")
LOGS_DIR             = os.path.join(BASE_DIR, "logs")

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------
load_dotenv()
RPC_URL = os.getenv("ALCHEMY_RPC_URL")

# ---------------------------------------------------------------------------
# Reentrancy Bug Variants
# ---------------------------------------------------------------------------
BUG_VARIANTS = [
    "single_function",
    "cross_function",
]

# ---------------------------------------------------------------------------
# Echidna Configuration
# ---------------------------------------------------------------------------
ECHIDNA_CONFIG = {
    "testLimit":       150_000,
    "seqLen":          100,
    "shrinkLimit":     5_000,
    "coverage":        True,
    "timeout":         180,
    "deployer":        "0x30000000000000000000000000000000000000000",
    "sender":          [
        "0x30000000000000000000000000000000000000000",
        "0x10000000000000000000000000000000000000000",
    ],
    "balanceAddr":     10_000,
    "balanceContract": 0,
    "maxTimeDelay":    3_600,
}

# ---------------------------------------------------------------------------
# Solidity Compilation
# ---------------------------------------------------------------------------
SOLIDITY_VERSION = "0.8.0"
SOLC_BINARY      = "solc"

# ---------------------------------------------------------------------------
# Echidna Oracle
# The oracle function name MUST start with "echidna_" to be recognized by Echidna.
# ---------------------------------------------------------------------------
ORACLE_FUNCTION_PREFIX = "echidna_"
ORACLE_FUNCTION_NAME   = "echidna_reentrantCheck"

# ---------------------------------------------------------------------------
# Internal Tracker Variable Name
# ---------------------------------------------------------------------------
TRACKER_VAR_NAME = "totalDepositsHZ"

# ---------------------------------------------------------------------------
# Timeouts (seconds)
# ---------------------------------------------------------------------------
COMPILATION_TIMEOUT = 30
ECHIDNA_TIMEOUT     = 195

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_LEVEL = "INFO"   # Options: DEBUG | INFO | WARNING | ERROR