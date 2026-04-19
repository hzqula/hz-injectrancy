"""
Konfigurasi utama untuk Dynamic Reentrancy Bug Injection Tool
Diadaptasi dari SolidiFI untuk evaluasi analisis dinamis dengan Echidna
"""

import os
from dotenv import load_dotenv

# Direktori 
BASE_DIR              = os.path.dirname(os.path.abspath(__file__))
BASE_CONTRACTS_DIR    = os.path.join(BASE_DIR, "contracts")
INSTRUMENTED_DIR      = os.path.join(BASE_DIR, "instrumented_contracts")
INJECTED_DIR          = os.path.join(BASE_DIR, "injected_contracts")
ECHIDNA_RESULTS_DIR   = os.path.join(BASE_DIR, "echidna_results")
ANALYSIS_RESULTS_DIR  = os.path.join(BASE_DIR, "analysis_results")
BUG_PATTERNS_DIR      = os.path.join(BASE_DIR, "bug_patterns")
LOGS_DIR              = os.path.join(BASE_DIR, "logs")

# Load env
load_dotenv()

# URL RPC
RPC_URL = os.getenv("ALCHEMY_RPC_URL")

# Varian Bug Reentrancy
BUG_VARIANTS = [
    "single_function",
    "cross_function",
]

# Konfigurasi Echidna 
ECHIDNA_CONFIG = {
    "testLimit":   150000,   
    "seqLen":      100,       
    "shrinkLimit": 5000,      
    "coverage":    True,     
    "timeout":     180,       
    "deployer":    "0x30000000000000000000000000000000000000000",
    "sender":      ["0x30000000000000000000000000000000000000000"],
    "balanceAddr": 10000,
    "balanceContract": 0,
    "maxTimeDelay": 3600,
}

# Versi Solidity
SOLIDITY_VERSION = "0.8.0"
SOLC_BINARY = "solc"  # Path ke solc binary

# Nama Fungsi Oracle harus diawali dengan "echidna_"
ORACLE_FUNCTION_PREFIX = "echidna_"
ORACLE_FUNCTION_NAME   = "echidna_cek_saldo"

# Nama Variabel Pelacak 
TRACKER_VAR_NAME = "totalDepositsHZ"

# Timeout
COMPILATION_TIMEOUT = 30   
ECHIDNA_TIMEOUT     = 195

# Logging
LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR