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
    "testLimit":   1000000,   # Jumlah test case
    "seqLen":      100,      # Panjang sequence transaksi
    "shrinkLimit": 5000,     # Batas iterasi shrinking
    "coverage":    True,     # Coverage-guided fuzzing
    "timeout":     300,      # Timeout per kontrak (detik)
    "deployer":    "0x30000000000000000000000000000000000000000",  # Alamat deployer
    "sender":      ["0x20000000000000000000000000000000000000000"],
    "balanceAddr": 10000,    # Saldo awal dalam Ether
    "balanceContract": 0,
}

# Versi Solidity
SOLIDITY_VERSION = "0.8.0"
SOLC_BINARY = "solc"  # Path ke solc binary

# Nama Fungsi Oracle harus diawali dengan "echidna_"
ORACLE_FUNCTION_PREFIX = "echidna_"
ORACLE_FUNCTION_NAME   = "echidna_cek_saldo"

# Nama Variabel Pelacak 
TRACKER_VAR_NAME = "totalDeposits"

# Timeout
COMPILATION_TIMEOUT = 30   # detik
ECHIDNA_TIMEOUT     = 300  # detik per kontrak

# Logging
LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR