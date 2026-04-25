"""
EXPERIMENT CONFIGURATIONS
==========================
Defines 3 named experiment configurations for comparative evaluation.
Each experiment varies the core Echidna fuzzing parameters to study
how configuration intensity affects detection rate, activation rate,
and average detection time.

Configuration summary:
    exp1_light   : Low intensity  — fast baseline run
    exp2_medium  : Medium intensity — balanced exploration
    exp3_heavy   : High intensity  — thorough deep fuzzing
"""

from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# Experiment registry
# Each entry must contain: name, label, description, echidna_config, timeout
# ---------------------------------------------------------------------------

EXPERIMENTS: List[Dict[str, Any]] = [
    {
        "name":        "exp1_light",
        "label":       "Exp 1 — Light",
        "description": (
            "Low-intensity baseline: minimal test limit and short timeout. "
            "Serves as the lower bound for detection capability."
        ),
        "echidna_config": {
            "testLimit":       50_000,
            "seqLen":          50,
            "shrinkLimit":     1_000,
            "coverage":        True,
            "timeout":         60,
            "deployer":        "0x30000000000000000000000000000000000000000",
            "sender": [
                "0x30000000000000000000000000000000000000000",
                "0x10000000000000000000000000000000000000000",
            ],
            "balanceAddr":     10_000,
            "balanceContract": 0,
            "maxTimeDelay":    3_600,
        },
        "echidna_timeout": 75,      # subprocess timeout (slightly > config timeout)
    },
    {
        "name":        "exp2_medium",
        "label":       "Exp 2 — Medium",
        "description": (
            "Medium-intensity configuration: balanced test limit and sequence length. "
            "Mirrors the default pipeline config for a fair midpoint."
        ),
        "echidna_config": {
            "testLimit":       150_000,
            "seqLen":          100,
            "shrinkLimit":     5_000,
            "coverage":        True,
            "timeout":         180,
            "deployer":        "0x30000000000000000000000000000000000000000",
            "sender": [
                "0x30000000000000000000000000000000000000000",
                "0x10000000000000000000000000000000000000000",
            ],
            "balanceAddr":     10_000,
            "balanceContract": 0,
            "maxTimeDelay":    3_600,
        },
        "echidna_timeout": 195,
    },
    {
        "name":        "exp3_heavy",
        "label":       "Exp 3 — Heavy",
        "description": (
            "High-intensity deep fuzzing: large test limit and long sequences. "
            "Maximises detection at the cost of execution time."
        ),
        "echidna_config": {
            "testLimit":       300_000,
            "seqLen":          200,
            "shrinkLimit":     10_000,
            "coverage":        True,
            "timeout":         360,
            "deployer":        "0x30000000000000000000000000000000000000000",
            "sender": [
                "0x30000000000000000000000000000000000000000",
                "0x10000000000000000000000000000000000000000",
            ],
            "balanceAddr":     10_000,
            "balanceContract": 0,
            "maxTimeDelay":    3_600,
        },
        "echidna_timeout": 375,
    },
]

# Quick lookup: experiment name → config dict
EXPERIMENT_MAP: Dict[str, Dict[str, Any]] = {exp["name"]: exp for exp in EXPERIMENTS}