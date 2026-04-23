"""
Centralized logger for all pipeline modules.
Each logger writes to both the console and a timestamped log file simultaneously.
"""

import logging
import os
from datetime import datetime

from config import LOGS_DIR, LOG_LEVEL

os.makedirs(LOGS_DIR, exist_ok=True)

# One log file per session, created when this module is first imported.
_SESSION_LOG_FILE = os.path.join(
    LOGS_DIR,
    f"tool_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
)

_LOG_FORMAT = logging.Formatter(
    fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def get_logger(name: str) -> logging.Logger:
    """
    Return a logger identified by *name*.

    The logger is configured with two handlers:
    - StreamHandler : writes to the console
    - FileHandler   : writes to this session's log file

    Repeated calls with the same name are safe — handlers are not duplicated.
    """
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger  # Already configured

    level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
    logger.setLevel(level)

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(_LOG_FORMAT)
    logger.addHandler(ch)

    # File handler
    fh = logging.FileHandler(_SESSION_LOG_FILE, encoding="utf-8")
    fh.setLevel(level)
    fh.setFormatter(_LOG_FORMAT)
    logger.addHandler(fh)

    return logger