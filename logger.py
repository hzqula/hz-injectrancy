"""
Logger terpusat untuk seluruh modul pipeline.
Setiap logger menulis ke console dan ke file log bertimestamp secara bersamaan.
"""

import logging
import os
from datetime import datetime

from config import LOGS_DIR, LOG_LEVEL

os.makedirs(LOGS_DIR, exist_ok=True)

# Satu file log per sesi (dibuat saat modul pertama kali diimpor)
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
    Mengembalikan logger bernama *name*.

    Logger dikonfigurasi dengan dua handler:
    - StreamHandler  → output ke console
    - FileHandler    → output ke file log sesi ini

    Pemanggilan berulang dengan nama yang sama aman (handler tidak digandakan).
    """
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger  # Sudah dikonfigurasi sebelumnya

    level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
    logger.setLevel(level)

    # Console
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(_LOG_FORMAT)
    logger.addHandler(ch)

    # File
    fh = logging.FileHandler(_SESSION_LOG_FILE, encoding="utf-8")
    fh.setLevel(level)
    fh.setFormatter(_LOG_FORMAT)
    logger.addHandler(fh)

    return logger