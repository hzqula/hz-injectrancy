import logging
import os
from datetime import datetime
from config import LOGS_DIR, LOG_LEVEL

os.makedirs(LOGS_DIR, exist_ok=True)

def get_logger(name: str) -> logging.Logger:
    """
    Mengembalikan logger dengan nama modul yang diberikan.
    Output ke file dan console secara bersamaan.
    """
    logger = logging.getLogger(name)
    
    if logger.handlers:
        # Hindari duplikasi handler jika dipanggil berkali-kali
        return logger

    level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
    logger.setLevel(level)

    # ─── Format ───────────────────────────────────────────────────────────────
    fmt = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # ─── Console Handler ──────────────────────────────────────────────────────
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # ─── File Handler ─────────────────────────────────────────────────────────
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file  = os.path.join(LOGS_DIR, f"tool_{timestamp}.log")
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(level)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger