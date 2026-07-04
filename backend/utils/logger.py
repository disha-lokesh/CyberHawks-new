"""
Garudatva v3 — Structured logger.
JSON-structured output for forensic audit trail.
"""

import logging
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


LOG_DIR = Path(__file__).parent.parent / "data" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)


class ForensicFormatter(logging.Formatter):
    """JSON formatter that produces audit-trail-safe log lines."""

    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            log_obj["exc"] = self.formatException(record.exc_info)
        return json.dumps(log_obj, ensure_ascii=True)


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    # Console handler — human readable
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.INFO)
    console.setFormatter(
        logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s — %(message)s",
            datefmt="%H:%M:%S",
        )
    )

    # File handler — JSON forensic audit log
    file_handler = logging.FileHandler(LOG_DIR / "garudatva.jsonl")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(ForensicFormatter())

    logger.addHandler(console)
    logger.addHandler(file_handler)
    return logger
