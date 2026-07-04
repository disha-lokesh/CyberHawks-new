"""
Garudatva v3 — RAM monitoring.
Critical on the 8GB developer machine with zram.
Dynamic analysis uses up to 4GB for AVD sandbox.
"""

import psutil
from dataclasses import dataclass
from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class RAMStatus:
    total_mb: float
    used_mb: float
    available_mb: float
    percent: float
    status: str  # "ok" | "warn" | "critical"


def get_ram_status(warn_mb: int = 6000, critical_mb: int = 7500) -> RAMStatus:
    """
    Return current RAM usage with tiered status.
    Warn at 6GB used, critical at 7.5GB used.
    """
    vm = psutil.virtual_memory()
    used_mb = vm.used / 1024 / 1024
    total_mb = vm.total / 1024 / 1024
    available_mb = vm.available / 1024 / 1024

    if used_mb >= critical_mb:
        status = "critical"
        logger.error(f"RAM CRITICAL: {used_mb:.0f}MB used of {total_mb:.0f}MB")
    elif used_mb >= warn_mb:
        status = "warn"
        logger.warning(f"RAM WARNING: {used_mb:.0f}MB used of {total_mb:.0f}MB")
    else:
        status = "ok"

    return RAMStatus(
        total_mb=round(total_mb, 1),
        used_mb=round(used_mb, 1),
        available_mb=round(available_mb, 1),
        percent=vm.percent,
        status=status,
    )


def assert_ram_available(required_mb: int) -> None:
    """
    Raise RuntimeError if insufficient RAM for the next pipeline stage.
    Call before launching AVD (requires ~4GB).
    """
    status = get_ram_status()
    if status.available_mb < required_mb:
        raise RuntimeError(
            f"Insufficient RAM: need {required_mb}MB, "
            f"only {status.available_mb:.0f}MB available. "
            f"Close other processes or wait for a prior stage to complete."
        )
    logger.info(
        f"RAM check passed: {status.available_mb:.0f}MB available, "
        f"{required_mb}MB required"
    )


def log_ram_snapshot(stage: str) -> RAMStatus:
    """Log RAM usage at a pipeline stage boundary."""
    status = get_ram_status()
    logger.info(
        f"[RAM] {stage}: {status.used_mb:.0f}MB used / "
        f"{status.total_mb:.0f}MB total ({status.percent:.1f}%)"
    )
    return status
