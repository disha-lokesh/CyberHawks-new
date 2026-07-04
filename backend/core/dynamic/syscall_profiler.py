"""
Garudatva v3 — Syscall Profiler
Runs strace on malware PID for 120s concurrently with MonkeyRunner.
Produces frequency vector of 24 syscalls → added as 10 ML features.
Target: these 10 features are expected to raise AUC over static-only
features (~0.94) toward the >= 0.972 goal — actual figures come only from
a real ml/trainer.py run against the trained model.
"""

from __future__ import annotations

import asyncio
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List

from utils.logger import get_logger

logger = get_logger(__name__)

# 24 syscalls tracked — chosen for malware relevance
TRACKED_SYSCALLS = [
    "connect", "sendto", "recvfrom", "socket",
    "open", "openat", "read", "write",
    "execve", "execveat", "ptrace",
    "mmap", "mmap2", "mprotect",
    "kill", "tgkill", "tkill",
    "clone", "fork", "vfork",
    "ioctl", "fcntl", "prctl",
    "getdents", "getdents64",
]

# The 10 features extracted from this (maps to FEATURE_NAMES in ml_classifier.py)
ML_SYSCALL_FEATURES = [
    "socket", "connect", "read", "write",
    "open", "execve", "ptrace", "mmap",
    "sendto", "recvfrom",
]


@dataclass
class SyscallResult:
    freq: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    total_calls: int = 0
    duration_seconds: float = 0.0
    strace_available: bool = True
    errors: List[str] = field(default_factory=list)

    def to_ml_vector(self) -> List[float]:
        """
        Return 10-element float vector matching syscall features in FEATURE_NAMES.
        Values are log-normalized call frequencies.
        """
        import math
        vector = []
        for syscall in ML_SYSCALL_FEATURES:
            count = self.freq.get(syscall, 0)
            # log1p normalization so high counts don't dominate
            vector.append(round(math.log1p(count), 4))
        return vector


async def profile_syscalls(
    adb_serial: str,
    pid: int,
    duration_seconds: int = 120,
) -> SyscallResult:
    """
    Run strace via ADB on the given PID for duration_seconds.
    Returns frequency counts for all 24 tracked syscalls.
    """
    result = SyscallResult()

    # Build strace command — trace only relevant syscalls for speed
    syscall_filter = ",".join(TRACKED_SYSCALLS)
    strace_cmd = (
        f"strace -p {pid} -e trace={syscall_filter} "
        f"-c -o /data/local/tmp/strace_out.txt "
        f"& sleep {duration_seconds} && kill %1 2>/dev/null"
    )

    logger.info(f"strace starting on PID {pid} for {duration_seconds}s")

    try:
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", adb_serial, "shell", strace_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=duration_seconds + 30
        )

        # Pull the strace summary output file
        pull_proc = await asyncio.create_subprocess_exec(
            "adb", "-s", adb_serial, "pull",
            "/data/local/tmp/strace_out.txt",
            "/tmp/garudatva_strace.txt",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(pull_proc.communicate(), timeout=15)

        result = _parse_strace_summary("/tmp/garudatva_strace.txt", duration_seconds)

    except asyncio.TimeoutError:
        result.errors.append("strace timed out")
        logger.warning("strace timed out")
    except FileNotFoundError:
        result.strace_available = False
        result.errors.append("adb not found in PATH")
    except Exception as e:
        result.errors.append(f"strace error: {e}")
        logger.error(f"strace failed: {e}")

    logger.info(
        f"Syscall profile: {result.total_calls} total calls, "
        f"connect={result.freq.get('connect', 0)}, "
        f"sendto={result.freq.get('sendto', 0)}"
    )
    return result


def _parse_strace_summary(path: str, duration: float) -> SyscallResult:
    """
    Parse strace -c summary output.
    Format:
      % time     seconds  usecs/call     calls    errors syscall
      ...
        3.14       0.001          10       150        3 connect
    """
    result = SyscallResult(duration_seconds=duration)
    try:
        import pathlib
        text = pathlib.Path(path).read_text(errors="replace")
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 6:
                syscall_name = parts[-1]
                if syscall_name in TRACKED_SYSCALLS:
                    try:
                        call_count = int(parts[3])
                        result.freq[syscall_name] = call_count
                        result.total_calls += call_count
                    except (ValueError, IndexError):
                        pass
    except FileNotFoundError:
        result.errors.append("strace output file not found — strace may not be installed on AVD")
    except Exception as e:
        result.errors.append(f"parse error: {e}")

    return result
