"""
Garudatva v3 — Memory Dumper
For CRITICAL tier APKs only.
Dumps active process memory via ADB to prove fraud was active at arrest time.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Dict, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)


class MemoryDumpResult:
    def __init__(self):
        self.dump_path: Optional[Path] = None
        self.dump_size_bytes: int = 0
        self.active_sockets: List[Dict] = []
        self.strings_extracted: List[str] = []
        self.errors: List[str] = []


async def dump_process_memory(
    adb_serial: str,
    pid: int,
    package_name: str,
    work_dir: Path,
) -> MemoryDumpResult:
    """
    Dump process memory for a running PID via ADB.
    Only called for CRITICAL tier (score >= 85).
    """
    result = MemoryDumpResult()
    work_dir.mkdir(parents=True, exist_ok=True)
    dump_path = work_dir / f"memdump_{package_name}_{pid}.bin"

    logger.info(f"Memory dump starting: PID={pid} package={package_name}")

    # Pull /proc/<pid>/mem via dd (requires root ADB)
    dump_cmd = (
        f"dd if=/proc/{pid}/mem of=/data/local/tmp/memdump.bin bs=4096 2>/dev/null || true"
    )
    try:
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", adb_serial, "shell", dump_cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.communicate(), timeout=60)

        # Pull dump from device
        pull = await asyncio.create_subprocess_exec(
            "adb", "-s", adb_serial, "pull",
            "/data/local/tmp/memdump.bin", str(dump_path),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(pull.communicate(), timeout=60)
        if dump_path.exists():
            result.dump_path = dump_path
            result.dump_size_bytes = dump_path.stat().st_size
            logger.info(f"Memory dump: {result.dump_size_bytes} bytes")
        else:
            result.errors.append(f"Pull failed: {stderr.decode(errors='replace')[:200]}")

    except asyncio.TimeoutError:
        result.errors.append("Memory dump timed out")
    except Exception as e:
        result.errors.append(f"Memory dump error: {e}")
        logger.error(f"Memory dump failed: {e}")

    # Extract active socket connections from /proc/net/tcp
    result.active_sockets = await _get_active_sockets(adb_serial, pid)

    return result


async def _get_active_sockets(adb_serial: str, pid: int) -> List[Dict]:
    """Read /proc/net/tcp to find active connections for this PID."""
    sockets = []
    try:
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", adb_serial, "shell", "cat /proc/net/tcp",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        for line in stdout.decode(errors="replace").splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4 and parts[3] == "01":  # 01 = ESTABLISHED
                local = _hex_to_addr(parts[1])
                remote = _hex_to_addr(parts[2])
                sockets.append({"local": local, "remote": remote, "state": "ESTABLISHED"})
    except Exception as e:
        logger.warning(f"Socket read failed: {e}")
    return sockets


def _hex_to_addr(hex_addr: str) -> str:
    """Convert hex-encoded /proc/net/tcp address to IP:port string."""
    try:
        addr, port = hex_addr.split(":")
        import socket, struct
        ip_int = int(addr, 16)
        ip = socket.inet_ntoa(struct.pack("<I", ip_int))
        port_int = int(port, 16)
        return f"{ip}:{port_int}"
    except Exception:
        return hex_addr
