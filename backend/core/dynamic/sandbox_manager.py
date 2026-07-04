"""
Garudatva v3 — Sandbox Manager
AVD lifecycle: boot, snapshot, install, restore, shutdown.
Context manager — always cleans up even on error.
"""

from __future__ import annotations

import asyncio
import subprocess
import time
from pathlib import Path
from typing import Optional

from config import settings
from utils.logger import get_logger

logger = get_logger(__name__)

EMULATOR_READY_TIMEOUT = 180   # seconds to wait for boot
EMULATOR_BIN = "emulator"
ADB_BIN = "adb"

SNAPSHOT_NAME = "garudatva_clean"


class SandboxManager:
    """
    Manages a single Android Virtual Device lifecycle.

    Usage:
        async with SandboxManager() as sb:
            await sb.install_apk(apk_path)
            ...
        # AVD is stopped and snapshot restored automatically
    """

    def __init__(self):
        self.serial: Optional[str] = None
        self._emulator_proc: Optional[asyncio.subprocess.Process] = None

    async def __aenter__(self) -> "SandboxManager":
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.stop()

    # ── Lifecycle ────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Boot the AVD with anti-detection flags."""
        logger.info(f"Booting AVD: {settings.AVD_NAME}")

        self._emulator_proc = await asyncio.create_subprocess_exec(
            EMULATOR_BIN,
            "-avd", settings.AVD_NAME,
            "-no-window",
            "-no-audio",
            "-no-boot-anim",
            "-memory", "2048",
            "-cores", "2",
            "-port", str(settings.AVD_EMULATOR_PORT),
            "-snapshot", SNAPSHOT_NAME,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        self.serial = f"emulator-{settings.AVD_EMULATOR_PORT}"

        await self._wait_for_boot()
        logger.info(f"AVD ready: {self.serial}")

    async def stop(self) -> None:
        """Shut down AVD and free ~3GB RAM."""
        logger.info("Shutting down AVD...")
        try:
            await self._adb("emu kill")
        except Exception:
            pass
        if self._emulator_proc:
            try:
                self._emulator_proc.kill()
                await self._emulator_proc.wait()
            except Exception:
                pass
        self._emulator_proc = None
        self.serial = None
        logger.info("AVD stopped")

    async def take_snapshot(self, name: str = SNAPSHOT_NAME) -> None:
        """Save clean state before APK install."""
        await self._adb(f"emu avd snapshot save {name}")
        logger.info(f"Snapshot saved: {name}")

    async def restore_snapshot(self, name: str = SNAPSHOT_NAME) -> None:
        """Restore clean state after analysis."""
        await self._adb(f"emu avd snapshot load {name}")
        logger.info(f"Snapshot restored: {name}")

    async def install_apk(self, apk_path: Path) -> None:
        """Install APK onto running AVD."""
        proc = await asyncio.create_subprocess_exec(
            ADB_BIN, "-s", self.serial, "install", "-r", str(apk_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
        if proc.returncode != 0:
            raise RuntimeError(
                f"APK install failed: {stderr.decode(errors='replace')[:200]}"
            )
        logger.info(f"APK installed: {apk_path.name}")

    async def launch_app(self, package_name: str, activity: str = "") -> None:
        """Launch the installed application."""
        if activity:
            cmd = f"am start -n {package_name}/{activity}"
        else:
            cmd = f"monkey -p {package_name} -c android.intent.category.LAUNCHER 1"
        await self._adb(cmd)
        logger.info(f"App launched: {package_name}")

    async def get_pid(self, package_name: str) -> Optional[int]:
        """Get running PID of the package."""
        result = await self._adb_output(f"pidof {package_name}")
        try:
            return int(result.strip().split()[0])
        except (ValueError, IndexError):
            return None

    async def pull_file(self, device_path: str, local_path: Path) -> bool:
        """Pull a file from the AVD to local disk."""
        proc = await asyncio.create_subprocess_exec(
            ADB_BIN, "-s", self.serial, "pull", device_path, str(local_path),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        if proc.returncode != 0:
            logger.warning(
                f"pull failed {device_path}: {stderr.decode(errors='replace')[:100]}"
            )
            return False
        return True

    async def push_file(self, local_path: Path, device_path: str) -> None:
        """Push a file from local disk to AVD."""
        proc = await asyncio.create_subprocess_exec(
            ADB_BIN, "-s", self.serial, "push", str(local_path), device_path,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=30)

    # ── Internals ────────────────────────────────────────────────────────

    async def _wait_for_boot(self) -> None:
        """Poll adb until device reports boot completed."""
        deadline = time.time() + EMULATOR_READY_TIMEOUT
        while time.time() < deadline:
            result = await self._adb_output(
                "getprop sys.boot_completed", ignore_error=True
            )
            if result.strip() == "1":
                await asyncio.sleep(2)   # allow services to stabilize
                return
            await asyncio.sleep(3)
        raise TimeoutError(
            f"AVD did not boot within {EMULATOR_READY_TIMEOUT}s"
        )

    async def _adb(self, cmd: str) -> None:
        proc = await asyncio.create_subprocess_exec(
            ADB_BIN, "-s", self.serial, "shell", cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.communicate(), timeout=30)

    async def _adb_output(self, cmd: str, ignore_error: bool = False) -> str:
        try:
            proc = await asyncio.create_subprocess_exec(
                ADB_BIN, "-s", self.serial, "shell", cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            return stdout.decode(errors="replace")
        except Exception:
            if ignore_error:
                return ""
            raise
