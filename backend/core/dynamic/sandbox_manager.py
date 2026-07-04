"""
Garudatva v3 — Sandbox Manager
AVD lifecycle: boot, snapshot, install, restore, shutdown.
Context manager — always cleans up even on error.
"""

from __future__ import annotations

import asyncio
import os
import platform
import shutil
import subprocess
import time
from pathlib import Path
from typing import List, Optional

from config import settings
from utils.logger import get_logger

logger = get_logger(__name__)

EMULATOR_READY_TIMEOUT = 180   # seconds to wait for boot

SNAPSHOT_NAME = "garudatva_clean"


def _sdk_root() -> str:
    """ANDROID_SDK_ROOT setting takes precedence; falls back to the two
    env vars real Android tooling actually uses (ANDROID_SDK_ROOT is the
    modern name, ANDROID_HOME the legacy one many setups still export)."""
    return settings.ANDROID_SDK_ROOT or os.environ.get("ANDROID_SDK_ROOT", "") or os.environ.get("ANDROID_HOME", "")


def _resolve_bin(name: str, sdk_subpath: str) -> Optional[str]:
    """Resolve an Android SDK tool: prefer <sdk_root>/<sdk_subpath> if an
    SDK root is configured, otherwise fall back to PATH. Returns None if
    neither resolves — the caller turns that into an actionable error
    instead of a bare FileNotFoundError from the subprocess call site."""
    root = _sdk_root()
    if root:
        candidate = Path(root) / sdk_subpath
        if candidate.exists():
            return str(candidate)
    return shutil.which(name)


def _resolve_emulator_bin() -> Optional[str]:
    return _resolve_bin("emulator", "emulator/emulator")


def _resolve_adb_bin() -> Optional[str]:
    return _resolve_bin("adb", "platform-tools/adb")


EMULATOR_BIN = _resolve_emulator_bin() or "emulator"
ADB_BIN = _resolve_adb_bin() or "adb"


def check_sandbox_prerequisites() -> List[str]:
    """
    Validate everything a real Android emulator boot needs, all at once,
    so a misconfigured host gets one clear actionable list instead of
    chasing a new bare FileNotFoundError/timeout after fixing each prior
    one. Returns a list of problem descriptions — empty means ready.
    See scripts/setup_android_sandbox.sh for how to provision all of this.
    """
    problems: List[str] = []

    emulator_bin = _resolve_emulator_bin()
    if not emulator_bin:
        problems.append(
            "Android SDK 'emulator' binary not found. Set ANDROID_SDK_ROOT (or "
            "ANDROID_HOME) to your SDK install, or put <sdk>/emulator on PATH."
        )

    adb_bin = _resolve_adb_bin()
    if not adb_bin:
        problems.append(
            "'adb' binary not found. Set ANDROID_SDK_ROOT (or ANDROID_HOME), "
            "or put <sdk>/platform-tools on PATH."
        )

    if emulator_bin:
        try:
            proc = subprocess.run(
                [emulator_bin, "-list-avds"], capture_output=True, text=True, timeout=15,
            )
            avd_names = {n.strip() for n in proc.stdout.splitlines() if n.strip()}
            if settings.AVD_NAME not in avd_names:
                problems.append(
                    f"No AVD named '{settings.AVD_NAME}' exists (found: {sorted(avd_names) or 'none'}). "
                    f"Create it with avdmanager, or run scripts/setup_android_sandbox.sh."
                )
        except Exception as e:
            problems.append(f"Could not list AVDs ('{emulator_bin} -list-avds' failed: {e})")

    if platform.system() == "Linux" and not Path("/dev/kvm").exists():
        problems.append(
            "/dev/kvm not present — the Android emulator needs KVM hardware-acceleration "
            "on Linux (nested virtualization must be enabled on the host/VM; the emulator "
            "will not boot in reasonable time without it, or at all in a container/VM "
            "that doesn't expose /dev/kvm)."
        )

    return problems


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
        problems = check_sandbox_prerequisites()
        if problems:
            raise RuntimeError(
                "Android sandbox not available on this host:\n- " + "\n- ".join(problems) +
                "\nSee scripts/setup_android_sandbox.sh to provision the emulator/AVD/KVM stack."
            )

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
            await self._adb_emu("kill")
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
        await self._adb_emu("avd", "snapshot", "save", name)
        logger.info(f"Snapshot saved: {name}")

    async def restore_snapshot(self, name: str = SNAPSHOT_NAME) -> None:
        """Restore clean state after analysis."""
        await self._adb_emu("avd", "snapshot", "load", name)
        logger.info(f"Snapshot restored: {name}")

    async def set_geo_location(self, longitude: float, latitude: float) -> None:
        """
        Spoof GPS location via the emulator console (`adb emu geo fix`).
        Some malware geofences itself — staying dormant unless the device
        reports a location matching (or specifically not matching) its
        target region — so being able to set this is a real anti-evasion
        lever, not just device-property spoofing.
        """
        await self._adb_emu("geo", "fix", str(longitude), str(latitude))
        logger.info(f"GPS spoofed: lon={longitude} lat={latitude}")

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

    async def list_packages(self) -> List[str]:
        """
        List all installed package names via the device's own package
        manager. Used to discover the real package name of a just-installed
        APK by diffing the package list before/after `install_apk()` — the
        robust fallback for when static manifest parsing failed (e.g. a
        packed/obfuscated sample) and never gave us a package name to work
        with in the first place. `pm install` always succeeds independent
        of whether our own AndroidManifest.xml parse did, since the device's
        package manager parses the manifest itself at install time.
        """
        output = await self._adb_output("pm list packages", ignore_error=True)
        return [
            line.split("package:", 1)[1].strip()
            for line in output.splitlines()
            if line.startswith("package:")
        ]

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

    async def _adb_emu(self, *args: str) -> None:
        """
        Run an emulator CONSOLE command (`adb -s <serial> emu ...`) — NOT
        the same as `adb shell`. `emu` connects directly to the emulator's
        console port (parsed from the emulator-<port> serial) and is how
        you talk to the AVD itself (snapshots, geo, power, kill), as
        opposed to `shell` which runs a command inside the guest OS.
        Passing an `emu` command through `adb shell` (the previous bug
        here) runs a literal shell command called "emu" on the device,
        which doesn't exist — snapshot save/restore and `emu kill` were
        all silently no-ops.
        """
        proc = await asyncio.create_subprocess_exec(
            ADB_BIN, "-s", self.serial, "emu", *args,
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
