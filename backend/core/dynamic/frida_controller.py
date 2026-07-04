"""
Garudatva v3 — Frida Controller
Manages Frida server deployment, script injection, and artifact collection.
Uses spawn mode (device.spawn) for early hooking before app initialization runs.

All 7 hook scripts (core/dynamic/hook/*.js) report findings via Frida's
send()/on('message') RPC channel, not by writing files on the device — so
this controller attaches a message handler and collects payloads in-process
via the real `frida` Python bindings (frida.get_usb_device().spawn/attach),
not the `frida` CLI subprocess.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)

FRIDA_SERVER_DEVICE_PATH = "/data/local/tmp/frida-server"
# Hook scripts live alongside this module, in core/dynamic/hook/.
FRIDA_SCRIPTS_DIR = Path(__file__).parent / "hook"

HOOK_SCRIPTS = [
    "network_intercept.js",
    "crypto_key_extract.js",
    "interceptor_hooks.js",
    "sms_intercept.js",
    "clipboard_intercept.js",
    "accessibility_intercept.js",
    "permission_intercept.js",
]

# Maps the outer `send({type: "<bucket>_event", ...})` type used by every
# hook script to the bucket its payloads are collected under.
MESSAGE_BUCKETS = ["network", "crypto", "sms", "interceptor", "clipboard", "accessibility", "permission"]


class FridaAttachError(RuntimeError):
    """Raised when Frida fails to spawn/attach/load the hook script — the
    dynamic stage must fail loudly on this, never fabricate hook output."""


class FridaController:
    def __init__(self, sandbox, on_event=None):
        """
        on_event: optional callable(bucket: str, data: dict), invoked
        synchronously on Frida's own message-dispatch thread the instant a
        hook fires — used to publish live events (e.g. to core.event_bus)
        for real-time UI streaming, in addition to the end-of-session
        self.messages collection.
        """
        self.sandbox = sandbox
        self.on_event = on_event
        self._device = None
        self._session = None
        self._script = None
        self._pid: Optional[int] = None
        self.messages: Dict[str, List[dict]] = {b: [] for b in MESSAGE_BUCKETS}
        self._script_errors: List[str] = []

    async def setup(self) -> None:
        """Push frida-server to AVD and start it (frida-server mode)."""
        server_path = self._find_frida_server()
        if server_path:
            device_abi = (await self.sandbox._adb_output(
                "getprop ro.product.cpu.abi", ignore_error=True
            )).strip()
            if device_abi and device_abi not in server_path.name:
                raise FridaAttachError(
                    f"frida-server arch mismatch: device ABI is '{device_abi}' "
                    f"but selected binary is '{server_path.name}'. Wrong-arch "
                    f"frida-server attaches to nothing and silently returns "
                    f"empty hook data — refusing to proceed."
                )
            await self.sandbox.push_file(server_path, FRIDA_SERVER_DEVICE_PATH)
            await self.sandbox._adb(f"chmod 755 {FRIDA_SERVER_DEVICE_PATH}")
            await self.sandbox._adb(f"{FRIDA_SERVER_DEVICE_PATH} &")
            await asyncio.sleep(2)
            logger.info("Frida server started on AVD")
        else:
            logger.warning(
                "frida-server binary not found on host — assuming a "
                "frida-gadget build is already embedded on the AVD image"
            )

    async def spawn_and_inject(self, package_name: str) -> int:
        """
        Spawn the target package under Frida (early hooking, before app
        init runs), inject all 6 hook scripts as one combined script, and
        resume the process. Returns the spawned PID.

        Raises FridaAttachError on any failure — per spec, an attach
        failure must fail the job, never silently produce empty hook data.
        """
        combined_script = self._build_combined_script()

        def _blocking_spawn():
            import frida

            device = frida.get_usb_device(timeout=15)
            pid = device.spawn([package_name])
            session = device.attach(pid)
            script = session.create_script(combined_script)
            script.on("message", self._on_message)
            script.load()
            device.resume(pid)
            return device, session, script, pid

        try:
            self._device, self._session, self._script, pid = await asyncio.to_thread(
                _blocking_spawn
            )
        except Exception as e:
            raise FridaAttachError(f"Frida spawn/attach/load failed for {package_name}: {e}") from e

        self._pid = pid
        logger.info(f"Frida hooks injected into {package_name} (spawn mode, pid={pid})")
        return pid

    def _on_message(self, message: dict, data) -> None:
        """Handler for script.on('message', ...) — runs on Frida's own thread."""
        if message.get("type") == "error":
            err = message.get("description", str(message))
            logger.warning(f"Frida script error: {err}")
            self._script_errors.append(err)
            return
        if message.get("type") != "send":
            return
        payload = message.get("payload") or {}
        msg_type = str(payload.get("type", ""))
        if not msg_type.endswith("_event"):
            return
        bucket = msg_type[: -len("_event")]
        if bucket in self.messages:
            event_data = payload.get("data", {})
            self.messages[bucket].append(event_data)
            if self.on_event:
                try:
                    self.on_event(bucket, event_data)
                except Exception as e:
                    logger.debug(f"on_event callback error: {e}")

    def get_artifacts(self) -> Dict[str, List[dict]]:
        """Return all hook messages collected so far, bucketed by category."""
        return {k: list(v) for k, v in self.messages.items()}

    async def stop(self) -> None:
        """Detach the Frida session. Does not kill the target process."""
        try:
            if self._session is not None:
                await asyncio.to_thread(self._session.detach)
        except Exception as e:
            logger.debug(f"Frida session detach: {e}")
        self._session = None
        self._script = None

    def _build_combined_script(self) -> str:
        """Concatenate all 6 hook scripts with error isolation per script."""
        parts = ["'use strict';", ""]
        found_any = False
        for script_name in HOOK_SCRIPTS:
            script_path = FRIDA_SCRIPTS_DIR / script_name
            if script_path.exists():
                content = script_path.read_text(encoding="utf-8")
                parts.append(f"// ── {script_name} ──────────────────────────")
                parts.append("try {")
                parts.append(content)
                parts.append("} catch(e) {")
                parts.append(f"  send({{type: 'error', description: '[garudatva] {script_name} failed: ' + e.message}});")
                parts.append("}")
                parts.append("")
                found_any = True
            else:
                logger.warning(f"Hook script not found: {script_path}")
        if not found_any:
            raise FridaAttachError(f"No hook scripts found in {FRIDA_SCRIPTS_DIR}")
        return "\n".join(parts)

    def _find_frida_server(self) -> Optional[Path]:
        """Find a local frida-server binary matching the installed frida version."""
        import frida
        version = frida.__version__
        candidates = [
            Path(f"/opt/frida/frida-server-{version}-android-arm64"),
            Path(f"/opt/frida/frida-server-{version}-android-x86_64"),
            Path(f"/tmp/frida-server-{version}-android-arm64"),
            Path(f"/tmp/frida-server-{version}-android-x86_64"),
            Path("./frida-server"),
        ]
        for p in candidates:
            if p.exists():
                return p
        return None
