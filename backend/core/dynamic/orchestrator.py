"""
Garudatva v3 — Dynamic Analysis Orchestrator
Stage 2 entry point: boots the AVD, applies anti-evasion, installs and spawns
the APK under Frida, runs MonkeyRunner + strace + tshark concurrently for a
real 120-second window, tears down, and assembles all artifacts.

This is the glue code that composes the individually-real dynamic modules
(anti_evasion, SandboxManager, FridaController, monkeyrunner, syscall_profiler,
network_capture, memory_dumper) into one session. Every sub-stage here calls
the real subprocess/ADB/Frida path — there is no time.sleep() standing in for
a real wait, and a stage that finishes faster than the enforced floor raises
PipelineIntegrityError rather than returning a plausible-looking result.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from config import settings
from models.ioc import IOC, IOCType, CryptoArtifact, NetworkArtifact
from utils.logger import get_logger

logger = get_logger(__name__)

# Real minimum wall-clock durations. A stage that completes faster than this
# was stubbed/mocked, not executed for real — fail loud rather than ship a
# fake number to a report a judge or officer will ask to see running live.
STAGE_MIN_DURATIONS = {
    "avd_boot": 15,
    "monkey_exercise": settings.MONKEYRUNNER_DURATION - 5,
}


class PipelineIntegrityError(RuntimeError):
    """Raised when a stage completes faster than physically possible for a
    real run — indicates a stubbed/mocked stage, not a genuine execution."""


def _enforce_real_duration(stage: str, elapsed: float) -> None:
    minimum = STAGE_MIN_DURATIONS.get(stage)
    if minimum and elapsed < minimum:
        raise PipelineIntegrityError(
            f"{stage} completed in {elapsed:.1f}s (< {minimum}s floor). "
            f"This indicates the stage was stubbed/mocked, not executed for real."
        )


async def run_dynamic_analysis(
    apk_path: Path,
    work_dir: Path,
    case_id: str,
    package_name: str,
    analysis_id: Optional[str] = None,
    risk_tier: str = "HIGH_RISK",
    custody=None,
) -> Dict[str, Any]:
    """
    Run the full Stage 2 dynamic sandbox session for one APK.

    Sequence (matches the spec's real-timing table):
      1. Boot AVD from clean snapshot, poll for real boot completion
      2. Apply anti-evasion device spoofing
      3. Start frida-server, spawn the APK under Frida (early hook), resume
      4. Concurrently for a real 120s window: MonkeyRunner UI exercise,
         strace syscall profiling, tshark network capture
      5. CRITICAL tier only: dump process memory
      6. Teardown: detach Frida, restore clean snapshot, stop AVD
      7. Assemble IOCs / crypto artifacts / network artifacts / JA4 hashes

    Returns a dict consumed by pipeline.py's dynamic + cloud-C2 stages.
    """
    from core.dynamic.anti_evasion import apply_anti_evasion
    from core.dynamic.frida_controller import FridaController, FridaAttachError
    from core.dynamic.monkeyrunner import run_monkeyrunner
    from core.dynamic.network_capture import capture_network_traffic, parse_pcap_with_ja4
    from core.dynamic.sandbox_manager import SandboxManager
    from core.dynamic.syscall_profiler import profile_syscalls

    from core.event_bus import publish as _publish_event

    work_dir.mkdir(parents=True, exist_ok=True)
    errors: List[str] = []

    def _log(stage: str, action: str) -> None:
        if custody:
            custody.log(stage=stage, action=action, actor="system")
        logger.info(f"[dynamic:{case_id}] {action}")
        if analysis_id:
            _publish_event(analysis_id, {
                "type": "sandbox_stage",
                "data": {"stage": stage, "action": action},
            })

    def _on_frida_event(bucket: str, data: dict) -> None:
        """Live-forward a Frida hook message to the SSE event stream."""
        if not analysis_id:
            return
        event_type = "permission_request" if bucket == "permission" else f"{bucket}_event"
        _publish_event(analysis_id, {"type": event_type, "data": data})

    def _on_monkey_event(action: str, detail: dict) -> None:
        if not analysis_id:
            return
        _publish_event(analysis_id, {
            "type": "monkey_event",
            "data": {"action": action, **detail},
        })

    sandbox = SandboxManager()
    t_boot_start = time.time()
    await sandbox.start()
    _enforce_real_duration("avd_boot", time.time() - t_boot_start)
    try:
        # ── 1. AVD boot (SandboxManager.start() already ran + polled) ───
        _log("DYNAMIC_AVD_BOOT", f"AVD booted: {sandbox.serial}")

        # ── 2. Anti-evasion (synchronous/blocking — run off the event loop) ──
        anti_evasion_result = await asyncio.to_thread(apply_anti_evasion, sandbox.serial)
        _log(
            "DYNAMIC_ANTI_EVASION",
            f"Anti-evasion applied: {len(anti_evasion_result.steps_applied)} steps, "
            f"{len(anti_evasion_result.errors)} errors",
        )

        # ── 3. Install + spawn under Frida ───────────────────────────────
        await sandbox.install_apk(apk_path)
        _log("DYNAMIC_INSTALL", f"APK installed: {apk_path.name}")

        frida_ctl = FridaController(sandbox, on_event=_on_frida_event)
        pid: Optional[int] = None
        try:
            await frida_ctl.setup()
            pid = await frida_ctl.spawn_and_inject(package_name)
        except FridaAttachError as e:
            # Spec requirement: a Frida attach failure fails the job outright,
            # it must never fabricate empty-but-plausible hook data.
            logger.error(f"Frida attach failed: {e}")
            raise
        _log("DYNAMIC_FRIDA_ATTACH", f"Frida attached to {package_name} (pid={pid})")

        # Give the app a moment to finish cold-start before UI exercise begins.
        await asyncio.sleep(3)
        if pid is None:
            pid = await sandbox.get_pid(package_name)

        # ── 4. Concurrent 120s window: monkey + strace + tshark ──────────
        duration = settings.MONKEYRUNNER_DURATION
        t_monkey_start = time.time()

        tasks = [run_monkeyrunner(
            sandbox.serial, package_name, duration_seconds=duration, on_event=_on_monkey_event,
        )]
        if pid:
            tasks.append(profile_syscalls(sandbox.serial, pid, duration_seconds=duration))
        else:
            errors.append("No PID resolved — syscall profiling skipped")
        pcap_path = work_dir / "capture.pcap"
        tasks.append(
            capture_network_traffic(duration_seconds=duration, output_path=str(pcap_path))
        )

        results = await asyncio.gather(*tasks, return_exceptions=True)
        monkey_elapsed = time.time() - t_monkey_start
        _enforce_real_duration("monkey_exercise", monkey_elapsed)

        monkey_stats = results[0] if not isinstance(results[0], Exception) else {}
        if isinstance(results[0], Exception):
            errors.append(f"monkeyrunner: {results[0]}")

        idx = 1
        syscall_result = None
        if pid:
            syscall_result = results[idx] if not isinstance(results[idx], Exception) else None
            if isinstance(results[idx], Exception):
                errors.append(f"syscall_profiler: {results[idx]}")
            idx += 1

        capture_result = results[idx] if not isinstance(results[idx], Exception) else None
        if isinstance(results[idx], Exception):
            errors.append(f"network_capture: {results[idx]}")

        _log(
            "DYNAMIC_MONKEY_WINDOW",
            f"Concurrent {duration}s window complete: "
            f"monkey_taps={monkey_stats.get('taps', 0) if isinstance(monkey_stats, dict) else 0}, "
            f"pcap={'ok' if capture_result else 'none'}",
        )

        # ── 5. CRITICAL tier only: memory dump ───────────────────────────
        memory_dump = None
        if risk_tier == "CRITICAL" and pid:
            from core.dynamic.memory_dumper import dump_process_memory
            memory_dump = await dump_process_memory(
                sandbox.serial, pid, package_name, work_dir / "memdump"
            )
            _log("DYNAMIC_MEMORY_DUMP", f"Memory dump: {memory_dump.dump_size_bytes} bytes")

        # ── Collect Frida hook messages before teardown ──────────────────
        frida_artifacts = frida_ctl.get_artifacts()
        await frida_ctl.stop()

        # ── 6. Teardown: restore clean snapshot ──────────────────────────
        try:
            await sandbox.restore_snapshot()
        except Exception as e:
            errors.append(f"snapshot restore: {e}")
        _log("DYNAMIC_TEARDOWN", "AVD snapshot restored, shutting down")
    finally:
        # Always stop the AVD — crash, exception, or timeout must still
        # free the ~3GB RAM budget for the next stage/job.
        await sandbox.stop()

    # ── 7. Assemble results (outside the AVD context — AVD is now down) ──
    network_artifacts: List[NetworkArtifact] = []
    if capture_result:
        try:
            network_artifacts = await parse_pcap_with_ja4(capture_result)
        except Exception as e:
            errors.append(f"JA4 parse: {e}")

    c2_urls: List[str] = []
    for entry in frida_artifacts.get("network", []):
        url = entry.get("url")
        if url:
            c2_urls.append(url)
            network_artifacts.append(
                NetworkArtifact(
                    url=url,
                    method=entry.get("method", "GET"),
                    host=entry.get("host", ""),
                    interceptor_class=entry.get("interceptor_class"),
                )
            )

    crypto_artifacts = _assemble_crypto_artifacts(frida_artifacts.get("crypto", []))

    iocs: List[IOC] = []
    for url in set(c2_urls):
        iocs.append(IOC(ioc_type=IOCType.URL, value=url, source="frida_network_hook"))
    for na in network_artifacts:
        if na.ip:
            iocs.append(IOC(ioc_type=IOCType.IP, value=na.ip, source="ja4_pcap"))

    ja4_hashes = [na.ja4_hash for na in network_artifacts if na.ja4_hash]

    total_artifacts = (
        len(network_artifacts) + len(crypto_artifacts)
        + sum(len(v) for k, v in frida_artifacts.items() if k not in ("network", "crypto"))
    )
    if analysis_id:
        _publish_event(analysis_id, {
            "type": "sandbox_complete",
            "data": {"artifact_count": total_artifacts},
        })

    return {
        "anti_evasion": {
            "steps_applied": anti_evasion_result.steps_applied,
            "errors": anti_evasion_result.errors,
            "battery_level": anti_evasion_result.battery_level,
        },
        "monkeyrunner_stats": monkey_stats,
        "syscall_profile": (
            {
                "freq": dict(syscall_result.freq),
                "total_calls": syscall_result.total_calls,
                "ml_vector": syscall_result.to_ml_vector(),
            }
            if syscall_result
            else None
        ),
        "network_artifacts": [na.model_dump() for na in network_artifacts],
        "c2_urls": list(set(c2_urls)),
        "crypto_artifacts": crypto_artifacts,
        "ja4_hashes": ja4_hashes,
        "iocs": iocs,
        "frida_artifacts": frida_artifacts,
        "memory_dump": (
            {
                "dump_size_bytes": memory_dump.dump_size_bytes,
                "active_sockets": memory_dump.active_sockets,
                "errors": memory_dump.errors,
            }
            if memory_dump
            else None
        ),
        "pcap_path": str(capture_result) if capture_result else None,
        "errors": errors,
    }


def _assemble_crypto_artifacts(crypto_events: List[dict]) -> List[dict]:
    """
    Merge CIPHER_INIT[_WITH_PARAMS] + CIPHER_DO_FINAL events by cipher_id
    (the Cipher object's hashCode()) into one CryptoArtifact per cipher use,
    per the spec's key-to-payload linkage requirement.
    """
    by_cipher_id: Dict[int, dict] = {}
    for event in crypto_events:
        cipher_id = event.get("cipher_id")
        if cipher_id is None:
            continue
        entry = by_cipher_id.setdefault(cipher_id, {"cipher_id": cipher_id})
        etype = event.get("type")
        if etype in ("CIPHER_INIT", "CIPHER_INIT_WITH_PARAMS"):
            entry["algorithm"] = event.get("algorithm", "")
            entry["mode"] = event.get("opmode")
            entry["timestamp"] = event.get("timestamp")
        elif etype == "CIPHER_DO_FINAL":
            entry["input_length_bytes"] = event.get("input_length_bytes")
            entry["output_length_bytes"] = event.get("output_length_bytes")

    artifacts = []
    for entry in by_cipher_id.values():
        artifacts.append(
            CryptoArtifact(
                cipher_id=entry["cipher_id"],
                algorithm=entry.get("algorithm", "unknown"),
                mode=entry.get("mode") or 0,
                timestamp=entry.get("timestamp"),
            ).model_dump()
        )
    return artifacts
