"""
Garudatva v3 — JADX Decompilation + Source-Level SAST
Decompiles the APK to readable Java source (as opposed to dex_analyzer.py's
raw opcode-disassembly strings) and scans that source for hardcoded
secrets, suspicious routes, and dangerous API usage.

Requires the `jadx` CLI (github.com/skylot/jadx) on PATH — install via the
project's BlackArch/pacman setup or download a release for the target OS.
Degrades gracefully (empty result, logged warning) if jadx isn't installed,
matching every other optional-external-tool integration in this codebase.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

from core.static.sast_patterns import scan_text
from utils.logger import get_logger

logger = get_logger(__name__)

JADX_TIMEOUT_SECONDS = 120


@dataclass
class JadxResult:
    available: bool = False
    source_dir: Path = None
    files_scanned: int = 0
    hardcoded_ips: List[str] = field(default_factory=list)
    hardcoded_urls: List[str] = field(default_factory=list)
    suspicious_routes: List[str] = field(default_factory=list)
    secrets_found: List[Dict[str, str]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


async def decompile_and_scan(apk_path: Path, work_dir: Path) -> JadxResult:
    """Run jadx against the APK, then SAST-scan the resulting Java source."""
    result = JadxResult()
    source_dir = work_dir / "jadx_sources"

    try:
        proc = await asyncio.create_subprocess_exec(
            "jadx", "-d", str(work_dir), "--no-res", str(apk_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=JADX_TIMEOUT_SECONDS)
        if proc.returncode not in (0, 1):  # jadx exits 1 on partial-decompile warnings, still usable
            result.errors.append(f"jadx exited {proc.returncode}: {stderr.decode(errors='replace')[:300]}")
    except FileNotFoundError:
        result.errors.append("jadx not installed — skipping source-level SAST scan")
        logger.warning("jadx not found on PATH — install from github.com/skylot/jadx")
        return result
    except asyncio.TimeoutError:
        result.errors.append(f"jadx timed out after {JADX_TIMEOUT_SECONDS}s")
        return result
    except Exception as e:
        result.errors.append(f"jadx invocation failed: {e}")
        return result

    result.available = True
    result.source_dir = source_dir
    _scan_source_tree(source_dir, result)
    logger.info(
        f"JADX SAST scan: {result.files_scanned} files, "
        f"{len(result.hardcoded_ips)} IPs, {len(result.hardcoded_urls)} URLs, "
        f"{len(result.secrets_found)} secrets, {len(result.suspicious_routes)} routes"
    )
    return result


def _scan_source_tree(source_dir: Path, result: JadxResult) -> None:
    """Walk decompiled .java files and apply the SAST patterns above."""
    if not source_dir.exists():
        result.errors.append(f"jadx produced no source output at {source_dir}")
        return

    ips, urls, routes = set(), set(), set()
    for java_file in source_dir.rglob("*.java"):
        try:
            text = java_file.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            result.errors.append(f"read {java_file.name}: {e}")
            continue

        result.files_scanned += 1
        rel_path = java_file.relative_to(source_dir).as_posix()
        f_ips, f_urls, f_routes, f_secrets = scan_text(text, rel_path)
        ips |= f_ips
        urls |= f_urls
        routes |= f_routes
        result.secrets_found.extend(f_secrets)

    result.hardcoded_ips = sorted(ips)[:200]
    result.hardcoded_urls = sorted(urls)[:200]
    result.suspicious_routes = sorted(routes)[:200]
