"""
Garudatva v3 — Ghidra Headless Decompilation + Native SAST
Decompiles bundled native .so libraries to C-like pseudocode using
Ghidra's headless analyzer (a proper decompiler, not just r2pipe's
imports/exports/strings view in native_analyzer.py), then applies the
same source-level SAST patterns jadx_decompiler.py uses on Java source
to the decompiled native pseudocode.

Requires a Ghidra install with `support/analyzeHeadless` reachable via
GHIDRA_HOME (env var) or on PATH. Ghidra headless analysis is slow
(minutes per binary, even small ones, due to auto-analysis) and heavy
(multi-GB install, JDK 17+) — this is capped to a handful of the
smallest bundled .so files and degrades gracefully (empty result,
logged warning) if Ghidra isn't installed, matching every other
optional-external-tool integration in this codebase.
"""

from __future__ import annotations

import asyncio
import shutil
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from core.static.sast_patterns import scan_text
from utils.logger import get_logger

logger = get_logger(__name__)

GHIDRA_TIMEOUT_SECONDS = 300         # headless analysis is slow even for small binaries
MAX_SO_FILES = 3                     # cap — each run is expensive
MAX_SO_SIZE_BYTES = 20 * 1024 * 1024  # skip large libs; not worth the analysis time


@dataclass
class GhidraResult:
    available: bool = False
    so_files_analyzed: List[str] = field(default_factory=list)
    hardcoded_ips: List[str] = field(default_factory=list)
    hardcoded_urls: List[str] = field(default_factory=list)
    suspicious_routes: List[str] = field(default_factory=list)
    secrets_found: List[Dict[str, str]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


def _find_analyze_headless() -> Optional[str]:
    import os
    ghidra_home = os.environ.get("GHIDRA_HOME", "")
    if ghidra_home:
        candidate = Path(ghidra_home) / "support" / "analyzeHeadless"
        if candidate.exists():
            return str(candidate)
    return shutil.which("analyzeHeadless")


async def decompile_native_and_scan(so_files: List[Path], work_dir: Path) -> GhidraResult:
    """Run Ghidra headless against a capped set of bundled .so files, then
    SAST-scan the decompiled pseudocode output."""
    result = GhidraResult()

    analyze_headless = _find_analyze_headless()
    if not analyze_headless:
        result.errors.append(
            "Ghidra not installed (GHIDRA_HOME unset and analyzeHeadless not on PATH) "
            "— skipping native decompilation"
        )
        logger.warning("Ghidra analyzeHeadless not found — install from ghidra-sre.org")
        return result

    candidates = sorted(
        (p for p in so_files if p.stat().st_size <= MAX_SO_SIZE_BYTES),
        key=lambda p: p.stat().st_size,
    )[:MAX_SO_FILES]

    if not candidates:
        result.errors.append("No .so files within size cap for Ghidra analysis")
        return result

    result.available = True
    scripts_dir = Path(__file__).parent / "ghidra_scripts"
    project_dir = work_dir / "ghidra_projects"
    project_dir.mkdir(parents=True, exist_ok=True)

    ips, urls, routes = set(), set(), set()
    for so_path in candidates:
        try:
            out_path = work_dir / f"{so_path.stem}_{uuid.uuid4().hex[:8]}.decompiled.c"
            project_name = f"proj_{uuid.uuid4().hex[:8]}"
            proc = await asyncio.create_subprocess_exec(
                analyze_headless, str(project_dir), project_name,
                "-import", str(so_path),
                "-postScript", "dump_decompiled.py", str(out_path),
                "-scriptPath", str(scripts_dir),
                "-deleteProject",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=GHIDRA_TIMEOUT_SECONDS)
            if proc.returncode != 0:
                result.errors.append(
                    f"Ghidra exited {proc.returncode} for {so_path.name}: "
                    f"{stderr.decode(errors='replace')[:300]}"
                )
                continue

            if not out_path.exists():
                result.errors.append(f"Ghidra produced no decompiled output for {so_path.name}")
                continue

            text = out_path.read_text(encoding="utf-8", errors="replace")
            f_ips, f_urls, f_routes, f_secrets = scan_text(text, so_path.name)
            ips |= f_ips
            urls |= f_urls
            routes |= f_routes
            result.secrets_found.extend(f_secrets)
            result.so_files_analyzed.append(so_path.name)
        except asyncio.TimeoutError:
            result.errors.append(f"Ghidra timed out after {GHIDRA_TIMEOUT_SECONDS}s on {so_path.name}")
        except Exception as e:
            result.errors.append(f"Ghidra analysis failed on {so_path.name}: {e}")
            logger.error(f"Ghidra analysis crashed on {so_path.name}: {e}", exc_info=True)

    result.hardcoded_ips = sorted(ips)[:200]
    result.hardcoded_urls = sorted(urls)[:200]
    result.suspicious_routes = sorted(routes)[:200]
    logger.info(
        f"Ghidra native SAST: {len(result.so_files_analyzed)} .so decompiled, "
        f"{len(result.hardcoded_ips)} IPs, {len(result.hardcoded_urls)} URLs, "
        f"{len(result.secrets_found)} secrets"
    )
    return result
