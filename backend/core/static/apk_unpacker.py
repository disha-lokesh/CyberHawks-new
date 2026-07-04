"""
Garudatva v3 — APK Unpacker
Extracts APK contents and builds file inventory.
Uses apktool for resource decoding + standard zip for binary inspection.
"""

from __future__ import annotations

import asyncio
import hashlib
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from utils.logger import get_logger
from utils.hasher import sha256_file

logger = get_logger(__name__)


class APKUnpackResult:
    def __init__(self, apk_path: Path, work_dir: Path):
        self.apk_path = apk_path
        self.work_dir = work_dir
        self.decoded_dir: Optional[Path] = None     # apktool output
        self.zip_dir: Optional[Path] = None          # raw zip extraction
        self.file_inventory: List[Dict] = []
        self.dex_files: List[Path] = []
        self.so_files: List[Path] = []
        self.manifest_path: Optional[Path] = None
        self.assets_dir: Optional[Path] = None
        self.apktool_success: bool = False
        self.errors: List[str] = []


async def unpack_apk(apk_path: Path, work_dir: Path) -> APKUnpackResult:
    """
    Full APK unpacking:
      1. apktool decode → decoded_dir (manifest XML, resources, smali)
      2. zipfile extract → zip_dir (raw DEX, .so, assets as-is)
      3. Build file inventory with SHA256 of every file
    """
    result = APKUnpackResult(apk_path, work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)

    # ── Step 1: apktool decode ─────────────────────────────────────────
    decoded_dir = work_dir / "decoded"
    try:
        proc = await asyncio.create_subprocess_exec(
            "apktool", "d", "-f", "-o", str(decoded_dir), str(apk_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        if proc.returncode == 0:
            result.decoded_dir = decoded_dir
            result.apktool_success = True
            manifest_candidate = decoded_dir / "AndroidManifest.xml"
            if manifest_candidate.exists():
                result.manifest_path = manifest_candidate
            logger.info(f"apktool decode succeeded → {decoded_dir}")
        else:
            err = stderr.decode(errors="replace").strip()
            result.errors.append(f"apktool: {err[:500]}")
            logger.warning(f"apktool decode failed: {err[:200]}")
    except asyncio.TimeoutError:
        result.errors.append("apktool timed out after 120s")
        logger.error("apktool timed out")
    except FileNotFoundError:
        result.errors.append("apktool not found in PATH")
        logger.error("apktool not found — install: sudo pacman -S apktool")

    # ── Step 2: Raw zip extraction ──────────────────────────────────────
    zip_dir = work_dir / "raw"
    try:
        zip_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(apk_path, "r") as zf:
            zf.extractall(zip_dir)
        result.zip_dir = zip_dir

        # Collect DEX files
        result.dex_files = sorted(zip_dir.glob("*.dex"))
        # Collect native .so files
        result.so_files = sorted(zip_dir.rglob("*.so"))
        # Assets dir
        assets = zip_dir / "assets"
        if assets.exists():
            result.assets_dir = assets

        logger.info(
            f"ZIP extracted: {len(result.dex_files)} DEX, "
            f"{len(result.so_files)} .so files"
        )
    except zipfile.BadZipFile as e:
        result.errors.append(f"BadZipFile: {e}")
        logger.error(f"APK is not a valid ZIP: {e}")

    # ── Step 3: File inventory ──────────────────────────────────────────
    result.file_inventory = _build_inventory(zip_dir if zip_dir.exists() else work_dir)

    return result


def _build_inventory(root: Path) -> List[Dict]:
    """Build SHA256 inventory of every file under root."""
    inventory = []
    if not root.exists():
        return inventory

    for f in root.rglob("*"):
        if f.is_file():
            try:
                inventory.append({
                    "path": str(f.relative_to(root)),
                    "size_bytes": f.stat().st_size,
                    "sha256": sha256_file(f),
                    "extension": f.suffix.lower(),
                })
            except Exception as e:
                inventory.append({
                    "path": str(f.relative_to(root)),
                    "size_bytes": 0,
                    "sha256": "error",
                    "extension": f.suffix.lower(),
                    "error": str(e),
                })

    return inventory
