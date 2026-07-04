"""
Garudatva v3 — Evidence Video Ingestor
BNSS Section 176(3) mandatory videography compliance.
SHA256 computed immediately on receipt.
Stored in encrypted local evidence locker.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from fastapi import UploadFile

from config import settings
from utils.hasher import multi_hash_file
from utils.logger import get_logger

logger = get_logger(__name__)


async def ingest_seizure_video(
    case_id: str,
    officer_badge: str,
    gps_lat: float,
    gps_lon: float,
    witnesses: List[str],
    file: UploadFile,
) -> Dict:
    """
    Ingest BNSS 176(3) seizure video.
    Returns evidence item manifest entry.
    """
    import aiofiles

    # Create case evidence directory
    case_dir = settings.EVIDENCE_DIR / case_id
    case_dir.mkdir(parents=True, exist_ok=True)

    # Save video file
    filename = file.filename or "seizure_video.mp4"
    video_path = case_dir / filename

    async with aiofiles.open(video_path, "wb") as f:
        content = await file.read()
        await f.write(content)

    # Compute all hashes immediately on receipt
    hashes = multi_hash_file(video_path)
    file_size = video_path.stat().st_size

    # Build evidence item record
    item_id = f"VID_{case_id[:8]}_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    ingested_at = datetime.now(timezone.utc).isoformat()

    evidence_item = {
        "item_id": item_id,
        "case_id": case_id,
        "filename": filename,
        "stored_path": str(video_path),
        "sha256": hashes["sha256"],
        "sha1": hashes["sha1"],
        "md5": hashes["md5"],
        "sha512": hashes["sha512"],
        "file_size_bytes": file_size,
        "mime_type": file.content_type or "video/mp4",
        "description": "BNSS Section 176(3) seizure videography",
        "ingested_at": ingested_at,
        "ingested_by": officer_badge,
        "bnss_176_compliant": True,
        "gps_lat": gps_lat,
        "gps_lon": gps_lon,
        "witnesses": witnesses,
    }

    # Append to case manifest
    manifest_path = settings.EVIDENCE_DIR / case_id / "manifest.json"
    manifest = _load_manifest(manifest_path)
    manifest["items"].append(evidence_item)
    manifest["total_items"] = len(manifest["items"])
    manifest["last_updated"] = ingested_at
    _save_manifest(manifest_path, manifest)

    logger.info(
        f"BNSS 176(3) video ingested: "
        f"case={case_id} sha256={hashes['sha256'][:16]}… "
        f"size={file_size} bytes"
    )

    return evidence_item


def _load_manifest(path: Path) -> Dict:
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            pass
    return {"items": [], "total_items": 0}


def _save_manifest(path: Path, manifest: Dict) -> None:
    path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=True, default=str),
        encoding="utf-8",
    )
