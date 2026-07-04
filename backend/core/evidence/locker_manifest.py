"""
Garudatva v3 — Evidence Locker Manifest
Generates court exhibit listing all evidence items with SHA256 hashes.
Appended to PDF as Exhibit A.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

from config import settings
from utils.logger import get_logger

logger = get_logger(__name__)


def get_case_manifest(case_id: str) -> Dict:
    """Load manifest for a case. Raises FileNotFoundError if not found."""
    manifest_path = settings.EVIDENCE_DIR / case_id / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"No evidence manifest for case {case_id}")
    return json.loads(manifest_path.read_text())


def format_for_pdf(case_id: str) -> str:
    """Format evidence manifest as plain text for PDF exhibit."""
    try:
        manifest = get_case_manifest(case_id)
    except FileNotFoundError:
        return "No evidence items registered for this case."

    lines = [
        "EVIDENCE LOCKER MANIFEST",
        f"Case ID: {case_id}",
        f"Total Items: {manifest.get('total_items', 0)}",
        f"Last Updated: {manifest.get('last_updated', 'N/A')}",
        "",
        "━" * 60,
    ]

    for i, item in enumerate(manifest.get("items", []), 1):
        lines += [
            f"Item {i}: {item.get('filename', 'unknown')}",
            f"  Item ID    : {item.get('item_id', '')}",
            f"  SHA256     : {item.get('sha256', '')}",
            f"  SHA1       : {item.get('sha1', '')}",
            f"  MD5        : {item.get('md5', '')}",
            f"  Size       : {item.get('file_size_bytes', 0):,} bytes",
            f"  Ingested   : {item.get('ingested_at', '')}",
            f"  Officer    : {item.get('ingested_by', '')}",
            f"  GPS        : {item.get('gps_lat', '')}, {item.get('gps_lon', '')}",
            f"  Witnesses  : {', '.join(item.get('witnesses', []))}",
            f"  BNSS 176(3): {'COMPLIANT' if item.get('bnss_176_compliant') else 'N/A'}",
            "",
        ]

    return "\n".join(lines)
