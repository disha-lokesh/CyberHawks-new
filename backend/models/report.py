"""
Garudatva v3 — Report and evidence models.
"""

from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel, Field
import uuid


class ReportMetadata(BaseModel):
    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    analysis_id: str
    case_id: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    pdf_path: Optional[str] = None
    pdf_sha256: Optional[str] = None
    reporting_officer_signed: bool = False
    reviewing_officer_signed: bool = False
    iso_27037_compliant: bool = True
    iso_27042_compliant: bool = True
    it_act_79a_compliant: bool = True
    bsa_sec63_hash_chain_appended: bool = False
    bnss_176_video_appended: bool = False


class EvidenceItem(BaseModel):
    """Single item in the evidence locker."""
    item_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str
    filename: str
    original_path: str
    stored_path: str
    sha256: str
    md5: str
    sha1: str
    file_size_bytes: int
    mime_type: str
    description: str
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ingested_by: str    # officer badge ID
    bnss_176_compliant: bool = False
    gps_lat: Optional[float] = None
    gps_lon: Optional[float] = None
    witnesses: List[str] = Field(default_factory=list)


class CustodyEvent(BaseModel):
    """Single entry in the BSA Sec 63 custody chain."""
    entry_id: str       # UUIDv7
    sequence: int
    stage: str
    action: str
    actor: str
    timestamp: str      # ISO 8601 UTC
    artifact_sha256: Optional[str] = None
    prev_hash: Optional[str] = None
    entry_hash: str     # SHA256 of canonical JSON of this entry


class CustodyChainManifest(BaseModel):
    analysis_id: str
    case_id: str
    apk_sha256: str
    entries: List[CustodyEvent] = Field(default_factory=list)
    chain_valid: bool = True
    total_entries: int = 0
