"""
Garudatva v3 — Evidence models.
EvidenceItem, VideoEvidence, LockerManifest.
Used by evidence_locker.py, video_ingestor.py, locker_manifest.py.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field
import uuid


class EvidenceType(str, Enum):
    APK_FILE      = "APK_FILE"
    VIDEO_SEIZURE = "VIDEO_SEIZURE"   # BNSS 176(3) mandatory video
    SCREENSHOT    = "SCREENSHOT"
    PCAP          = "PCAP"
    MEMORY_DUMP   = "MEMORY_DUMP"
    FRIDA_LOG     = "FRIDA_LOG"
    REPORT_PDF    = "REPORT_PDF"
    OTHER         = "OTHER"


class IntegrityStatus(str, Enum):
    VERIFIED   = "VERIFIED"    # SHA256 recomputed and matches
    UNVERIFIED = "UNVERIFIED"  # Not yet verified
    CORRUPTED  = "CORRUPTED"   # Hash mismatch — tampered


class EvidenceItem(BaseModel):
    """
    Single item in the encrypted evidence locker.
    Created on every file ingested into Garudatva.
    SHA256 ties directly into BSA Sec 63 custody chain.
    """
    item_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique evidence item ID"
    )
    case_id: str = Field(description="FIR/case reference")
    analysis_id: str = Field(description="Pipeline job ID this evidence belongs to")

    evidence_type: EvidenceType = EvidenceType.OTHER
    filename: str
    original_path: str             # Path on seizure device or upload
    stored_path: str               # Path in encrypted locker

    # Integrity hashes — computed on ingest, never recalculated
    sha256: str
    md5: str
    sha1: str
    file_size_bytes: int

    mime_type: str = "application/octet-stream"
    description: str = ""

    # Chain of custody
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ingested_by: str = ""          # Officer badge ID
    custody_entry_id: str = ""     # Links to CustodyEvent.entry_id

    # Legal compliance
    bnss_176_compliant: bool = False   # BNSS Section 176(3)
    it_act_65b_certified: bool = False # IT Act Section 65B certificate attached

    # Location of seizure (for BNSS 176 mandatory GPS)
    gps_lat: Optional[float] = None
    gps_lon: Optional[float] = None
    gps_accuracy_meters: Optional[float] = None

    # Witnesses (mandatory for BNSS 176(3))
    witnesses: List[str] = Field(default_factory=list)

    # Integrity verification
    integrity_status: IntegrityStatus = IntegrityStatus.UNVERIFIED
    last_verified_at: Optional[datetime] = None
    last_verified_by: Optional[str] = None

    class Config:
        use_enum_values = True


class VideoEvidence(BaseModel):
    """
    BNSS Section 176(3) seizure video.
    Mandatory for offences carrying 7+ year sentences.
    Must be recorded at the time of seizure, not after.
    """
    video_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str
    analysis_id: str

    # File info
    filename: str
    stored_path: str
    sha256: str
    file_size_bytes: int
    duration_seconds: Optional[float] = None
    mime_type: str = "video/mp4"

    # BNSS 176(3) mandatory fields
    recorded_at: datetime                   # Timestamp of recording, NOT upload
    recording_officer_badge: str            # Officer who pressed record
    seizure_location: str                   # Street address / coordinates
    gps_lat: Optional[float] = None
    gps_lon: Optional[float] = None
    device_seized_from: str = ""            # Person name or description
    witnesses: List[str] = Field(default_factory=list)  # Min 2 witnesses required

    # Upload tracking
    uploaded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    uploaded_by: str = ""

    # Chain of custody link
    custody_entry_id: str = ""

    # Exhibit reference for PDF
    exhibit_reference: str = ""    # e.g. "Exhibit A — BNSS 176(3) Seizure Video"

    @property
    def is_bnss_compliant(self) -> bool:
        """Check all BNSS 176(3) mandatory fields are present."""
        return all([
            self.recorded_at is not None,
            self.recording_officer_badge != "",
            self.seizure_location != "",
            len(self.witnesses) >= 2,
            self.sha256 != "",
        ])


class LockerManifest(BaseModel):
    """
    Complete manifest of all items in the evidence locker for one case.
    Appended to forensic PDF as Exhibit A.
    Covers IT Act Section 65B certificate requirements.
    """
    manifest_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str
    analysis_id: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    generated_by: str = ""    # Officer badge ID

    # All evidence items
    items: List[EvidenceItem] = Field(default_factory=list)
    videos: List[VideoEvidence] = Field(default_factory=list)

    # Aggregate hashes — SHA256 of all item hashes concatenated
    manifest_sha256: str = ""

    # Compliance declarations
    iso_27037_compliant: bool = True    # Digital evidence acquisition standard
    bsa_sec63_chain_verified: bool = False
    bnss_176_video_count: int = 0
    total_items: int = 0
    total_size_bytes: int = 0

    # Exhibit reference
    exhibit_label: str = "Exhibit A — Evidence Locker Manifest"

    def compute_totals(self) -> None:
        """Recompute aggregate fields from item list."""
        self.total_items = len(self.items) + len(self.videos)
        self.total_size_bytes = sum(
            i.file_size_bytes for i in self.items
        ) + sum(v.file_size_bytes for v in self.videos)
        self.bnss_176_video_count = len(self.videos)

        # Manifest hash: SHA256 of all item SHA256s concatenated
        import hashlib
        all_hashes = "".join(
            i.sha256 for i in self.items
        ) + "".join(v.sha256 for v in self.videos)
        self.manifest_sha256 = hashlib.sha256(all_hashes.encode()).hexdigest()