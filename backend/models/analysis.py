"""
Garudatva v3 — Analysis models.
Covers case metadata, pipeline state, and full analysis result.
"""

from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator
import uuid


class RiskTier(str, Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    CRITICAL = "CRITICAL"


class PipelineStage(str, Enum):
    QUEUED = "QUEUED"
    STATIC_TRIAGE = "STATIC_TRIAGE"
    DYNAMIC_ANALYSIS = "DYNAMIC_ANALYSIS"
    CLOUD_C2_DETECTION = "CLOUD_C2_DETECTION"
    NEO4J_GRAPH = "NEO4J_GRAPH"
    LLM_NARRATIVE = "LLM_NARRATIVE"
    PDF_GENERATION = "PDF_GENERATION"
    JARM_PROBE = "JARM_PROBE"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"


class OfficerInfo(BaseModel):
    officer_id: str
    badge_id: str
    name: str
    rank: str
    station: str
    district: str


class DeviceInfo(BaseModel):
    imei: str
    make: str
    model: str
    android_version: str
    serial_number: Optional[str] = None


class CaseMetadata(BaseModel):
    """Wizard Step 1-5 mandatory fields."""
    fir_number: str
    district: str
    station: str
    reporting_officer: OfficerInfo
    reviewing_officer: OfficerInfo
    device: DeviceInfo
    seizure_video_hash: Optional[str] = None
    seizure_gps_lat: Optional[float] = None
    seizure_gps_lon: Optional[float] = None
    seizure_witnesses: List[str] = Field(default_factory=list)
    case_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AnalysisRequest(BaseModel):
    case_id: str
    apk_filename: str
    apk_sha256: str
    run_dynamic: bool = True
    run_jarm: bool = False   # Workstation B only
    priority: int = Field(default=5, ge=1, le=10)


class StageResult(BaseModel):
    stage: PipelineStage
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    status: str = "pending"   # pending | running | done | failed
    error: Optional[str] = None
    artifacts: Dict[str, Any] = Field(default_factory=dict)


class AnalysisStatus(BaseModel):
    analysis_id: str
    case_id: str
    apk_filename: str = ""
    current_stage: PipelineStage
    stages: Dict[str, StageResult] = Field(default_factory=dict)
    risk_score: Optional[float] = None
    risk_tier: Optional[RiskTier] = None
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
