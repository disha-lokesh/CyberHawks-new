"""
Garudatva v3 — Risk score model with full component breakdown.
"""

from __future__ import annotations
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
from models.analysis import RiskTier


SCORE_COMPONENTS = {
    "ml_classifier":         35,
    "syscall_profile":       15,
    "yara_matches":          20,
    "toxic_permissions":     10,
    "india_pattern_matches": 10,
    "certificate_anomalies":  5,
    "manifest_obfuscation":   5,
}

CLOUD_C2_ADDITIONS = {
    "connects_to_cloud_asn":     10,
    "dga_domain_detected":       15,
    "domain_fronting_detected":  25,
    "firebase_c2_pattern":       20,
    "tunnel_service_detected":   30,
}

EVASION_ADDITIONS = {
    "has_anti_emulator_code":    15,
    "has_frida_detection":       20,
    "has_root_detection":        10,
    "has_debugger_detection":    10,
}


class SHAPFeature(BaseModel):
    feature_name: str
    shap_value: float
    feature_value: float
    rank: int


class RiskScore(BaseModel):
    total: float = Field(ge=0.0, le=100.0)
    tier: RiskTier

    # Component breakdown
    ml_score: float = 0.0          # RF probability × 35
    syscall_score: float = 0.0     # strace anomaly × 15
    yara_score: float = 0.0        # per category hit
    permission_score: float = 0.0
    india_pattern_score: float = 0.0
    cert_score: float = 0.0
    manifest_score: float = 0.0
    sast_score: float = 0.0        # hardcoded secrets found in jadx-decompiled source
    config_score: float = 0.0      # network_security_config / backup-rule anomalies
    dependency_score: float = 0.0  # ad-SDK bundling density (adware pattern)

    # Additions
    cloud_c2_additions: Dict[str, float] = Field(default_factory=dict)
    evasion_additions: Dict[str, float] = Field(default_factory=dict)

    # ML explainability
    ml_probability: float = 0.0    # raw RF probability
    shap_features: List[SHAPFeature] = Field(default_factory=list)

    # Flags
    flags: Dict[str, bool] = Field(default_factory=dict)

    # Set when static analysis couldn't get a clean read on the APK
    # (unpack failure, near-zero string yield, unparseable manifest) —
    # treated as an evasion signal in its own right, not a null result.
    analysis_degraded: bool = False
    degradation_reasons: List[str] = Field(default_factory=list)

    @classmethod
    def compute_tier(cls, total: float) -> RiskTier:
        if total >= 85:
            return RiskTier.CRITICAL
        elif total >= 65:
            return RiskTier.HIGH_RISK
        elif total >= 30:
            return RiskTier.SUSPICIOUS
        else:
            return RiskTier.BENIGN
