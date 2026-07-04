"""
Garudatva v3 — Static Triage
Stage 1: runs all static analyzers and assembles feature vector.
~60s, ~800MB RAM on the target machine.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from config import settings
from core.static.apk_unpacker import unpack_apk, APKUnpackResult
from core.static.manifest_parser import parse_manifest, ManifestResult
from core.static.permission_scorer import score_permissions
from core.static.dex_analyzer import analyze_dex, DEXAnalysisResult
from core.static.native_analyzer import analyze_native, NativeAnalysisResult
from core.static.certificate_parser import parse_certificate, CertificateResult
from core.static.yara_scanner import scan_with_yara, YARAScanResult
from core.static.india_patterns import IndiaPatternsEngine
from core.static.ml_classifier import MLClassifier, FEATURE_NAMES
from models.ioc import IOC, IOCType, IndiaPatternMatch, YARAMatch
from models.risk_score import RiskScore, RiskTier, SCORE_COMPONENTS
from utils.logger import get_logger
from utils.ram_monitor import log_ram_snapshot
from utils.hasher import sha256_file

logger = get_logger(__name__)

# Singleton pattern engine (loads once per process)
_pattern_engine = IndiaPatternsEngine()

# Singleton classifier (loads model once)
_classifier = MLClassifier(settings.ML_MODEL_PATH)


@dataclass
class StaticTriageResult:
    apk_path: Path
    apk_sha256: str = ""
    unpack: Optional[APKUnpackResult] = None
    manifest: Optional[ManifestResult] = None
    dex: Optional[DEXAnalysisResult] = None
    native: Optional[NativeAnalysisResult] = None
    cert: Optional[CertificateResult] = None
    yara: Optional[YARAScanResult] = None
    india_matches: List[IndiaPatternMatch] = field(default_factory=list)
    iocs: List[IOC] = field(default_factory=list)
    risk_score: Optional[RiskScore] = None
    feature_vector: List[float] = field(default_factory=list)
    permission_score: float = 0.0
    permission_reasons: List[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    errors: List[str] = field(default_factory=list)


async def run_static_triage(apk_path: Path, work_dir: Path) -> StaticTriageResult:
    """Run all Stage 1 static analysis. Returns full triage result."""
    start = time.time()
    result = StaticTriageResult(apk_path=apk_path)
    log_ram_snapshot("static_triage_start")

    # ── 1a. APK hash ────────────────────────────────────────────────────
    result.apk_sha256 = sha256_file(apk_path)
    logger.info(f"APK SHA256: {result.apk_sha256}")

    # ── 1b. Unpack ──────────────────────────────────────────────────────
    logger.info("Stage 1b: APK unpack")
    result.unpack = await unpack_apk(apk_path, work_dir / "unpack")
    result.errors.extend(result.unpack.errors)

    # ── 1c. Manifest ────────────────────────────────────────────────────
    logger.info("Stage 1c: Manifest parse")
    if result.unpack.manifest_path:
        result.manifest = parse_manifest(result.unpack.manifest_path)
        result.errors.extend(result.manifest.errors)
    else:
        logger.warning("No manifest available — skipping manifest parse")

    # ── 1d. Permissions ─────────────────────────────────────────────────
    if result.manifest:
        result.permission_score, result.permission_reasons = score_permissions(
            result.manifest.permissions
        )

    # ── 1e. Certificate ─────────────────────────────────────────────────
    logger.info("Stage 1e: Certificate parse")
    result.cert = parse_certificate(apk_path)
    result.errors.extend(result.cert.errors)

    # ── 1f. DEX analysis ────────────────────────────────────────────────
    logger.info("Stage 1f: DEX analysis")
    result.dex = analyze_dex(result.unpack.dex_files)
    result.errors.extend(result.dex.errors)

    # ── 1g. Native .so analysis ─────────────────────────────────────────
    logger.info("Stage 1g: Native analysis")
    result.native = analyze_native(result.unpack.so_files)
    result.errors.extend(result.native.errors)

    # ── 1h. YARA scan ───────────────────────────────────────────────────
    logger.info("Stage 1h: YARA scan")
    yara_targets = [apk_path] + result.unpack.dex_files[:3]
    result.yara = scan_with_yara(yara_targets, settings.YARA_RULES_DIR)
    result.errors.extend(result.yara.errors)

    # ── 1i. India patterns ──────────────────────────────────────────────
    logger.info("Stage 1i: India patterns (47)")
    corpus_parts = []
    if result.dex:
        corpus_parts.extend(result.dex.all_strings[:5000])
    if result.manifest:
        corpus_parts.append(result.manifest.raw_xml)
    result.india_matches = _pattern_engine.scan_strings_list(corpus_parts)

    # ── 1j. Feature vector ──────────────────────────────────────────────
    result.feature_vector = _build_feature_vector(result)

    # ── 1k. ML inference ────────────────────────────────────────────────
    logger.info("Stage 1k: ML inference")
    _classifier.load()
    ml_prob, shap_features = _classifier.predict(result.feature_vector)

    # ── 1l. Risk score assembly ─────────────────────────────────────────
    result.risk_score = _assemble_risk_score(result, ml_prob, shap_features)

    # ── IOC extraction ──────────────────────────────────────────────────
    result.iocs = _extract_iocs(result)

    result.elapsed_seconds = time.time() - start
    log_ram_snapshot("static_triage_end")
    logger.info(
        f"Static triage complete: "
        f"risk={result.risk_score.total:.1f} ({result.risk_score.tier}) "
        f"in {result.elapsed_seconds:.1f}s"
    )
    return result


def _build_feature_vector(r: StaticTriageResult) -> List[float]:
    """Construct the 87-dimensional feature vector from all analyzer outputs."""
    m = r.manifest
    d = r.dex
    n = r.native
    c = r.cert
    y = r.yara

    # India pattern counts by category
    india_cats: Dict[str, int] = {}
    for match in r.india_matches:
        india_cats[match.category] = india_cats.get(match.category, 0) + 1

    # Permission helpers
    perms = set(m.permissions) if m else set()
    def p(perm_suffix): return 1.0 if f"android.permission.{perm_suffix}" in perms else 0.0

    # YARA helpers
    yara_cats = set(y.categories_hit) if y else set()
    def yc(cat): return 1.0 if cat in yara_cats else 0.0

    # Cert helpers
    cert_validity_years = 0.0
    if c and c.valid_from and c.valid_until:
        try:
            from datetime import datetime
            vf = datetime.fromisoformat(c.valid_from.replace("Z", "+00:00"))
            vu = datetime.fromisoformat(c.valid_until.replace("Z", "+00:00"))
            cert_validity_years = (vu - vf).days / 365
        except Exception:
            pass

    fv = [
        # Permissions (15)
        p("READ_SMS"), p("RECEIVE_SMS"), p("SEND_SMS"),
        p("READ_CONTACTS"), p("READ_CALL_LOG"),
        p("RECORD_AUDIO"), p("CAMERA"),
        p("SYSTEM_ALERT_WINDOW"), p("BIND_ACCESSIBILITY_SERVICE"),
        p("BIND_DEVICE_ADMIN"), p("REQUEST_INSTALL_PACKAGES"),
        p("ACCESS_FINE_LOCATION"), p("ACCESS_BACKGROUND_LOCATION"),
        p("USE_BIOMETRIC"), p("PROCESS_OUTGOING_CALLS"),
        # Manifest (8)
        1.0 if (m and m.debuggable) else 0.0,
        1.0 if (m and m.uses_cleartext_traffic) else 0.0,
        1.0 if (m and m.allow_backup) else 0.0,
        float(len(m.permissions)) if m else 0.0,
        float(len(m.activities)) if m else 0.0,
        float(len(m.services)) if m else 0.0,
        float(len(m.receivers)) if m else 0.0,
        float(m.obfuscation_score) if m else 0.0,
        # DEX (12)
        float(min(len(d.all_strings), 10000)) if d else 0.0,
        float(len(d.urls)) if d else 0.0,
        float(len(d.ips)) if d else 0.0,
        float(len(d.class_names)) if d else 0.0,
        1.0 if (d and d.reflection_used) else 0.0,
        1.0 if (d and d.dynamic_loading) else 0.0,
        float(d.obfuscation_level) if d else 0.0,
        float(len(d.crypto_classes)) if d else 0.0,
        float(len(d.network_classes)) if d else 0.0,
        float(len(d.suspicious_apis)) if d else 0.0,
        float(len(d.phone_numbers)) if d else 0.0,
        float(len(d.encoded_payloads)) if d else 0.0,
        # Certificate (5)
        1.0 if (c and c.is_debug_cert) else 0.0,
        1.0 if (c and c.is_expired) else 0.0,
        1.0 if (c and c.is_self_signed) else 0.0,
        float(c.anomaly_score) if c else 0.0,
        float(min(cert_validity_years, 50)),
        # YARA (6)
        yc("UPI_FRAUD"), yc("BANKING_TROJAN"), yc("FAKE_LOAN"),
        yc("AADHAAR"), yc("RAT"), yc("C2"),
        # India patterns (8)
        float(india_cats.get("UPI_FRAUD", 0)),
        float(india_cats.get("FAKE_LOAN", 0)),
        float(india_cats.get("AADHAAR", 0)),
        float(india_cats.get("BANKING_TROJAN", 0)),
        float(india_cats.get("RAT", 0)),
        float(india_cats.get("SOCIAL_FRAUD", 0)),
        float(india_cats.get("GOV_FRAUD", 0)),
        float(india_cats.get("CRYPTO_FRAUD", 0)),
        # Native (7)
        float(min(len(n.suspicious_imports), 20)) if n else 0.0,
        float(min(len(n.suspicious_strings), 20)) if n else 0.0,
        1.0 if (n and n.frida_detection) else 0.0,
        1.0 if (n and n.root_detection) else 0.0,
        1.0 if (n and n.emulator_detection) else 0.0,
        float(len(n.so_files_analyzed)) if n else 0.0,
        float(n.native_risk_score) if n else 0.0,
        # Syscall (10) — zeros at static stage
        0.0, 0.0, 0.0, 0.0, 0.0,
        0.0, 0.0, 0.0, 0.0, 0.0,
        # Network dynamic (6) — zeros at static stage
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
        # Risk score components (10)
        float(r.permission_score),
        float(len(r.india_matches)),
        float(y.yara_score) if y else 0.0,
        float(m.obfuscation_score * 1.0) if m else 0.0,
        float(c.anomaly_score) if c else 0.0,
        float(n.native_risk_score) if n else 0.0,
        0.0,   # cloud_c2_score — dynamic stage
        0.0,   # evasion_score — dynamic stage
        float(len(m.toxic_permissions)) if m else 0.0,
        float(len(m.dangerous_components)) if m else 0.0,
    ]

    assert len(fv) == 87, f"Feature vector length mismatch: {len(fv)}"
    return fv


def _assemble_risk_score(
    r: StaticTriageResult, ml_prob: float, shap_features
) -> RiskScore:
    """Compute final risk score from all component contributions."""
    m = r.manifest
    y = r.yara
    c = r.cert

    # Core components
    ml_score = ml_prob * SCORE_COMPONENTS["ml_classifier"]
    syscall_score = 0.0   # Set by dynamic analysis later
    yara_score = (y.yara_score / 20.0) * SCORE_COMPONENTS["yara_matches"] if y else 0.0
    perm_score = (r.permission_score / 10.0) * SCORE_COMPONENTS["toxic_permissions"]
    india_score = (
        min(len(r.india_matches) / 10.0, 1.0) * SCORE_COMPONENTS["india_pattern_matches"]
    )
    cert_score = (
        (c.anomaly_score / 5.0) * SCORE_COMPONENTS["certificate_anomalies"] if c else 0.0
    )
    manifest_score = (
        (m.obfuscation_score / 5.0) * SCORE_COMPONENTS["manifest_obfuscation"] if m else 0.0
    )

    total = (
        ml_score + syscall_score + yara_score +
        perm_score + india_score + cert_score + manifest_score
    )
    total = min(total, 100.0)
    tier = RiskScore.compute_tier(total)

    return RiskScore(
        total=round(total, 2),
        tier=tier,
        ml_score=round(ml_score, 2),
        syscall_score=0.0,
        yara_score=round(yara_score, 2),
        permission_score=round(perm_score, 2),
        india_pattern_score=round(india_score, 2),
        cert_score=round(cert_score, 2),
        manifest_score=round(manifest_score, 2),
        ml_probability=round(ml_prob, 4),
        shap_features=shap_features or [],
        flags={
            "dynamic_loading": r.dex.dynamic_loading if r.dex else False,
            "reflection": r.dex.reflection_used if r.dex else False,
            "frida_detection": r.native.frida_detection if r.native else False,
            "emulator_detection": r.native.emulator_detection if r.native else False,
            "root_detection": r.native.root_detection if r.native else False,
        },
    )


def _extract_iocs(r: StaticTriageResult) -> List[IOC]:
    """Pull all IOCs from static analysis results."""
    iocs: List[IOC] = []

    if r.dex:
        for url in r.dex.urls[:50]:
            iocs.append(IOC(ioc_type=IOCType.URL, value=url, source="dex_strings"))
        for ip in r.dex.ips[:30]:
            iocs.append(IOC(ioc_type=IOCType.IP, value=ip, source="dex_strings"))
        for phone in r.dex.phone_numbers[:20]:
            iocs.append(IOC(ioc_type=IOCType.PHONE_NUMBER, value=phone, source="dex_strings"))

    if r.cert and r.cert.signing_cert_sha1:
        iocs.append(
            IOC(
                ioc_type=IOCType.CERTIFICATE_SHA1,
                value=r.cert.signing_cert_sha1,
                source="certificate",
                context=r.cert.subject[:100],
            )
        )

    if r.manifest and r.manifest.package_name:
        iocs.append(
            IOC(
                ioc_type=IOCType.PACKAGE_NAME,
                value=r.manifest.package_name,
                source="manifest",
            )
        )

    return iocs
