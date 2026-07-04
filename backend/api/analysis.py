"""
Garudatva v3 — Analysis API
POST /analyze          — upload APK, validate, start pipeline
GET  /status/{id}      — Server-Sent Events stream for live pipeline updates
GET  /result/{id}      — complete JSON result
GET  /custody/{id}     — custody chain manifest
GET  /custody/{id}/verify — verify chain integrity
"""

from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path
from typing import AsyncGenerator

import aiofiles
from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse, StreamingResponse

from config import settings
from core.pipeline import start_analysis, get_job_status, get_job_results, list_job_statuses
from models.analysis import AnalysisRequest, CaseMetadata, OfficerInfo, DeviceInfo
from utils.hasher import sha256_file
from utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter()

# In-memory case store (keyed by case_id)
_cases: dict = {}


@router.post("/cases")
async def create_case(case: CaseMetadata):
    """
    Register case metadata from the Case Setup Wizard.
    Returns case_id. Must be called before /analyze.
    """
    _cases[case.case_id] = case
    logger.info(f"Case registered: {case.case_id} FIR={case.fir_number}")
    return {"case_id": case.case_id, "status": "registered"}


@router.post("/analyze")
async def analyze_apk(
    case_id: str = Form(...),
    file: UploadFile = File(...),
):
    """
    Upload APK for analysis.
    Validates file, computes SHA256, starts pipeline.
    Returns analysis_id for status polling.
    """
    # Validate case exists
    case = _cases.get(case_id)
    if not case:
        raise HTTPException(
            status_code=404,
            detail=f"Case {case_id} not found. Complete Case Setup Wizard first.",
        )

    # Validate file extension
    filename = file.filename or "unknown.apk"
    if not filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="Only .apk files accepted")

    # Save uploaded file
    analysis_id = str(uuid.uuid4())
    upload_path = settings.UPLOAD_DIR / analysis_id
    upload_path.mkdir(parents=True, exist_ok=True)
    apk_path = upload_path / filename

    async with aiofiles.open(apk_path, "wb") as f:
        content = await file.read()
        await f.write(content)

    # Compute SHA256
    apk_sha256 = sha256_file(apk_path)
    logger.info(f"APK uploaded: {filename} sha256={apk_sha256[:16]}…")

    request = AnalysisRequest(
        case_id=case_id,
        apk_filename=filename,
        apk_sha256=apk_sha256,
    )

    # Start pipeline (non-blocking) — pass our analysis_id through so the ID
    # returned to the client below matches the one the job is tracked under.
    await start_analysis(request, case, apk_path, analysis_id=analysis_id)

    return {
        "analysis_id": analysis_id,
        "case_id": case_id,
        "filename": filename,
        "sha256": apk_sha256,
        "status": "pipeline_started",
        "status_url": f"/api/v1/status/{analysis_id}",
        "result_url": f"/api/v1/result/{analysis_id}",
    }


@router.get("/analyses")
async def list_analyses():
    """
    History list of every analysis run against this backend process
    (in-memory only, like all other job state here — clears on restart).
    Powers the frontend's history/dashboard view of past analyses.
    """
    out = []
    for status in list_job_statuses():
        case = _cases.get(status.case_id)
        out.append({
            "analysis_id": status.analysis_id,
            "case_id": status.case_id,
            "fir_number": case.fir_number if case else None,
            "apk_filename": status.apk_filename,
            "current_stage": status.current_stage,
            "risk_score": status.risk_score,
            "risk_tier": status.risk_tier,
            "started_at": status.started_at,
            "completed_at": status.completed_at,
            "error": status.error,
        })
    return {"analyses": out, "count": len(out)}


@router.get("/status/{analysis_id}")
async def stream_status(analysis_id: str):
    """
    Server-Sent Events stream for real-time pipeline updates.

    Merges two sources into one stream, each event tagged with a `type`:
      - "pipeline_status": stage-level snapshot (polled every 1.5s), same
        shape as before.
      - granular live events published during dynamic analysis — e.g.
        "network_event", "crypto_event", "sms_event", "clipboard_event",
        "accessibility_event", "permission_request", "monkey_event",
        "sandbox_stage", "sandbox_complete" — via core.event_bus, the
        instant a Frida hook or MonkeyRunner action fires.
    """
    from core.event_bus import subscribe as subscribe_events

    async def event_generator() -> AsyncGenerator[str, None]:
        out_queue: asyncio.Queue = asyncio.Queue()
        stop = asyncio.Event()

        async def poll_stage_status():
            while not stop.is_set():
                status = get_job_status(analysis_id)
                if status is None:
                    await out_queue.put({"type": "error", "data": {"error": "analysis_id not found"}})
                    stop.set()
                    return

                await out_queue.put({
                    "type": "pipeline_status",
                    "analysis_id": analysis_id,
                    "current_stage": status.current_stage,
                    "risk_score": status.risk_score,
                    "risk_tier": status.risk_tier,
                    "stages": {
                        name: {
                            "status": sr.status,
                            "duration_seconds": sr.duration_seconds,
                            "artifacts": sr.artifacts,
                            "error": sr.error,
                        }
                        for name, sr in status.stages.items()
                    },
                })

                if status.current_stage in ("COMPLETE", "FAILED"):
                    stop.set()
                    return
                await asyncio.sleep(1.5)

        async def relay_live_events():
            async for event in subscribe_events(analysis_id):
                if stop.is_set():
                    return
                await out_queue.put(event)

        poller = asyncio.create_task(poll_stage_status())
        relay = asyncio.create_task(relay_live_events())

        try:
            elapsed = 0
            while elapsed < 3600:  # max 1 hour stream
                try:
                    event = await asyncio.wait_for(out_queue.get(), timeout=2.0)
                    yield _sse_event(event)
                    if event.get("type") in ("pipeline_status",) and event.get("current_stage") in ("COMPLETE", "FAILED"):
                        break
                    if event.get("type") == "error":
                        break
                except asyncio.TimeoutError:
                    elapsed += 2
                    if stop.is_set() and out_queue.empty():
                        break
        finally:
            stop.set()
            poller.cancel()
            relay.cancel()

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/result/{analysis_id}")
async def get_result(analysis_id: str):
    """Return complete analysis result JSON."""
    status = get_job_status(analysis_id)
    if not status:
        raise HTTPException(status_code=404, detail="Analysis not found")

    results = get_job_results(analysis_id)

    return {
        "analysis_id": analysis_id,
        "status": status.current_stage,
        "risk_score": status.risk_score,
        "risk_tier": status.risk_tier,
        "stages": status.stages,
        "results": {
            k: _serialize_result(v)
            for k, v in (results or {}).items()
            if k not in ("static", "dynamic")   # large objects — use dedicated endpoints below
        },
    }


@router.get("/result/{analysis_id}/static")
async def get_static_result(analysis_id: str):
    """
    Curated Stage 1 static triage result for the report UI: manifest,
    permissions, DEX/Dalvik findings, certificate, YARA matches, India
    patterns, IOCs, risk score with SHAP features.

    Deliberately NOT a raw dump of StaticTriageResult — dex.all_strings
    alone can hold 1-2 million raw opcode-disassembly strings per APK
    (~80MB+ serialized), which no UI needs; only the derived fields below
    (urls/ips/counts/flags) are ever rendered.
    """
    status = get_job_status(analysis_id)
    if not status:
        raise HTTPException(status_code=404, detail="Analysis not found")
    results = get_job_results(analysis_id) or {}
    static = results.get("static")
    if static is None:
        raise HTTPException(status_code=404, detail="Static result not available")

    m, d, n, c, y = static.manifest, static.dex, static.native, static.cert, static.yara

    return {
        "apk_sha256": static.apk_sha256,
        "elapsed_seconds": static.elapsed_seconds,
        "errors": static.errors,
        "manifest": None if not m else {
            "package_name": m.package_name,
            "version_name": m.version_name,
            "version_code": m.version_code,
            "min_sdk": m.min_sdk,
            "target_sdk": m.target_sdk,
            "permissions": m.permissions,
            "toxic_permissions": m.toxic_permissions,
            "activities": m.activities,
            "services": m.services,
            "receivers": m.receivers,
            "providers": m.providers,
            "exported_components": m.exported_components,
            "dangerous_components": m.dangerous_components,
            "uses_cleartext_traffic": m.uses_cleartext_traffic,
            "debuggable": m.debuggable,
            "allow_backup": m.allow_backup,
            "obfuscation_score": m.obfuscation_score,
            "obfuscation_signals": m.obfuscation_signals,
        },
        "dex": None if not d else {
            "url_count": len(d.urls),
            "urls": d.urls[:200],
            "ip_count": len(d.ips),
            "ips": d.ips[:200],
            "phone_numbers": d.phone_numbers[:50],
            "class_count": len(d.class_names),
            "method_count": len(d.method_names),
            "suspicious_apis": sorted(set(d.suspicious_apis)),
            "crypto_classes": d.crypto_classes,
            "network_classes": d.network_classes,
            "reflection_used": d.reflection_used,
            "dynamic_loading": d.dynamic_loading,
            "obfuscation_level": d.obfuscation_level,
            "obfuscation_evidence": d.obfuscation_evidence,
            "encoded_payloads": d.encoded_payloads[:20],
        },
        "native": None if not n else {
            "so_files_analyzed": n.so_files_analyzed,
            "suspicious_imports": n.suspicious_imports,
            "suspicious_strings": n.suspicious_strings[:50],
            "anti_debug_signals": n.anti_debug_signals,
            "frida_detection": n.frida_detection,
            "root_detection": n.root_detection,
            "emulator_detection": n.emulator_detection,
            "native_risk_score": n.native_risk_score,
        },
        "cert": None if not c else {
            "subject": c.subject,
            "issuer": c.issuer,
            "valid_from": c.valid_from,
            "valid_until": c.valid_until,
            "is_expired": c.is_expired,
            "is_debug_cert": c.is_debug_cert,
            "is_self_signed": c.is_self_signed,
            "serial_number": c.serial_number,
            "signing_cert_sha1": c.signing_cert_sha1,
            "signing_cert_sha256": c.signing_cert_sha256,
            "anomalies": c.anomalies,
            "anomaly_score": c.anomaly_score,
        },
        "yara": None if not y else {
            "matches": [
                {"rule_name": mt.rule_name, "rule_file": mt.rule_file, "category": mt.category,
                 "strings_matched": mt.strings_matched}
                for mt in y.matches
            ],
            "categories_hit": y.categories_hit,
            "yara_score": y.yara_score,
        },
        "india_matches": [
            {"pattern_id": p.pattern_id, "pattern_name": p.pattern_name,
             "category": p.category, "matched_strings": p.matched_strings, "severity": p.severity}
            for p in static.india_matches
        ],
        "iocs": [ioc.model_dump() for ioc in static.iocs],
        "risk_score": static.risk_score.model_dump() if static.risk_score else None,
        "permission_score": static.permission_score,
        "permission_reasons": static.permission_reasons,
        "config": None if not static.config else {
            "network_security_config_present": static.config.network_security_config_present,
            "cleartext_permitted_domains": static.config.cleartext_permitted_domains,
            "cleartext_permitted_globally": static.config.cleartext_permitted_globally,
            "trusts_user_added_cas": static.config.trusts_user_added_cas,
            "certificate_pinning_present": static.config.certificate_pinning_present,
            "backup_rules_present": static.config.backup_rules_present,
            "backup_excludes_sensitive_data": static.config.backup_excludes_sensitive_data,
            "anomalies": static.config.anomalies,
            "anomaly_score": static.config.anomaly_score,
        },
        "dependencies": None if not static.dependencies else {
            "ad_sdks_detected": static.dependencies.ad_sdks_detected,
            "analytics_sdks_detected": static.dependencies.analytics_sdks_detected,
            "anomalies": static.dependencies.anomalies,
            "anomaly_score": static.dependencies.anomaly_score,
        },
        "jadx": None if not static.jadx else {
            "available": static.jadx.available,
            "files_scanned": static.jadx.files_scanned,
            "hardcoded_ips": static.jadx.hardcoded_ips[:100],
            "hardcoded_urls": static.jadx.hardcoded_urls[:100],
            "suspicious_routes": static.jadx.suspicious_routes[:100],
            "secrets_found": static.jadx.secrets_found[:50],
            "errors": static.jadx.errors,
        },
        "ghidra": None if not static.ghidra else {
            "available": static.ghidra.available,
            "so_files_analyzed": static.ghidra.so_files_analyzed,
            "hardcoded_ips": static.ghidra.hardcoded_ips[:100],
            "hardcoded_urls": static.ghidra.hardcoded_urls[:100],
            "suspicious_routes": static.ghidra.suspicious_routes[:100],
            "secrets_found": static.ghidra.secrets_found[:50],
            "errors": static.ghidra.errors,
        },
        "mobsf": None if not static.mobsf else {
            "available": static.mobsf.available,
            "security_score": static.mobsf.security_score,
            "average_cvss": static.mobsf.average_cvss,
            "trackers_detected": static.mobsf.trackers_detected,
            "urls": static.mobsf.urls[:100],
            "emails": static.mobsf.emails,
            "firebase_urls": static.mobsf.firebase_urls,
            "code_analysis_findings": static.mobsf.code_analysis_findings,
            "errors": static.mobsf.errors,
        },
    }


@router.get("/result/{analysis_id}/dynamic")
async def get_dynamic_result(analysis_id: str):
    """
    Stage 2 dynamic analysis result: anti-evasion steps, MonkeyRunner
    stats, syscall profile, network/crypto artifacts, JA4 hashes, Frida
    hook artifacts. None if the APK never escalated past static triage.

    This dict is already the exact JSON-safe shape orchestrator.py builds
    (IOC/NetworkArtifact/CryptoArtifact already .model_dump()'d there) —
    no additional trimming needed, unlike the static result.
    """
    status = get_job_status(analysis_id)
    if not status:
        raise HTTPException(status_code=404, detail="Analysis not found")
    results = get_job_results(analysis_id) or {}
    dynamic = results.get("dynamic")
    if dynamic is None:
        raise HTTPException(status_code=404, detail="Dynamic analysis was not run for this APK")
    return {**dynamic, "iocs": [ioc.model_dump() for ioc in dynamic.get("iocs", [])]}


@router.get("/custody/{analysis_id}")
async def get_custody_chain(analysis_id: str):
    """Return the full custody chain manifest for this analysis."""
    chain_path = settings.ARTIFACT_DIR / analysis_id / "custody_chain.json"
    if not chain_path.exists():
        raise HTTPException(status_code=404, detail="Custody chain not found")
    return JSONResponse(content=json.loads(chain_path.read_text()))


@router.get("/custody/{analysis_id}/verify")
async def verify_custody_chain(analysis_id: str):
    """Verify chain integrity — recomputes all hashes."""
    chain_path = settings.ARTIFACT_DIR / analysis_id / "custody_chain.json"
    if not chain_path.exists():
        raise HTTPException(status_code=404, detail="Custody chain not found")

    from core.custody_chain import CustodyChain
    try:
        chain = CustodyChain.load(chain_path)
        return {"valid": True, "entry_count": chain.entry_count}
    except ValueError as e:
        return {"valid": False, "error": str(e)}


# ── Helpers ──────────────────────────────────────────────────────────────────

def _sse_event(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"


def _serialize_result(obj):
    """Best-effort serialization of arbitrary result objects."""
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, dict):
        return {k: _serialize_result(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_serialize_result(i) for i in obj]
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if hasattr(obj, "__dict__"):
        return {k: _serialize_result(v) for k, v in obj.__dict__.items()
                if not k.startswith("_")}
    return str(obj)
