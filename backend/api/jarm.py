"""
Garudatva v3 — JARM API (Workstation B endpoints)
POST /jarm/probe          — run JARM probes on C2 IPs
POST /jarm/qr/generate    — generate QR for air-gap transfer
POST /jarm/qr/import      — import QR results from Workstation B
GET  /jarm/sweep/{hash}   — trigger CSP cloud range sweep
"""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from config import settings
from utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter()


class ProbeRequest(BaseModel):
    ips: List[str]
    analysis_id: str


class QRImportRequest(BaseModel):
    qr_payload: str     # base64-encoded QR data scanned from Workstation A
    analysis_id: str


@router.post("/jarm/probe")
async def probe_jarm(req: ProbeRequest):
    """
    Run JARM active probing against a list of C2 IPs.
    Only available on Workstation B (internet-connected).
    """
    if settings.AIR_GAP_MODE:
        raise HTTPException(
            status_code=403,
            detail="JARM probing requires internet access. "
                   "Use QR bridge: POST /jarm/qr/generate on Workstation A, "
                   "then scan on Workstation B.",
        )
    try:
        from core.jarm.jarm_prober import probe_hosts
        results = await probe_hosts(req.ips)
        return {"analysis_id": req.analysis_id, "jarm_results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/jarm/qr/generate")
async def generate_qr(analysis_id: str):
    """
    Generate QR code encoding C2 IPs for air-gap transfer to Workstation B.
    Returns base64-encoded QR image PNG.
    """
    from core.pipeline import get_job_results
    from core.jarm.qr_bridge import generate_c2_qr

    results = get_job_results(analysis_id)
    if not results:
        raise HTTPException(status_code=404, detail="Analysis not found")

    # Collect C2 IPs from static + dynamic
    ips = []
    static = results.get("static")
    if static and hasattr(static, "iocs"):
        from models.ioc import IOCType
        ips = [ioc.value for ioc in static.iocs if ioc.ioc_type == IOCType.IP]

    qr_b64, payload_hash = generate_c2_qr(ips, analysis_id)
    return {
        "qr_image_b64": qr_b64,
        "payload_hash": payload_hash,
        "ip_count": len(ips),
        "instructions": (
            "Display this QR on Workstation A screen. "
            "Scan with Workstation B webcam to run JARM probing."
        ),
    }


@router.post("/jarm/qr/import")
async def import_jarm_results(req: QRImportRequest):
    """
    Import JARM results QR scanned from Workstation B.
    Validates SHA256 before accepting — tampered QR is rejected.
    """
    from core.jarm.qr_bridge import import_jarm_results
    from core.custody_chain import CustodyChain

    try:
        results = import_jarm_results(req.qr_payload)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"QR validation failed: {e}")

    # Log bridge event to custody chain
    chain_path = settings.ARTIFACT_DIR / req.analysis_id / "custody_chain.json"
    if chain_path.exists():
        try:
            chain = CustodyChain.load(chain_path)
            chain.log(
                stage="JARM_QR_IMPORT",
                action=f"JARM results imported via QR bridge: "
                       f"{len(results.get('jarm_results', []))} results",
                actor="system",
            )
            chain.save(chain_path)
        except Exception as e:
            logger.warning(f"Could not update custody chain: {e}")

    return {"analysis_id": req.analysis_id, "jarm_results": results}


@router.get("/jarm/sweep/{jarm_hash}")
async def csp_sweep(jarm_hash: str):
    """
    Trigger cloud provider IP range sweep for matching JARM fingerprint.
    Runs on Workstation B only.
    """
    if settings.AIR_GAP_MODE:
        raise HTTPException(
            status_code=403,
            detail="CSP sweep requires internet access (Workstation B only).",
        )
    try:
        from core.jarm.csp_sweeper import sweep_cloud_ranges
        matching_ips = await sweep_cloud_ranges(jarm_hash)
        return {"jarm_hash": jarm_hash, "matching_ips": matching_ips, "count": len(matching_ips)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
