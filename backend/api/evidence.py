"""
Garudatva v3 — Evidence API
POST /evidence/video        — BNSS 176(3) video upload
GET  /evidence/{id}/manifest — locker manifest
"""

from __future__ import annotations

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse

from utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter()


@router.post("/evidence/video")
async def ingest_video(
    case_id: str = Form(...),
    officer_badge: str = Form(...),
    gps_lat: float = Form(...),
    gps_lon: float = Form(...),
    witnesses: str = Form(""),   # comma-separated names
    file: UploadFile = File(...),
):
    """
    BNSS Section 176(3) seizure video ingestion.
    Mandatory for offences carrying 7+ year sentences.
    SHA256 computed immediately on receipt.
    Stored in encrypted local evidence locker.
    """
    try:
        from core.evidence.video_ingestor import ingest_seizure_video
        witness_list = [w.strip() for w in witnesses.split(",") if w.strip()]

        result = await ingest_seizure_video(
            case_id=case_id,
            officer_badge=officer_badge,
            gps_lat=gps_lat,
            gps_lon=gps_lon,
            witnesses=witness_list,
            file=file,
        )
        return JSONResponse(content=result)
    except Exception as e:
        logger.error(f"Video ingest failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/evidence/{case_id}/manifest")
async def get_manifest(case_id: str):
    """Return evidence locker manifest for this case."""
    try:
        from core.evidence.locker_manifest import get_case_manifest
        manifest = get_case_manifest(case_id)
        return JSONResponse(content=manifest)
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"Manifest not found: {e}")
