"""
Garudatva v3 — Reports API
GET /report/{id}/download  — stream signed PDF
GET /report/{id}/custody   — custody chain JSON
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, JSONResponse

from config import settings
from core.pipeline import get_job_results
from utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter()


@router.get("/report/{analysis_id}/download")
async def download_report(analysis_id: str):
    """Stream the signed forensic PDF."""
    results = get_job_results(analysis_id)
    if not results:
        raise HTTPException(status_code=404, detail="Analysis not found")

    pdf_path_str = results.get("pdf_path")
    if not pdf_path_str:
        raise HTTPException(status_code=404, detail="PDF not yet generated")

    pdf_path = Path(pdf_path_str)
    if not pdf_path.exists():
        raise HTTPException(status_code=404, detail="PDF file missing from disk")

    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=f"garudatva_report_{analysis_id[:8]}.pdf",
        headers={"Content-Disposition": f'attachment; filename="garudatva_report_{analysis_id[:8]}.pdf"'},
    )


@router.get("/report/{analysis_id}/custody")
async def get_custody_json(analysis_id: str):
    """Return full custody chain as JSON for court exhibit."""
    chain_path = settings.ARTIFACT_DIR / analysis_id / "custody_chain.json"
    if not chain_path.exists():
        raise HTTPException(status_code=404, detail="Custody chain not found")

    import json
    return JSONResponse(content=json.loads(chain_path.read_text()))


@router.get("/report/{analysis_id}/manifest")
async def get_evidence_manifest(analysis_id: str):
    """Return evidence locker manifest for this analysis."""
    results = get_job_results(analysis_id)
    if not results:
        raise HTTPException(status_code=404, detail="Analysis not found")

    manifest_path = settings.ARTIFACT_DIR / analysis_id / "evidence_manifest.json"
    if not manifest_path.exists():
        return JSONResponse(content={"items": [], "note": "No evidence items ingested"})

    import json
    return JSONResponse(content=json.loads(manifest_path.read_text()))
