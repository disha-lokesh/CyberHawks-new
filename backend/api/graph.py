"""
Garudatva v3 — Graph API
GET /graph/{id}              — IOC graph for job
GET /graph/syndicate/search  — cross-district query
GET /graph/syndicate/jarm/{hash} — JARM-based linkage
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse

from utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter()


@router.get("/graph/{analysis_id}")
async def get_ioc_graph(analysis_id: str):
    """Return node/edge graph for this analysis (for frontend force-directed vis)."""
    try:
        from core.graph.neo4j_client import get_client
        client = get_client()
        graph = client.get_analysis_graph(analysis_id)
        return JSONResponse(content=graph)
    except Exception as e:
        logger.warning(f"Graph query failed: {e}")
        raise HTTPException(status_code=503, detail=f"Graph unavailable: {e}")


@router.get("/graph/syndicate/search")
async def syndicate_search(
    district: str = Query(None),
    ip: str = Query(None),
    cert_sha1: str = Query(None),
    jarm_hash: str = Query(None),
):
    """Cross-district syndicate search across all ingested cases."""
    try:
        from core.graph.syndicate_linker import search_syndicates
        results = search_syndicates(
            district=district, ip=ip,
            cert_sha1=cert_sha1, jarm_hash=jarm_hash
        )
        return JSONResponse(content={"syndicates": results})
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Graph unavailable: {e}")


@router.get("/graph/syndicate/jarm/{jarm_hash}")
async def jarm_syndicate(jarm_hash: str):
    """Find all C2 infrastructure sharing this JARM fingerprint."""
    try:
        from core.graph.queries import find_jarm_group
        result = find_jarm_group(jarm_hash)
        return JSONResponse(content=result)
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Graph unavailable: {e}")
