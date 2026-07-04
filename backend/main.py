"""
Garudatva v3 — APK Threat Analysis Platform with C2 Detection
CIDECODE 2026 — PES University
"""

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config import settings
from api.analysis import router as analysis_router
from api.reports import router as reports_router
from api.graph import router as graph_router
from api.jarm import router as jarm_router
from api.evidence import router as evidence_router
from utils.logger import get_logger

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    logger.info("Garudatva v3 starting up...")
    logger.info(f"Environment: {settings.ENV}")
    logger.info(f"Air-gap mode: {settings.AIR_GAP_MODE}")

    # Verify critical directories exist
    for d in [
        settings.UPLOAD_DIR,
        settings.EVIDENCE_DIR,
        settings.REPORT_DIR,
        settings.ARTIFACT_DIR,
    ]:
        d.mkdir(parents=True, exist_ok=True)
        logger.info(f"Directory ready: {d}")

    yield

    logger.info("Garudatva v3 shutting down...")


app = FastAPI(
    title="Garudatva v3",
    description="APK Threat Analysis Platform with C2 Detection — CIDECODE 2026",
    version="3.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount routers
app.include_router(analysis_router, prefix="/api/v1", tags=["Analysis"])
app.include_router(reports_router, prefix="/api/v1", tags=["Reports"])
app.include_router(graph_router, prefix="/api/v1", tags=["Graph"])
app.include_router(jarm_router, prefix="/api/v1", tags=["JARM"])
app.include_router(evidence_router, prefix="/api/v1", tags=["Evidence"])


@app.get("/health", tags=["System"])
async def health_check():
    return {
        "status": "operational",
        "version": "3.0.0",
        "platform": "Garudatva",
        "air_gap": settings.AIR_GAP_MODE,
    }


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "error": str(exc)},
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.ENV == "development",
        log_level="info",
    )
