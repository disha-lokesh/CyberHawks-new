"""
Garudatva v3 — Pipeline Orchestrator
Sequential pipeline: Static → Dynamic → Cloud C2 → Graph → LLM → PDF
Manages state, custody chain, and RAM through all stages.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from config import settings
from core.custody_chain import CustodyChain
from core.static.triage import run_static_triage, StaticTriageResult
from models.analysis import (
    AnalysisRequest, AnalysisStatus, CaseMetadata,
    PipelineStage, RiskTier, StageResult,
)
from models.risk_score import RiskScore
from utils.hasher import sha256_file
from utils.logger import get_logger
from utils.ram_monitor import log_ram_snapshot, assert_ram_available

logger = get_logger(__name__)

# In-memory job store (replace with Redis in production)
_jobs: Dict[str, AnalysisStatus] = {}
_results: Dict[str, Any] = {}

# The AVD (Stage 2, ~4GB) and Ollama (Stage 5, ~5GB) must never be resident
# at the same time on a 16GB target — this holds across concurrent *jobs*,
# not just within one job's sequential await chain. Acquired with
# try/finally semantics (async with) so a crash/timeout in either stage
# still releases it for the next job.
_avd_ollama_lock = asyncio.Lock()


class PipelineOrchestrator:
    """
    Runs the full Garudatva analysis pipeline for one APK.
    One instance per analysis job.
    """

    def __init__(
        self,
        analysis_id: str,
        request: AnalysisRequest,
        case: CaseMetadata,
        apk_path: Path,
    ):
        self.analysis_id = analysis_id
        self.request = request
        self.case = case
        self.apk_path = apk_path
        self.work_dir = settings.ARTIFACT_DIR / analysis_id
        self.work_dir.mkdir(parents=True, exist_ok=True)

        self.custody = CustodyChain(
            analysis_id=analysis_id,
            case_id=case.case_id,
            apk_sha256=request.apk_sha256,
        )

        self.status = AnalysisStatus(
            analysis_id=analysis_id,
            case_id=case.case_id,
            current_stage=PipelineStage.QUEUED,
        )
        _jobs[analysis_id] = self.status

        # Accumulated results from each stage
        self._static_result: Optional[StaticTriageResult] = None
        self._dynamic_result = None
        self._cloud_result = None
        self._graph_result = None
        self._llm_result = None
        self._pdf_path: Optional[Path] = None

    # ── Public entry point ───────────────────────────────────────────────

    async def run(self) -> None:
        """Execute full pipeline. Updates self.status throughout."""
        from core.event_bus import open_stream, close_stream
        open_stream(self.analysis_id)

        self.custody.log(
            stage="PIPELINE_START",
            action=f"Analysis started for {self.apk_path.name}",
            actor=self.case.reporting_officer.badge_id,
            artifact_sha256=self.request.apk_sha256,
        )

        try:
            await self._stage_static_triage()

            tier = self.status.risk_score
            if tier is not None and tier >= settings.RISK_HIGH_RISK_MIN and self.request.run_dynamic:
                await self._stage_dynamic_analysis()
                await self._stage_cloud_c2()

            await self._stage_neo4j_graph()
            await self._stage_llm_narrative()
            await self._stage_pdf_generation()

            self.status.current_stage = PipelineStage.COMPLETE
            self.custody.log(
                stage="PIPELINE_COMPLETE",
                action="Full analysis pipeline completed successfully",
                actor="system",
            )

        except Exception as e:
            logger.error(f"Pipeline failed at {self.status.current_stage}: {e}", exc_info=True)
            self.status.current_stage = PipelineStage.FAILED
            self.status.error = str(e)
            self.custody.log(
                stage="PIPELINE_FAILED",
                action=f"Pipeline error: {str(e)[:200]}",
                actor="system",
            )
        finally:
            # Always save custody chain
            chain_path = self.work_dir / "custody_chain.json"
            self.custody.save(chain_path)
            _results[self.analysis_id] = {
                "static": self._static_result,
                "dynamic": self._dynamic_result,
                "cloud": self._cloud_result,
                "graph": self._graph_result,
                "llm": self._llm_result,
                "pdf_path": str(self._pdf_path) if self._pdf_path else None,
                "custody_chain_path": str(chain_path),
            }
            # Give the SSE handler a moment to drain any last events, then
            # release the queue — the stage-status stream still reports
            # COMPLETE/FAILED independently via get_job_status().
            await asyncio.sleep(2)
            close_stream(self.analysis_id)

    # ── Stage methods ────────────────────────────────────────────────────

    async def _stage_static_triage(self) -> None:
        self._set_stage(PipelineStage.STATIC_TRIAGE)
        self.custody.log(
            stage="STATIC_TRIAGE", action="Static analysis started", actor="system"
        )

        result = await run_static_triage(self.apk_path, self.work_dir / "static")
        self._static_result = result

        self.status.risk_score = result.risk_score.total if result.risk_score else 0.0
        self.status.risk_tier = result.risk_score.tier if result.risk_score else RiskTier.BENIGN

        self.custody.log(
            stage="STATIC_TRIAGE",
            action=f"Static analysis complete: risk={self.status.risk_score:.1f} "
                   f"tier={self.status.risk_tier}",
            actor="system",
            artifact_sha256=result.apk_sha256,
        )
        self._complete_stage(
            PipelineStage.STATIC_TRIAGE,
            artifacts={
                "risk_score": self.status.risk_score,
                "risk_tier": self.status.risk_tier,
                "yara_categories": result.yara.categories_hit if result.yara else [],
                "india_match_count": len(result.india_matches),
                "ioc_count": len(result.iocs),
                "ml_probability": result.risk_score.ml_probability if result.risk_score else 0.0,
            },
        )

    async def _stage_dynamic_analysis(self) -> None:
        self._set_stage(PipelineStage.DYNAMIC_ANALYSIS)
        self.custody.log(
            stage="DYNAMIC_ANALYSIS", action="Dynamic sandbox started", actor="system"
        )
        try:
            from core.dynamic.orchestrator import run_dynamic_analysis

            package_name = (
                self._static_result.manifest.package_name
                if self._static_result and self._static_result.manifest
                else None
            )
            if not package_name:
                raise RuntimeError("No package_name from static triage — cannot launch APK in AVD")

            async with _avd_ollama_lock:
                assert_ram_available(required_mb=4096)
                result = await run_dynamic_analysis(
                    apk_path=self.apk_path,
                    work_dir=self.work_dir / "dynamic",
                    case_id=self.case.case_id,
                    analysis_id=self.analysis_id,
                    package_name=package_name,
                    risk_tier=(
                        self.status.risk_tier.value if self.status.risk_tier else "HIGH_RISK"
                    ),
                    custody=self.custody,
                )
            self._dynamic_result = result
            self.custody.log(
                stage="DYNAMIC_ANALYSIS",
                action=f"Dynamic analysis complete: "
                       f"{len(result.get('network_artifacts', []))} network artifacts",
                actor="system",
            )
            self._complete_stage(
                PipelineStage.DYNAMIC_ANALYSIS,
                artifacts={"dynamic_summary": {
                    "c2_urls": len(result.get("c2_urls", [])),
                    "crypto_artifacts": len(result.get("crypto_artifacts", [])),
                    "ja4_hashes": len(result.get("ja4_hashes", [])),
                }},
            )
        except Exception as e:
            logger.error(f"Dynamic analysis failed: {e}")
            self._fail_stage(PipelineStage.DYNAMIC_ANALYSIS, str(e))

    async def _stage_cloud_c2(self) -> None:
        self._set_stage(PipelineStage.CLOUD_C2_DETECTION)
        try:
            from core.dynamic.network_capture import classify_cloud_c2
            iocs = self._static_result.iocs if self._static_result else []
            if self._dynamic_result:
                iocs += self._dynamic_result.get("iocs", [])
            result = await classify_cloud_c2(iocs)
            self._cloud_result = result
            self._complete_stage(
                PipelineStage.CLOUD_C2_DETECTION,
                artifacts={"cloud_c2_count": len(result.get("cloud_hits", []))},
            )
        except Exception as e:
            self._fail_stage(PipelineStage.CLOUD_C2_DETECTION, str(e))

    async def _stage_neo4j_graph(self) -> None:
        self._set_stage(PipelineStage.NEO4J_GRAPH)
        try:
            from core.graph.ioc_ingester import ingest_iocs
            from core.graph.syndicate_linker import find_syndicates
            all_iocs = self._static_result.iocs if self._static_result else []
            ingest_iocs(self.analysis_id, self.case.case_id, all_iocs)
            syndicates = find_syndicates(self.analysis_id)
            self._graph_result = {"syndicates": syndicates}
            self._complete_stage(
                PipelineStage.NEO4J_GRAPH,
                artifacts={"syndicate_count": len(syndicates)},
            )
        except Exception as e:
            logger.warning(f"Neo4j graph stage failed (non-fatal): {e}")
            self._fail_stage(PipelineStage.NEO4J_GRAPH, str(e))

    async def _stage_llm_narrative(self) -> None:
        self._set_stage(PipelineStage.LLM_NARRATIVE)
        try:
            from core.ai.ollama_client import generate_narrative
            async with _avd_ollama_lock:
                narrative = await generate_narrative(
                    static=self._static_result,
                    dynamic=self._dynamic_result,
                    cloud=self._cloud_result,
                    graph=self._graph_result,
                    case=self.case,
                )
            self._llm_result = narrative
            self._complete_stage(
                PipelineStage.LLM_NARRATIVE,
                artifacts={"narrative_word_count": len(narrative.get("text", "").split())},
            )
        except Exception as e:
            logger.warning(f"LLM narrative failed (non-fatal): {e}")
            self._fail_stage(PipelineStage.LLM_NARRATIVE, str(e))

    async def _stage_pdf_generation(self) -> None:
        self._set_stage(PipelineStage.PDF_GENERATION)
        try:
            from core.report.pdf_builder import build_pdf, validate_output_pdf
            from core.report.signer import dual_sign_report

            pdf_path = await build_pdf(
                analysis_id=self.analysis_id,
                case=self.case,
                static=self._static_result,
                dynamic=self._dynamic_result,
                cloud=self._cloud_result,
                graph=self._graph_result,
                llm=self._llm_result,
                custody=self.custody,
                output_dir=settings.REPORT_DIR,
            )

            # IT Act Sec 79A dual-officer signature — Reporting then Reviewing
            # officer. Each pyHanko signature is an incremental PDF update, so
            # re-validate after signing: a non-incremental rewrite of the
            # second signature would silently invalidate the first.
            pdf_path = await dual_sign_report(
                pdf_path=pdf_path,
                reporting_officer_badge=self.case.reporting_officer.badge_id,
                reviewing_officer_badge=self.case.reviewing_officer.badge_id,
                custody=self.custody,
            )
            validate_output_pdf(pdf_path)

            self._pdf_path = pdf_path
            pdf_hash = sha256_file(pdf_path)
            self.custody.log(
                stage="PDF_GENERATED",
                action=f"PDF report generated: {pdf_path.name}",
                actor="system",
                artifact_sha256=pdf_hash,
            )
            self._complete_stage(
                PipelineStage.PDF_GENERATION,
                artifacts={"pdf_path": str(pdf_path), "pdf_sha256": pdf_hash},
            )
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            self._fail_stage(PipelineStage.PDF_GENERATION, str(e))

    # ── Helpers ──────────────────────────────────────────────────────────

    def _set_stage(self, stage: PipelineStage) -> None:
        from datetime import datetime, timezone
        self.status.current_stage = stage
        self.status.stages[stage.value] = StageResult(
            stage=stage,
            started_at=datetime.now(timezone.utc),
            status="running",
        )
        log_ram_snapshot(stage.value)

    def _complete_stage(self, stage: PipelineStage, artifacts: dict = None) -> None:
        from datetime import datetime, timezone
        sr = self.status.stages.get(stage.value)
        if sr:
            sr.completed_at = datetime.now(timezone.utc)
            if sr.started_at:
                sr.duration_seconds = (sr.completed_at - sr.started_at).total_seconds()
            sr.status = "done"
            sr.artifacts = artifacts or {}

    def _fail_stage(self, stage: PipelineStage, error: str) -> None:
        from datetime import datetime, timezone
        sr = self.status.stages.get(stage.value)
        if sr:
            sr.status = "failed"
            sr.error = error
            sr.completed_at = datetime.now(timezone.utc)


# ── Job registry helpers ─────────────────────────────────────────────────────

def get_job_status(analysis_id: str) -> Optional[AnalysisStatus]:
    return _jobs.get(analysis_id)


def get_job_results(analysis_id: str) -> Optional[Dict]:
    return _results.get(analysis_id)


async def start_analysis(
    request: AnalysisRequest,
    case: CaseMetadata,
    apk_path: Path,
    analysis_id: Optional[str] = None,
) -> str:
    """
    Create job, start pipeline in background, return analysis_id.

    Accepts an optional caller-supplied analysis_id so the ID the client
    receives from POST /analyze (used for the upload directory) is the
    exact same ID the job is tracked under in _jobs/_results and the SSE
    event bus — previously this always minted its own ID here, silently
    discarded by the caller, so GET /status/{id} and /result/{id} could
    never find the job the client was told to poll.
    """
    analysis_id = analysis_id or str(uuid.uuid4())
    orchestrator = PipelineOrchestrator(analysis_id, request, case, apk_path)
    asyncio.create_task(orchestrator.run())
    logger.info(f"Pipeline started: analysis_id={analysis_id}")
    return analysis_id
