"""
Garudatva v3 — MobSF Automated Scanner Integration
Delegates a static scan to a locally-run Mobile Security Framework
instance (github.com/MobSF/Mobile-Security-Framework-MobSF) via its
REST API, then curates the (large, version-varying) JSON report down
to the fields this project's report/UI actually render.

Requires a running MobSF server (MOBSF_URL) reachable from this host —
typically `docker run -p 8000:8000 opensecurity/mobsf` on the same
air-gapped workstation, so this does not violate AIR_GAP_MODE (no
traffic leaves the workstation). Degrades gracefully (empty result,
logged warning) if MOBSF_URL/MOBSF_API_KEY are unset or the server is
unreachable — matching every other optional-external-tool integration
in this codebase (jadx, apktool, Ollama).

MobSF's own risk/CVSS scoring is NOT folded into this project's numeric
RiskScore: its scan surface overlaps heavily with the manifest/cert/DEX
analyzers already implemented here, and its exact JSON schema varies
across MobSF releases in ways that can't be fully verified without a
live instance in every deployment environment. Findings are surfaced
as supplementary evidence in the report instead of silently moving the
risk total.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

from config import settings
from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class MobSFResult:
    available: bool = False
    file_hash: str = ""
    security_score: Optional[float] = None
    average_cvss: Optional[float] = None
    trackers_detected: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    firebase_urls: List[str] = field(default_factory=list)
    code_analysis_findings: List[Dict[str, str]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


async def run_mobsf_scan(apk_path: Path) -> MobSFResult:
    """Upload + scan the APK against a local MobSF instance, if configured."""
    result = MobSFResult()

    if not settings.MOBSF_URL or not settings.MOBSF_API_KEY:
        result.errors.append(
            "MobSF not configured (MOBSF_URL/MOBSF_API_KEY unset) — skipping automated scan"
        )
        logger.info("MobSF integration skipped — not configured")
        return result

    headers = {"Authorization": settings.MOBSF_API_KEY}

    try:
        async with httpx.AsyncClient(
            base_url=settings.MOBSF_URL, timeout=settings.MOBSF_TIMEOUT
        ) as client:
            with open(apk_path, "rb") as f:
                upload_resp = await client.post(
                    "/api/v1/upload",
                    headers=headers,
                    files={"file": (apk_path.name, f, "application/vnd.android.package-archive")},
                )
            upload_resp.raise_for_status()
            upload_json = upload_resp.json()
            file_hash = upload_json.get("hash", "")
            if not file_hash:
                result.errors.append(f"MobSF upload returned no file hash: {upload_json}")
                return result
            result.file_hash = file_hash

            scan_resp = await client.post(
                "/api/v1/scan", headers=headers, data={"hash": file_hash}
            )
            scan_resp.raise_for_status()
            scan_json = scan_resp.json()
    except httpx.ConnectError as e:
        result.errors.append(f"MobSF unreachable at {settings.MOBSF_URL}: {e}")
        logger.warning(f"MobSF unreachable: {e}")
        return result
    except httpx.HTTPStatusError as e:
        result.errors.append(f"MobSF API error: {e}")
        logger.warning(f"MobSF API error: {e}")
        return result
    except Exception as e:
        result.errors.append(f"MobSF scan failed: {e}")
        logger.error(f"MobSF scan crashed: {e}", exc_info=True)
        return result

    result.available = True
    _parse_mobsf_report(scan_json, result)
    logger.info(
        f"MobSF scan complete: security_score={result.security_score} "
        f"trackers={len(result.trackers_detected)} findings={len(result.code_analysis_findings)}"
    )
    return result


def _parse_mobsf_report(report: Dict[str, Any], result: MobSFResult) -> None:
    """
    Defensively pull curated fields out of MobSF's JSON scan report.
    MobSF's schema has changed across major versions — every lookup is
    a best-effort .get() so an unexpected shape degrades to an empty
    field rather than crashing this stage.
    """
    try:
        result.security_score = report.get("security_score")
        result.average_cvss = report.get("average_cvss")

        trackers = report.get("trackers", {})
        if isinstance(trackers, dict):
            result.trackers_detected = [
                t.get("name", "") for t in trackers.get("trackers", []) if isinstance(t, dict)
            ][:50]

        result.urls = [
            u.get("url", u) if isinstance(u, dict) else u
            for u in report.get("urls", [])
        ][:100]
        result.emails = list(report.get("emails", []))[:50]
        result.firebase_urls = list(report.get("firebase_urls", []))[:20]

        code_analysis = report.get("code_analysis", {})
        findings = code_analysis.get("findings", {}) if isinstance(code_analysis, dict) else {}
        for rule_id, finding in list(findings.items())[:50]:
            if not isinstance(finding, dict):
                continue
            result.code_analysis_findings.append({
                "rule": rule_id,
                "severity": finding.get("metadata", {}).get("severity", "unknown"),
                "description": finding.get("metadata", {}).get("description", "")[:200],
            })
    except Exception as e:
        result.errors.append(f"MobSF report parse: {e}")
        logger.warning(f"MobSF report parse failed: {e}")
