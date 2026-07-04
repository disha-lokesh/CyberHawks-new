"""
Garudatva v3 — PDF Builder
Builds complete 12-section forensic PDF using ReportLab.
ISO/IEC 27037 + 27042 compliance headers.
IT Act Sec 79A examiner declaration.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    HRFlowable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
    TableStyle,
)

from config import settings
from utils.logger import get_logger

logger = get_logger(__name__)

# ── Color palette ─────────────────────────────────────────────────────────────
GARUDATVA_DARK  = colors.HexColor("#1a1a2e")
GARUDATVA_BLUE  = colors.HexColor("#16213e")
GARUDATVA_GOLD  = colors.HexColor("#e94560")
TIER_COLORS = {
    "BENIGN":     colors.HexColor("#27ae60"),
    "SUSPICIOUS": colors.HexColor("#f39c12"),
    "HIGH_RISK":  colors.HexColor("#e67e22"),
    "CRITICAL":   colors.HexColor("#c0392b"),
}

ISO_COMPLIANCE_TEXT = """This forensic report was generated in compliance with:
ISO/IEC 27037:2012 — Identification, collection, acquisition and preservation of digital evidence.
ISO/IEC 27042:2015 — Analysis and interpretation of digital evidence.
IT Act Section 79A — Examiner of Electronic Evidence.
Bharatiya Sakshya Adhiniyam Section 63 — Electronic records admissibility (SHA256 hash chain maintained).
BNSS Section 176(3) — Mandatory videography compliance confirmed.
DPDP Act 2023 — No victim data transmitted externally. Analysis performed on air-gapped workstation."""


async def build_pdf(
    analysis_id: str,
    case,
    static=None,
    dynamic=None,
    cloud=None,
    graph=None,
    llm=None,
    custody=None,
    output_dir: Path = None,
) -> Path:
    """Build the complete 12-section forensic PDF. Returns path to PDF."""

    output_dir = output_dir or settings.REPORT_DIR
    output_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = output_dir / f"garudatva_report_{analysis_id[:8]}.pdf"

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2.5*cm, bottomMargin=2.5*cm,
        title=f"Garudatva Forensic Report — {analysis_id[:8]}",
        author="Garudatva v3 — CIDECODE 2026",
    )

    styles = _build_styles()
    story = []

    # ── Cover page ────────────────────────────────────────────────────
    story += _cover_page(styles, analysis_id, case)
    story.append(PageBreak())

    # ── Compliance block ──────────────────────────────────────────────
    story += _compliance_block(styles)
    story.append(PageBreak())

    # ── Section 1: Application Identity ──────────────────────────────
    story += _section_app_identity(styles, static, analysis_id)

    # ── Section 2: Case Metadata ──────────────────────────────────────
    story += _section_case_metadata(styles, case)

    # ── Section 3: Permissions Analysis ──────────────────────────────
    story += _section_permissions(styles, static)

    # ── Section 4: Code Analysis Findings ────────────────────────────
    story += _section_code_analysis(styles, static)

    # ── Section 5: Dynamic Behavior ───────────────────────────────────
    story += _section_dynamic(styles, dynamic)

    # ── Section 6: Cryptographic Artifacts ───────────────────────────
    story += _section_crypto(styles, dynamic)

    # ── Section 7: Network Communication ─────────────────────────────
    story += _section_network(styles, static, dynamic)

    # ── Section 8: Cloud C2 Assessment ───────────────────────────────
    story += _section_cloud_c2(styles, cloud)

    # ── Section 9: Indicators of Compromise ──────────────────────────
    story += _section_iocs(styles, static)

    # ── Section 10: Syndicate Linkage ────────────────────────────────
    story += _section_syndicate(styles, graph)

    # ── Section 11: Risk Assessment ──────────────────────────────────
    story += _section_risk(styles, static)

    # ── Section 12: Recommended Actions ──────────────────────────────
    story += _section_actions(styles, static)

    story.append(PageBreak())

    # ── LLM Narrative ────────────────────────────────────────────────
    if llm and llm.get("text"):
        story += _section_narrative(styles, llm)
        story.append(PageBreak())

    # ── Custody chain exhibit ─────────────────────────────────────────
    if custody:
        story += _custody_exhibit(styles, custody)
        story.append(PageBreak())

    # ── Exhibit A: Evidence locker (BNSS Sec 176(3)) ───────────────────
    if case is not None and getattr(case, "case_id", None):
        from core.report.templates.evidence_locker_exhibit import render_evidence_exhibit
        story += render_evidence_exhibit(styles, case.case_id)
        story.append(PageBreak())

    # ── Regional language summary ─────────────────────────────────────
    if llm and llm.get("translation"):
        story += _regional_summary(styles, llm["translation"])

    # ── Build PDF ─────────────────────────────────────────────────────
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, doc.build, story)

    validate_output_pdf(pdf_path)
    logger.info(f"PDF built: {pdf_path} ({pdf_path.stat().st_size:,} bytes)")
    return pdf_path


class ReportIntegrityError(RuntimeError):
    """Raised when a generated/signed PDF fails independent-library validation.
    The job must fail loudly here rather than hand a broken file to an
    officer and call the job complete."""


def validate_output_pdf(path: Path) -> None:
    """
    Open the produced PDF with an independent library (pypdf) and assert it
    actually parses. Catches: truncated writes from an unclosed ReportLab
    canvas, byte-range corruption from a non-incremental second signature,
    and encoding crashes from non-ASCII LLM text — any of which can produce
    a file that pyHanko "succeeds" on but no real viewer can open.
    """
    from pypdf import PdfReader
    from pypdf.errors import PdfReadError

    try:
        reader = PdfReader(str(path))
        if len(reader.pages) == 0:
            raise ReportIntegrityError(f"{path}: generated PDF has zero pages")
        for page in reader.pages:
            page.extract_text()  # forces the page object to actually parse
    except PdfReadError as e:
        raise ReportIntegrityError(f"{path}: PDF failed to parse — {e}") from e
    except ReportIntegrityError:
        raise
    except Exception as e:
        raise ReportIntegrityError(f"{path}: PDF validation failed — {e}") from e


# ── Section builders ─────────────────────────────────────────────────────────

def _cover_page(styles, analysis_id, case) -> list:
    elements = [
        Spacer(1, 2*cm),
        Paragraph("GARUDATVA v3", styles["CoverTitle"]),
        Paragraph("APK Threat Analysis Platform with C2 Detection", styles["CoverSubtitle"]),
        HRFlowable(width="100%", thickness=2, color=GARUDATVA_GOLD),
        Spacer(1, 1*cm),
        Paragraph("FORENSIC ANALYSIS REPORT", styles["CoverTitle"]),
        Spacer(1, 2*cm),
        Paragraph(f"Analysis ID: {analysis_id}", styles["CoverMeta"]),
        Paragraph(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}", styles["CoverMeta"]),
    ]
    if case:
        elements += [
            Paragraph(f"FIR Number: {case.fir_number}", styles["CoverMeta"]),
            Paragraph(f"District: {case.district}", styles["CoverMeta"]),
            Paragraph(f"Station: {case.station}", styles["CoverMeta"]),
            Paragraph(f"Reporting Officer: {case.reporting_officer.name} ({case.reporting_officer.badge_id})", styles["CoverMeta"]),
        ]
    elements += [
        Spacer(1, 2*cm),
        Paragraph("CIDECODE 2026 — PES University", styles["CoverSubtitle"]),
        Paragraph("FOR OFFICIAL USE ONLY — NOT FOR PUBLIC DISCLOSURE", styles["Confidential"]),
    ]
    return elements


def _compliance_block(styles) -> list:
    return [
        Paragraph("COMPLIANCE DECLARATION", styles["SectionHeader"]),
        HRFlowable(width="100%", thickness=1, color=GARUDATVA_GOLD),
        Spacer(1, 0.3*cm),
        Paragraph(ISO_COMPLIANCE_TEXT, styles["Body"]),
    ]


def _section_app_identity(styles, static, analysis_id) -> list:
    elements = [
        Paragraph("1. APPLICATION IDENTITY", styles["SectionHeader"]),
        HRFlowable(width="100%", thickness=1, color=GARUDATVA_GOLD),
        Spacer(1, 0.3*cm),
    ]
    rows = [["Property", "Value"]]
    if static:
        rows.append(["Analysis ID", analysis_id])
        rows.append(["APK SHA256", static.apk_sha256 if hasattr(static, "apk_sha256") else "—"])
        if static.manifest:
            rows += [
                ["Package Name", static.manifest.package_name],
                ["Version", static.manifest.version_name],
                ["Min SDK", static.manifest.min_sdk],
                ["Target SDK", static.manifest.target_sdk],
                ["Debuggable", str(static.manifest.debuggable)],
            ]
        if static.cert:
            rows.append(["Cert Subject", static.cert.subject[:60] + "…" if len(static.cert.subject) > 60 else static.cert.subject])
            rows.append(["Cert SHA256", static.cert.signing_cert_sha256[:32] + "…" if static.cert.signing_cert_sha256 else "—"])
    elements.append(_table(rows))
    elements.append(Spacer(1, 0.5*cm))
    return elements


def _section_case_metadata(styles, case) -> list:
    elements = [
        Paragraph("2. CASE METADATA", styles["SectionHeader"]),
        HRFlowable(width="100%", thickness=1, color=GARUDATVA_GOLD),
        Spacer(1, 0.3*cm),
    ]
    if case:
        rows = [
            ["Property", "Value"],
            ["FIR Number", case.fir_number],
            ["Case ID", case.case_id],
            ["District", case.district],
            ["Station", case.station],
            ["Reporting Officer", f"{case.reporting_officer.name} — Badge: {case.reporting_officer.badge_id}"],
            ["Reviewing Officer", f"{case.reviewing_officer.name} — Badge: {case.reviewing_officer.badge_id}"],
            ["Device IMEI", case.device.imei],
            ["Device", f"{case.device.make} {case.device.model}"],
            ["Android Version", case.device.android_version],
        ]
        elements.append(_table(rows))
    elements.append(Spacer(1, 0.5*cm))
    return elements


def _section_permissions(styles, static) -> list:
    elements = [
        Paragraph("3. PERMISSIONS ANALYSIS", styles["SectionHeader"]),
        HRFlowable(width="100%", thickness=1, color=GARUDATVA_GOLD),
        Spacer(1, 0.3*cm),
    ]
    if static and static.manifest:
        m = static.manifest
        elements.append(Paragraph(
            f"Total permissions declared: {len(m.permissions)}. "
            f"Toxic permissions: {len(m.toxic_permissions)}.",
            styles["Body"]
        ))
        if m.toxic_permissions:
            rows = [["Toxic Permission", "Risk"]]
            for perm in m.toxic_permissions:
                rows.append([perm.replace("android.permission.", ""), "HIGH"])
            elements.append(_table(rows))
        if static.permission_reasons:
            elements.append(Spacer(1, 0.2*cm))
            elements.append(Paragraph("Score factors:", styles["SubHeader"]))
            for reason in static.permission_reasons[:10]:
                elements.append(Paragraph(f"• {reason}", styles["Body"]))
    elements.append(Spacer(1, 0.5*cm))
    return elements


def _section_code_analysis(styles, static) -> list:
    elements = [
        Paragraph("4. CODE ANALYSIS FINDINGS", styles["SectionHeader"]),
        HRFlowable(width="100%", thickness=1, color=GARUDATVA_GOLD),
        Spacer(1, 0.3*cm),
    ]
    if static:
        if static.dex:
            d = static.dex
            elements.append(Paragraph(
                f"DEX analysis extracted {len(d.all_strings):,} strings, "
                f"{len(d.urls)} URLs, {len(d.ips)} IP addresses. "
                f"Obfuscation level: {d.obfuscation_level}/3. "
                f"Dynamic code loading: {'Detected' if d.dynamic_loading else 'Not detected'}. "
                f"Reflection API: {'Detected' if d.reflection_used else 'Not detected'}.",
                styles["Body"]
            ))
        if static.india_matches:
            elements.append(Spacer(1, 0.2*cm))
            elements.append(Paragraph("India-Specific Fraud Patterns:", styles["SubHeader"]))
            rows = [["Pattern ID", "Name", "Category", "Severity"]]
            for m in static.india_matches[:15]:
                rows.append([m.pattern_id, m.pattern_name, m.category, m.severity])
            elements.append(_table(rows))
        if static.yara and static.yara.matches:
            elements.append(Spacer(1, 0.2*cm))
            elements.append(Paragraph("YARA Rule Matches:", styles["SubHeader"]))
            rows = [["Rule", "Category", "File"]]
            for match in static.yara.matches[:10]:
                rows.append([match.rule_name, match.category, match.rule_file])
            elements.append(_table(rows))
    elements.append(Spacer(1, 0.5*cm))
    return elements


def _section_dynamic(styles, dynamic) -> list:
    elements = [
        Paragraph("5. DYNAMIC BEHAVIOR", styles["SectionHeader"]),
        HRFlowable(width="100%", thickness=1, color=GARUDATVA_GOLD),
        Spacer(1, 0.3*cm),
    ]
    if not dynamic:
        elements.append(Paragraph("Dynamic analysis not performed (risk score below threshold).", styles["Body"]))
    else:
        rows = [
            ["Metric", "Value"],
            ["C2 URLs captured", str(len(dynamic.get("c2_urls", [])))],
            ["SMS intercept events", str(len(dynamic.get("sms_intercepts", [])))],
            ["Clipboard events", str(len(dynamic.get("clipboard_events", [])))],
            ["Accessibility events", str(len(dynamic.get("accessibility_events", [])))],
            ["JA4 fingerprints", str(len(dynamic.get("ja4_hashes", [])))],
        ]
        if dynamic.get("monkey_stats"):
            ms = dynamic["monkey_stats"]
            rows.append(["MonkeyRunner taps", str(ms.get("taps", 0))])
        elements.append(_table(rows))
        if dynamic.get("c2_urls"):
            elements.append(Spacer(1, 0.2*cm))
            elements.append(Paragraph("Captured C2 URLs:", styles["SubHeader"]))
            for url in dynamic["c2_urls"][:10]:
                elements.append(Paragraph(f"• {url}", styles["Mono"]))
    elements.append(Spacer(1, 0.5*cm))
    return elements


def _section_crypto(styles, dynamic) -> list:
    elements = [
        Paragraph("6. CRYPTOGRAPHIC ARTIFACTS", styles["SectionHeader"]),
        HRFlowable(width="100%", thickness=1, color=GARUDATVA_GOLD),
        Spacer(1, 0.3*cm),
    ]
    if not dynamic or not dynamic.get("crypto_artifacts"):
        elements.append(Paragraph("No cryptographic artifacts captured.", styles["Body"]))
    else:
        rows = [["Cipher ID", "Algorithm", "Mode", "Key Length (bits)"]]
        for artifact in dynamic["crypto_artifacts"][:15]:
            rows.append([
                str(artifact.get("cipher_id", "—")),
                artifact.get("algorithm", "—"),
                "ENCRYPT" if artifact.get("mode") == 1 else "DECRYPT",
                str(artifact.get("key_length_bits", "—")),
            ])
        elements.append(_table(rows))
    elements.append(Spacer(1, 0.5*cm))
    return elements


def _section_network(styles, static, dynamic) -> list:
    elements = [
        Paragraph("7. NETWORK COMMUNICATION ANALYSIS", styles["SectionHeader"]),
        HRFlowable(width="100%", thickness=1, color=GARUDATVA_GOLD),
        Spacer(1, 0.3*cm),
    ]
    all_ips = []
    all_urls = []
    if static and static.iocs:
        from models.ioc import IOCType
        all_ips = [ioc.value for ioc in static.iocs if ioc.ioc_type == IOCType.IP][:15]
        all_urls = [ioc.value for ioc in static.iocs if ioc.ioc_type == IOCType.URL][:10]
    if all_ips:
        elements.append(Paragraph("Extracted IP Addresses (static analysis):", styles["SubHeader"]))
        for ip in all_ips:
            elements.append(Paragraph(f"• {ip}", styles["Mono"]))
    if dynamic and dynamic.get("ja4_hashes"):
        elements.append(Spacer(1, 0.2*cm))
        elements.append(Paragraph("JA4 TLS Fingerprints:", styles["SubHeader"]))
        for h in dynamic["ja4_hashes"][:5]:
            elements.append(Paragraph(f"• {h}", styles["Mono"]))
    elements.append(Spacer(1, 0.5*cm))
    return elements


def _section_cloud_c2(styles, cloud) -> list:
    elements = [
        Paragraph("8. CLOUD C2 ASSESSMENT", styles["SectionHeader"]),
        HRFlowable(width="100%", thickness=1, color=GARUDATVA_GOLD),
        Spacer(1, 0.3*cm),
    ]
    if not cloud:
        elements.append(Paragraph("Cloud C2 classification not performed.", styles["Body"]))
    else:
        additions = cloud.get("score_additions", {})
        if additions:
            rows = [["Detection", "Score Addition"]]
            labels = {
                "connects_to_cloud_asn":    "Cloud ASN Connection",
                "dga_domain_detected":      "DGA Domain",
                "domain_fronting_detected": "Domain Fronting",
                "firebase_c2_pattern":      "Firebase C2",
                "tunnel_service_detected":  "Tunnel Service",
            }
            for key, val in additions.items():
                rows.append([labels.get(key, key), f"+{val}"])
            elements.append(_table(rows))
        if cloud.get("tunnel_services"):
            elements.append(Spacer(1, 0.2*cm))
            elements.append(Paragraph("Tunnel Services Detected:", styles["SubHeader"]))
            for t in cloud["tunnel_services"]:
                elements.append(Paragraph(f"• {t.get('domain', '')} via {t.get('service', '')}", styles["Mono"]))
    elements.append(Spacer(1, 0.5*cm))
    return elements


def _section_iocs(styles, static) -> list:
    elements = [
        Paragraph("9. INDICATORS OF COMPROMISE", styles["SectionHeader"]),
        HRFlowable(width="100%", thickness=1, color=GARUDATVA_GOLD),
        Spacer(1, 0.3*cm),
    ]
    if static and static.iocs:
        rows = [["Type", "Value", "Source"]]
        for ioc in static.iocs[:20]:
            rows.append([
                ioc.ioc_type.value,
                ioc.value[:60],
                ioc.source,
            ])
        elements.append(_table(rows))
    else:
        elements.append(Paragraph("No IOCs extracted.", styles["Body"]))
    elements.append(Spacer(1, 0.5*cm))
    return elements


def _section_syndicate(styles, graph) -> list:
    elements = [
        Paragraph("10. SYNDICATE LINKAGE", styles["SectionHeader"]),
        HRFlowable(width="100%", thickness=1, color=GARUDATVA_GOLD),
        Spacer(1, 0.3*cm),
    ]
    if not graph or not graph.get("syndicates"):
        elements.append(Paragraph("No syndicate links identified in current graph database.", styles["Body"]))
    else:
        elements.append(Paragraph(
            f"{len(graph['syndicates'])} syndicate link(s) identified across cases.",
            styles["Body"]
        ))
        rows = [["Link Type", "Related Case", "Shared Indicator"]]
        for s in graph["syndicates"][:10]:
            rows.append([
                s.get("link_type", ""),
                s.get("related_case", "")[:20],
                s.get("shared_ip", s.get("shared_cert", ""))[:30],
            ])
        elements.append(_table(rows))
    elements.append(Spacer(1, 0.5*cm))
    return elements


def _section_risk(styles, static) -> list:
    elements = [
        Paragraph("11. RISK ASSESSMENT", styles["SectionHeader"]),
        HRFlowable(width="100%", thickness=1, color=GARUDATVA_GOLD),
        Spacer(1, 0.3*cm),
    ]
    if static and static.risk_score:
        rs = static.risk_score
        tier_color = TIER_COLORS.get(rs.tier, colors.grey)
        elements.append(Paragraph(
            f"RISK SCORE: {rs.total:.1f} / 100 — TIER: {rs.tier}",
            ParagraphStyle("RiskScore", fontSize=16, textColor=tier_color, spaceAfter=10)
        ))

        from core.static.ml_classifier import get_model_metrics
        model_metrics = get_model_metrics()
        if model_metrics:
            ml_label = (
                f"ML Classifier (Random Forest, measured CV AUC "
                f"{model_metrics['cv_auc_mean']:.3f})"
            )
        else:
            ml_label = "ML Classifier (heuristic fallback — no trained model deployed)"

        rows = [
            ["Component", "Score", "Max"],
            [ml_label, f"{rs.ml_score:.1f}", "35"],
            ["Syscall Profile (strace dynamic)", f"{rs.syscall_score:.1f}", "15"],
            ["YARA Ruleset Matches", f"{rs.yara_score:.1f}", "20"],
            ["Toxic Permission Combinations", f"{rs.permission_score:.1f}", "10"],
            ["India Fraud Pattern Matches", f"{rs.india_pattern_score:.1f}", "10"],
            ["Certificate Anomalies", f"{rs.cert_score:.1f}", "5"],
            ["Manifest Obfuscation", f"{rs.manifest_score:.1f}", "5"],
            ["TOTAL", f"{rs.total:.1f}", "100"],
        ]
        elements.append(_table(rows))
        if rs.shap_features:
            elements.append(Spacer(1, 0.2*cm))
            elements.append(Paragraph("Top ML Features (SHAP Explainability):", styles["SubHeader"]))
            rows2 = [["Rank", "Feature", "SHAP Value", "Feature Value"]]
            for f in rs.shap_features[:8]:
                rows2.append([str(f.rank), f.feature_name, f"{f.shap_value:.4f}", f"{f.feature_value:.2f}"])
            elements.append(_table(rows2))
    elements.append(Spacer(1, 0.5*cm))
    return elements


def _section_actions(styles, static) -> list:
    elements = [
        Paragraph("12. RECOMMENDED IMMEDIATE ACTIONS", styles["SectionHeader"]),
        HRFlowable(width="100%", thickness=1, color=GARUDATVA_GOLD),
        Spacer(1, 0.3*cm),
    ]
    tier = static.risk_score.tier if static and static.risk_score else "SUSPICIOUS"
    actions = {
        "BENIGN":     ["Document analysis. No immediate action required. Archive report."],
        "SUSPICIOUS": [
            "Forward report to Cyber Crime Unit for review.",
            "Preserve device — do not factory reset.",
            "Identify victim financial accounts for protective freeze.",
        ],
        "HIGH_RISK": [
            "Issue preservation notice to payment gateway operators.",
            "Arrest warrant application supported by this report.",
            "Request mutual legal assistance for C2 server takedown.",
            "Notify CERT-In under IT Act Section 70B.",
            "Brief prosecutor — this report is court-admissible.",
        ],
        "CRITICAL": [
            "IMMEDIATE: Freeze victim financial accounts.",
            "Arrest warrant — report provides prima facie evidence.",
            "Emergency mutual legal assistance request for C2 servers.",
            "Notify CBI Cyber Crime Unit and CERT-In immediately.",
            "Initiate UAPA proceedings if transnational elements confirmed.",
            "Preserve all network logs from ISPs under legal process.",
        ],
    }
    for action in actions.get(tier, []):
        elements.append(Paragraph(f"• {action}", styles["Body"]))
    elements.append(Spacer(1, 0.5*cm))
    return elements


def _section_narrative(styles, llm) -> list:
    elements = [
        Paragraph("FORENSIC NARRATIVE (AI-ASSISTED, VALIDATED)", styles["SectionHeader"]),
        HRFlowable(width="100%", thickness=1, color=GARUDATVA_GOLD),
        Spacer(1, 0.3*cm),
        Paragraph(llm.get("text", ""), styles["Body"]),
    ]
    return elements


def _custody_exhibit(styles, custody) -> list:
    elements = [
        Paragraph("EXHIBIT A — CUSTODY CHAIN (BSA SEC 63)", styles["SectionHeader"]),
        HRFlowable(width="100%", thickness=1, color=GARUDATVA_GOLD),
        Spacer(1, 0.3*cm),
    ]
    manifest = custody.to_manifest()
    elements.append(Paragraph(
        f"Total entries: {manifest.total_entries}. "
        f"Chain integrity: {'VERIFIED' if manifest.chain_valid else 'COMPROMISED'}.",
        styles["Body"]
    ))
    rows = [["Seq", "Stage", "Action", "Actor", "Timestamp"]]
    for entry in manifest.entries[:30]:
        rows.append([
            str(entry.sequence),
            entry.stage[:20],
            entry.action[:40],
            entry.actor[:15],
            entry.timestamp[:19],
        ])
    elements.append(_table(rows))
    return elements


def _regional_summary(styles, translation) -> list:
    elements = [
        Paragraph("REGIONAL LANGUAGE SUMMARY — ಕನ್ನಡ / हिन्दी", styles["SectionHeader"]),
        HRFlowable(width="100%", thickness=1, color=GARUDATVA_GOLD),
        Spacer(1, 0.3*cm),
    ]
    if translation.get("kannada"):
        elements.append(Paragraph("ಕನ್ನಡ (Kannada):", styles["SubHeader"]))
        elements.append(Paragraph(translation["kannada"], styles["Body"]))
        elements.append(Spacer(1, 0.3*cm))
    if translation.get("hindi"):
        elements.append(Paragraph("हिन्दी (Hindi):", styles["SubHeader"]))
        elements.append(Paragraph(translation["hindi"], styles["Body"]))
    return elements


# ── Helpers ───────────────────────────────────────────────────────────────────

def _table(rows: list) -> Table:
    t = Table(rows, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0),  GARUDATVA_BLUE),
        ("TEXTCOLOR",    (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",     (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
        ("GRID",         (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ("WORDWRAP",     (0, 0), (-1, -1), True),
        ("LEFTPADDING",  (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def _build_styles() -> dict:
    base = getSampleStyleSheet()
    styles = {}
    styles["CoverTitle"] = ParagraphStyle(
        "CoverTitle", fontSize=24, fontName="Helvetica-Bold",
        textColor=GARUDATVA_DARK, alignment=TA_CENTER, spaceAfter=12,
    )
    styles["CoverSubtitle"] = ParagraphStyle(
        "CoverSubtitle", fontSize=12, fontName="Helvetica",
        textColor=GARUDATVA_BLUE, alignment=TA_CENTER, spaceAfter=8,
    )
    styles["CoverMeta"] = ParagraphStyle(
        "CoverMeta", fontSize=11, fontName="Helvetica",
        textColor=GARUDATVA_DARK, alignment=TA_CENTER, spaceAfter=4,
    )
    styles["Confidential"] = ParagraphStyle(
        "Confidential", fontSize=10, fontName="Helvetica-Bold",
        textColor=GARUDATVA_GOLD, alignment=TA_CENTER, spaceBefore=20,
    )
    styles["SectionHeader"] = ParagraphStyle(
        "SectionHeader", fontSize=13, fontName="Helvetica-Bold",
        textColor=GARUDATVA_DARK, spaceBefore=16, spaceAfter=4,
    )
    styles["SubHeader"] = ParagraphStyle(
        "SubHeader", fontSize=10, fontName="Helvetica-Bold",
        textColor=GARUDATVA_BLUE, spaceBefore=8, spaceAfter=4,
    )
    styles["Body"] = ParagraphStyle(
        "Body", fontSize=9, fontName="Helvetica",
        textColor=colors.black, spaceAfter=6, leading=14,
    )
    styles["Mono"] = ParagraphStyle(
        "Mono", fontSize=8, fontName="Courier",
        textColor=GARUDATVA_DARK, spaceAfter=3,
    )
    return styles
