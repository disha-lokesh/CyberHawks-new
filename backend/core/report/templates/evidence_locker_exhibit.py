"""
Garudatva v3 — Evidence Locker Exhibit Template
BNSS Section 176(3) video evidence exhibit for PDF.
Lists all items with SHA256 hashes, GPS, officer ID, witnesses.
Appended to PDF as Exhibit A.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List

from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import HRFlowable, Paragraph, Spacer, Table, TableStyle

GARUDATVA_DARK = colors.HexColor("#1a1a2e")
GARUDATVA_BLUE = colors.HexColor("#16213e")
GARUDATVA_GOLD = colors.HexColor("#e94560")
COMPLIANT_GREEN = colors.HexColor("#27ae60")


def render_evidence_exhibit(styles: dict, case_id: str) -> list:
    """
    Render the BNSS 176(3) evidence locker exhibit.
    Loads manifest from disk for the given case_id.
    """
    elements = [
        Paragraph("EXHIBIT A — EVIDENCE LOCKER MANIFEST (BNSS SEC 176(3))", styles["SectionHeader"]),
        HRFlowable(width="100%", thickness=1, color=GARUDATVA_GOLD),
        Spacer(1, 0.3 * cm),
    ]

    # Load manifest
    try:
        from core.evidence.locker_manifest import get_case_manifest
        manifest = get_case_manifest(case_id)
    except FileNotFoundError:
        elements.append(Paragraph(
            "No evidence items registered for this case. "
            "BNSS Section 176(3) videography may not have been completed.",
            styles["Body"],
        ))
        return elements

    items = manifest.get("items", [])
    total = manifest.get("total_items", len(items))

    # ── Legal declaration ─────────────────────────────────────────────────────
    elements.append(Paragraph(
        "BHARATIYA NAGARIK SURAKSHA SANHITA (BNSS) SECTION 176(3) COMPLIANCE",
        ParagraphStyle(
            "BNSSHeader", fontSize=10, fontName="Helvetica-Bold",
            textColor=GARUDATVA_BLUE, spaceAfter=6,
        ),
    ))
    elements.append(Paragraph(
        "Section 176(3) of the BNSS mandates videography for all offences "
        "punishable with imprisonment of seven years or more. The following "
        "evidence items were seized, hashed, and ingested in compliance with "
        "this requirement. SHA256 hashes were computed immediately upon receipt "
        "and are permanently linked to the custody chain.",
        styles["Body"],
    ))
    elements.append(Spacer(1, 0.3 * cm))

    # ── Manifest summary ──────────────────────────────────────────────────────
    summary_rows = [
        ["Property", "Value"],
        ["Case ID",         case_id],
        ["Total Items",     str(total)],
        ["Last Updated",    manifest.get("last_updated", "—")],
        ["Hash Algorithm",  "SHA256 (primary) + SHA1 + MD5 (compatibility)"],
        ["Legal Basis",     "BNSS Section 176(3) — IT Act Section 79A"],
        ["Generated",       datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")],
    ]
    elements.append(_summary_table(summary_rows))
    elements.append(Spacer(1, 0.3 * cm))

    if not items:
        elements.append(Paragraph(
            "No evidence items have been ingested for this case.",
            styles["Body"],
        ))
        return elements

    # ── Per-item detail ───────────────────────────────────────────────────────
    elements.append(Paragraph(
        f"Registered Evidence Items ({total}):",
        styles["SubHeader"],
    ))
    elements.append(Spacer(1, 0.15 * cm))

    for idx, item in enumerate(items, 1):
        elements += _render_item(styles, idx, item)

    # ── Hash verification table (all items) ───────────────────────────────────
    elements.append(Spacer(1, 0.3 * cm))
    elements.append(Paragraph("Hash Verification Summary:", styles["SubHeader"]))
    elements.append(Spacer(1, 0.15 * cm))

    hash_rows = [["#", "Filename", "SHA256 (Integrity Hash)", "Size (bytes)"]]
    for idx, item in enumerate(items, 1):
        sha256 = item.get("sha256", "—")
        # Show first 32 chars + … for readability while still being verifiable
        sha256_display = sha256[:32] + "…" if len(sha256) > 32 else sha256
        hash_rows.append([
            str(idx),
            item.get("filename", "—")[:30],
            sha256_display,
            f"{item.get('file_size_bytes', 0):,}",
        ])
    elements.append(_hash_table(hash_rows))

    elements.append(Spacer(1, 0.3 * cm))
    elements.append(Paragraph(
        "CERTIFICATION: The SHA256 hashes listed above were computed at the moment "
        "of evidence ingestion and are permanently recorded in the BSA Section 63 "
        "custody chain. Any modification to the evidence files will result in a "
        "hash mismatch detectable by re-running sha256sum on the stored files.",
        styles["Body"],
    ))
    elements.append(Spacer(1, 0.5 * cm))
    return elements


def _render_item(styles: dict, idx: int, item: dict) -> list:
    """Render a single evidence item as a detail block."""
    elements = []

    filename = item.get("filename", "unknown")
    bnss_ok  = item.get("bnss_176_compliant", False)
    compliance_color = COMPLIANT_GREEN if bnss_ok else colors.orange

    elements.append(Paragraph(
        f"Item {idx}: {filename}",
        ParagraphStyle(
            "ItemHeader", fontSize=9, fontName="Helvetica-Bold",
            textColor=GARUDATVA_DARK, spaceBefore=6, spaceAfter=3,
        ),
    ))

    rows = [
        ["Field",         "Value"],
        ["Item ID",       item.get("item_id", "—")],
        ["SHA256",        item.get("sha256", "—")],
        ["SHA1",          item.get("sha1", "—")],
        ["MD5",           item.get("md5", "—")],
        ["File Size",     f"{item.get('file_size_bytes', 0):,} bytes"],
        ["MIME Type",     item.get("mime_type", "—")],
        ["Description",   item.get("description", "—")],
        ["Ingested At",   item.get("ingested_at", "—")],
        ["Seized By",     item.get("ingested_by", "—")],
        ["GPS Location",  _fmt_gps(item)],
        ["Witnesses",     ", ".join(item.get("witnesses", [])) or "None recorded"],
        ["BNSS 176(3)",   "COMPLIANT ✓" if bnss_ok else "NOT MARKED COMPLIANT"],
    ]

    t = Table(rows, colWidths=[3.5 * cm, 13.5 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (0, -1),  colors.HexColor("#f0f0f0")),
        ("FONTNAME",    (0, 0), (0, -1),  "Helvetica-Bold"),
        ("FONTNAME",    (1, 0), (1, -1),  "Courier"),
        ("FONTSIZE",    (0, 0), (-1, -1), 7),
        ("GRID",        (0, 0), (-1, -1), 0.3, colors.HexColor("#cccccc")),
        ("VALIGN",      (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        # Colour BNSS row
        ("TEXTCOLOR",   (1, -1), (1, -1), compliance_color),
        ("FONTNAME",    (1, -1), (1, -1), "Helvetica-Bold"),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 0.2 * cm))
    return elements


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fmt_gps(item: dict) -> str:
    lat = item.get("gps_lat")
    lon = item.get("gps_lon")
    if lat is not None and lon is not None:
        return f"{lat:.6f}°N, {lon:.6f}°E"
    return "Not recorded"


def _summary_table(rows: list) -> Table:
    t = Table(rows)
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  GARUDATVA_BLUE),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
        ("GRID",          (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
    ]))
    return t


def _hash_table(rows: list) -> Table:
    t = Table(
        rows,
        colWidths=[0.8 * cm, 4 * cm, 9.5 * cm, 2.5 * cm],
        repeatRows=1,
    )
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  GARUDATVA_BLUE),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTNAME",      (0, 1), (-1, -1), "Courier"),
        ("FONTSIZE",      (0, 0), (-1, -1), 7),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
        ("GRID",          (0, 0), (-1, -1), 0.3, colors.HexColor("#cccccc")),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
    ]))
    return t
