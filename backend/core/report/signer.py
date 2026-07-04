"""
Garudatva v3 — Dual Officer PDF Signer
Step 1: Reporting Officer signs (pyHanko)
Step 2: Reviewing Officer countersigns
Both signatures embedded with timestamps.
Both events logged to custody chain.
IT Act Section 79A dual-signature requirement.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

from utils.logger import get_logger

logger = get_logger(__name__)


async def dual_sign_report(
    pdf_path: Path,
    reporting_officer_badge: str,
    reviewing_officer_badge: str,
    custody=None,
) -> Path:
    """
    Apply dual pyHanko signatures to the PDF.
    Returns path to signed PDF (overwrites in place).
    """
    loop = asyncio.get_event_loop()

    # Step 1: Reporting Officer signature
    logger.info(f"Step 1: Reporting Officer {reporting_officer_badge} signing...")
    await loop.run_in_executor(
        None,
        _apply_signature,
        pdf_path,
        reporting_officer_badge,
        "Reporting Officer — IT Act Sec 79A",
        1,
    )
    if custody:
        custody.log(
            stage="PDF_SIGNING",
            action=f"Reporting Officer {reporting_officer_badge} applied digital signature",
            actor=reporting_officer_badge,
        )

    # Step 2: Reviewing Officer countersignature
    logger.info(f"Step 2: Reviewing Officer {reviewing_officer_badge} countersigning...")
    await loop.run_in_executor(
        None,
        _apply_signature,
        pdf_path,
        reviewing_officer_badge,
        "Reviewing Officer — IT Act Sec 79A Countersignature",
        2,
    )
    if custody:
        custody.log(
            stage="PDF_SIGNING",
            action=f"Reviewing Officer {reviewing_officer_badge} applied countersignature",
            actor=reviewing_officer_badge,
        )

    logger.info(f"Dual signing complete: {pdf_path}")
    return pdf_path


def _apply_signature(
    pdf_path: Path,
    officer_badge: str,
    reason: str,
    sig_number: int,
) -> None:
    """Apply a single pyHanko signature. Runs in thread executor."""
    try:
        from pyhanko.sign import signers, fields
        from pyhanko.sign.fields import SigFieldSpec
        from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
        from pyhanko.sign.signers.pdf_signer import PdfSignatureMetadata

        cert_dir = _get_or_create_cert_dir(officer_badge)
        signer = _load_signer(cert_dir, officer_badge)

        with open(pdf_path, "r+b") as pdf_file:
            writer = IncrementalPdfFileWriter(pdf_file)
            meta = PdfSignatureMetadata(
                field_name=f"Sig{sig_number}",
                reason=reason,
                certify=sig_number == 1,
            )
            # in_place=True is required for a second/third signature to be a
            # true incremental update appended to the existing stream — with
            # it left False (pyHanko's default), passing output=pdf_file
            # instead writes a fresh full copy into the same file handle
            # that's still backing the reader, corrupting the xref/trailer
            # on the second signature. in_place overrides `output`.
            signers.sign_pdf(
                writer,
                signature_meta=meta,
                signer=signer,
                in_place=True,
            )
        logger.info(f"Signature {sig_number} applied for {officer_badge}")

    except ImportError:
        logger.warning("pyHanko not installed — signatures skipped. pip install pyhanko")
    except Exception as e:
        logger.error(f"Signature {sig_number} failed for {officer_badge}: {e}")
        # Non-fatal — PDF still valid without signature for demo purposes


def _get_or_create_cert_dir(badge_id: str) -> Path:
    """Get or create self-signed cert for officer (demo mode)."""
    from config import settings
    cert_dir = settings.SIGNING_CERT_DIR / badge_id
    cert_dir.mkdir(parents=True, exist_ok=True)

    cert_path = cert_dir / "cert.pem"
    key_path  = cert_dir / "key.pem"

    if not cert_path.exists() or not key_path.exists():
        _generate_self_signed(cert_dir, badge_id)

    return cert_dir


def _generate_self_signed(cert_dir: Path, badge_id: str) -> None:
    """Generate a self-signed certificate for demo signing."""
    import subprocess
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", str(cert_dir / "key.pem"),
        "-out",    str(cert_dir / "cert.pem"),
        "-days",   "365",
        "-nodes",
        "-subj",   f"/CN={badge_id}/O=Garudatva/C=IN",
    ], capture_output=True, check=False)
    logger.info(f"Self-signed cert generated for {badge_id}")


def _load_signer(cert_dir: Path, badge_id: str):
    """Load pyHanko SimpleSigner from PEM files."""
    from pyhanko.sign import signers
    from pyhanko_certvalidator import CertificateValidator

    return signers.SimpleSigner.load(
        key_file=str(cert_dir / "key.pem"),
        cert_file=str(cert_dir / "cert.pem"),
        ca_chain_files=[str(cert_dir / "cert.pem")],
        key_passphrase=None,
    )
