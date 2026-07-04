"""
Garudatva v3 — APK Certificate Parser
Extracts and validates signing certificates.
Detects anomalies: debug certs, expired certs, self-signed chains, mismatches.
"""

from __future__ import annotations

import hashlib
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization

from utils.logger import get_logger

logger = get_logger(__name__)

KNOWN_DEBUG_SUBJECTS = {
    "CN=Android Debug, O=Android, C=US",
}


class CertificateResult:
    def __init__(self):
        self.certificates: List[Dict] = []
        self.signing_cert_sha1: str = ""
        self.signing_cert_sha256: str = ""
        self.subject: str = ""
        self.issuer: str = ""
        self.valid_from: Optional[str] = None
        self.valid_until: Optional[str] = None
        self.is_expired: bool = False
        self.is_debug_cert: bool = False
        self.is_self_signed: bool = False
        self.serial_number: str = ""
        self.anomalies: List[str] = []
        self.anomaly_score: float = 0.0
        self.errors: List[str] = []


def parse_certificate(apk_path: Path) -> CertificateResult:
    """Extract and analyse APK signing certificate."""
    result = CertificateResult()

    cert_bytes = _extract_cert_from_apk(apk_path)
    if not cert_bytes:
        result.errors.append("No signing certificate found in APK")
        return result

    try:
        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
        _populate_from_cert(cert, cert_bytes, result)
        _detect_anomalies(cert, result)
    except Exception as e:
        result.errors.append(f"Certificate parse error: {e}")
        logger.error(f"Certificate parse failed: {e}")

    return result


def _extract_cert_from_apk(apk_path: Path) -> Optional[bytes]:
    """Extract the main signing certificate DER bytes from META-INF/."""
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for name in zf.namelist():
                if name.upper().startswith("META-INF/") and (
                    name.upper().endswith(".RSA")
                    or name.upper().endswith(".DSA")
                    or name.upper().endswith(".EC")
                ):
                    pkcs7_bytes = zf.read(name)
                    # Extract DER cert from PKCS#7 (simple extraction)
                    return _extract_der_from_pkcs7(pkcs7_bytes)
    except Exception as e:
        logger.warning(f"Cert extraction failed: {e}")
    return None


def _extract_der_from_pkcs7(pkcs7: bytes) -> Optional[bytes]:
    """
    Extract the signing certificate's DER bytes from a DER-encoded PKCS#7
    SignedData blob (the .RSA/.DSA/.EC file in META-INF/).

    Uses `cryptography`'s native PKCS#7 parser — NOT `openssl pkcs7
    -print_certs -outform DER`, which silently ignores -outform for
    -print_certs and emits human-readable PEM text instead of raw DER,
    producing bytes that look plausible but fail ASN.1 parsing downstream.
    """
    try:
        from cryptography.hazmat.primitives.serialization.pkcs7 import load_der_pkcs7_certificates
        certs = load_der_pkcs7_certificates(pkcs7)
        if certs:
            return certs[0].public_bytes(serialization.Encoding.DER)
    except Exception as e:
        logger.warning(f"PKCS7 cert extraction failed: {e}")

    return None


def _populate_from_cert(cert: x509.Certificate, cert_bytes: bytes, result: CertificateResult) -> None:
    result.subject = cert.subject.rfc4514_string()
    result.issuer = cert.issuer.rfc4514_string()
    result.serial_number = str(cert.serial_number)
    result.valid_from = cert.not_valid_before_utc.isoformat()
    result.valid_until = cert.not_valid_after_utc.isoformat()

    now = datetime.now(timezone.utc)
    result.is_expired = cert.not_valid_after_utc < now

    result.signing_cert_sha1 = hashlib.sha1(cert_bytes).hexdigest()
    result.signing_cert_sha256 = hashlib.sha256(cert_bytes).hexdigest()

    result.certificates.append({
        "subject": result.subject,
        "issuer": result.issuer,
        "serial": result.serial_number,
        "valid_from": result.valid_from,
        "valid_until": result.valid_until,
        "sha1": result.signing_cert_sha1,
        "sha256": result.signing_cert_sha256,
    })


def _detect_anomalies(cert: x509.Certificate, result: CertificateResult) -> None:
    score = 0.0

    # Debug certificate
    subject_str = cert.subject.rfc4514_string()
    if any(debug in subject_str for debug in KNOWN_DEBUG_SUBJECTS):
        result.is_debug_cert = True
        result.anomalies.append("Debug signing certificate (production APK should use release cert)")
        score += 2.0

    # Self-signed
    if cert.subject == cert.issuer:
        result.is_self_signed = True
        result.anomalies.append("Self-signed certificate")
        score += 1.0

    # Expired
    if result.is_expired:
        result.anomalies.append(f"Certificate expired: {result.valid_until}")
        score += 1.5

    # Validity period anomalies
    try:
        valid_years = (
            cert.not_valid_after_utc - cert.not_valid_before_utc
        ).days / 365
        if valid_years > 30:
            result.anomalies.append(f"Unusually long validity: {valid_years:.0f} years")
            score += 0.5
    except Exception:
        pass

    # Weak serial number (e.g. serial=0 or serial=1 used by default tools)
    if cert.serial_number in (0, 1):
        result.anomalies.append(f"Weak serial number: {cert.serial_number}")
        score += 0.5

    result.anomaly_score = min(score, 5.0)
    logger.info(
        f"Cert: subject={result.subject[:50]}… "
        f"anomalies={len(result.anomalies)} score={result.anomaly_score}"
    )
