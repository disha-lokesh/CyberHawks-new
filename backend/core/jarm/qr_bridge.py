"""
Garudatva v3 — QR Air-Gap Bridge
Solves the JARM vs air-gap contradiction.
Workstation A (offline) encodes C2 IPs into a QR code.
Workstation B (online) scans it, runs JARM, returns results via second QR.
SHA256 of payload embedded in QR — tampered QR rejected on import.
All bridge events logged to custody chain.
"""

from __future__ import annotations

import base64
import json
import hashlib
from typing import Dict, List, Tuple

from utils.logger import get_logger

logger = get_logger(__name__)


def generate_c2_qr(ips: List[str], analysis_id: str) -> Tuple[str, str]:
    """
    Encode C2 IPs into a QR code for transfer to Workstation B.

    Returns:
        (qr_image_base64, payload_sha256)
    """
    import qrcode
    import io

    payload = {
        "analysis_id": analysis_id,
        "ips": ips,
        "version": "garudatva_v3",
    }
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    payload_sha256 = hashlib.sha256(payload_json.encode()).hexdigest()

    # Embed the hash inside the payload so receiver can verify
    payload["sha256"] = payload_sha256
    final_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=6,
        border=2,
    )
    qr.add_data(final_json)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    logger.info(
        f"QR generated: {len(ips)} IPs, "
        f"analysis={analysis_id}, sha256={payload_sha256[:16]}…"
    )
    return qr_b64, payload_sha256


def import_jarm_results(qr_payload_json: str) -> Dict:
    """
    Validate and parse JARM results returned from Workstation B via QR.
    Raises ValueError if SHA256 does not match — tampered QR rejected.
    """
    try:
        data = json.loads(qr_payload_json)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid QR JSON: {e}")

    received_hash = data.pop("sha256", None)
    if not received_hash:
        raise ValueError("QR payload missing sha256 field — rejected")

    # Recompute hash on payload without sha256 field
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    expected_hash = hashlib.sha256(canonical.encode()).hexdigest()

    if received_hash != expected_hash:
        logger.error(
            f"QR TAMPER DETECTED: "
            f"expected={expected_hash[:16]}… got={received_hash[:16]}…"
        )
        raise ValueError(
            f"QR integrity check FAILED — payload tampered. "
            f"Expected SHA256: {expected_hash[:16]}…"
        )

    logger.info(
        f"QR import validated OK: "
        f"{len(data.get('jarm_results', []))} JARM results"
    )
    return data


def encode_jarm_results_qr(jarm_results: List[Dict], analysis_id: str) -> Tuple[str, str]:
    """
    Called on Workstation B — encode JARM results into QR for import back to A.
    """
    import qrcode
    import io

    payload = {
        "analysis_id": analysis_id,
        "jarm_results": jarm_results,
        "version": "garudatva_v3",
    }
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    payload_sha256 = hashlib.sha256(payload_json.encode()).hexdigest()
    payload["sha256"] = payload_sha256
    final_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=5,
        border=2,
    )
    qr.add_data(final_json)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return qr_b64, payload_sha256
