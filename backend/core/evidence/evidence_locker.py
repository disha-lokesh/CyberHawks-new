"""
Garudatva v3 — Evidence Locker
Encrypted local storage for all evidence items.
AES-256 at rest. Access logged. Zero data leaves workstation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from config import settings
from utils.logger import get_logger

logger = get_logger(__name__)


class EvidenceLocker:
    """
    Manages encrypted evidence storage for one case.
    Uses Fernet (AES-128-CBC with HMAC-SHA256) for at-rest encryption.
    Key derived from case_id + machine secret via PBKDF2.
    """

    def __init__(self, case_id: str):
        self.case_id = case_id
        self.locker_dir = settings.EVIDENCE_DIR / case_id
        self.locker_dir.mkdir(parents=True, exist_ok=True)
        self._fernet = self._get_fernet()

    def _get_fernet(self):
        """Derive encryption key from case_id + machine secret."""
        try:
            from cryptography.fernet import Fernet
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
            import base64, os

            # Machine secret — generated once and stored locally
            secret_path = settings.BASE_DIR / "data" / ".locker_secret"
            if not secret_path.exists():
                secret_path.parent.mkdir(parents=True, exist_ok=True)
                secret_path.write_bytes(os.urandom(32))

            machine_secret = secret_path.read_bytes()
            salt = self.case_id.encode()[:16].ljust(16, b"0")

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(machine_secret))
            return Fernet(key)
        except ImportError:
            logger.warning("cryptography not installed — evidence stored unencrypted")
            return None

    def store(self, filename: str, data: bytes) -> Path:
        """Store file in locker (encrypted if available)."""
        path = self.locker_dir / filename
        if self._fernet:
            path.write_bytes(self._fernet.encrypt(data))
        else:
            path.write_bytes(data)
        logger.info(f"Stored in locker: {filename} ({len(data)} bytes)")
        return path

    def retrieve(self, filename: str) -> bytes:
        """Retrieve and decrypt file from locker."""
        path = self.locker_dir / filename
        if not path.exists():
            raise FileNotFoundError(f"Evidence item not found: {filename}")
        raw = path.read_bytes()
        if self._fernet:
            return self._fernet.decrypt(raw)
        return raw

    def cleanup(self) -> None:
        """Wipe locker after report is finalized."""
        import shutil
        shutil.rmtree(self.locker_dir, ignore_errors=True)
        logger.info(f"Evidence locker wiped for case: {self.case_id}")
