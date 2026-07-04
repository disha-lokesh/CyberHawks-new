"""
Garudatva v3 — Custody Chain
BSA Sec 63 compliant: Canonical JSON + UUIDv7 + SHA256 hash chain.

Each entry's hash covers:
  - Its own canonical JSON (keys sorted alphabetically at every level)
  - The previous entry's hash (chain linkage)

Tampering with any entry invalidates all subsequent hashes.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from uuid_extensions import uuid7str   # pip install uuid-extensions

from utils.hasher import sha256_str
from utils.logger import get_logger
from models.report import CustodyEvent, CustodyChainManifest

logger = get_logger(__name__)


def canonical_json(obj: dict) -> str:
    """
    Deterministic serialization — keys sorted alphabetically at every
    nesting level. Identical data = identical hash.
    Prevents false tampering alerts in court evidence.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


class CustodyChain:
    """
    Append-only BSA Sec 63 custody chain for one analysis run.

    Usage:
        chain = CustodyChain(analysis_id, case_id, apk_sha256)
        chain.log(stage="UPLOAD", action="APK received", actor="officer_001")
        chain.log(stage="STATIC", action="YARA scan complete", artifact_sha256="abc...")
        chain.verify()   # True if unbroken
        chain.save(path)
    """

    def __init__(self, analysis_id: str, case_id: str, apk_sha256: str):
        self.analysis_id = analysis_id
        self.case_id = case_id
        self.apk_sha256 = apk_sha256
        self._entries: List[CustodyEvent] = []
        self._sequence = 0
        logger.info(f"CustodyChain initialised — analysis_id={analysis_id}")

    # ── Public API ──────────────────────────────────────────────────────

    def log(
        self,
        stage: str,
        action: str,
        actor: str = "system",
        artifact_sha256: Optional[str] = None,
    ) -> CustodyEvent:
        """Append a new entry to the chain and return it."""
        prev_hash = self._entries[-1].entry_hash if self._entries else "GENESIS"
        entry_id = uuid7str()   # First 48 bits are timestamp
        timestamp = datetime.now(timezone.utc).isoformat()
        seq = self._sequence

        # Build canonical payload for hashing
        payload = {
            "action": action,
            "actor": actor,
            "analysis_id": self.analysis_id,
            "artifact_sha256": artifact_sha256,
            "case_id": self.case_id,
            "entry_id": entry_id,
            "prev_hash": prev_hash,
            "sequence": seq,
            "stage": stage,
            "timestamp": timestamp,
        }
        entry_hash = sha256_str(canonical_json(payload))

        event = CustodyEvent(
            entry_id=entry_id,
            sequence=seq,
            stage=stage,
            action=action,
            actor=actor,
            timestamp=timestamp,
            artifact_sha256=artifact_sha256,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
        self._entries.append(event)
        self._sequence += 1
        logger.debug(f"[custody] seq={seq} stage={stage} hash={entry_hash[:16]}…")
        return event

    def verify(self) -> bool:
        """
        Recompute every entry hash and verify the chain.
        Returns True if intact, False if any entry was tampered.
        """
        if not self._entries:
            return True

        prev_hash = "GENESIS"
        for event in self._entries:
            payload = {
                "action": event.action,
                "actor": event.actor,
                "analysis_id": self.analysis_id,
                "artifact_sha256": event.artifact_sha256,
                "case_id": self.case_id,
                "entry_id": event.entry_id,
                "prev_hash": prev_hash,
                "sequence": event.sequence,
                "stage": event.stage,
                "timestamp": event.timestamp,
            }
            expected = sha256_str(canonical_json(payload))
            if expected != event.entry_hash:
                logger.error(
                    f"Chain BROKEN at seq={event.sequence} "
                    f"expected={expected[:16]}… got={event.entry_hash[:16]}…"
                )
                return False
            prev_hash = event.entry_hash

        logger.info(f"Chain verified OK — {len(self._entries)} entries intact")
        return True

    def to_manifest(self) -> CustodyChainManifest:
        return CustodyChainManifest(
            analysis_id=self.analysis_id,
            case_id=self.case_id,
            apk_sha256=self.apk_sha256,
            entries=list(self._entries),
            chain_valid=self.verify(),
            total_entries=len(self._entries),
        )

    def save(self, path: Path) -> None:
        """Write chain to JSON file for PDF exhibit attachment."""
        manifest = self.to_manifest()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            canonical_json(manifest.model_dump()),
            encoding="utf-8",
        )
        logger.info(f"Custody chain saved to {path} ({len(self._entries)} entries)")

    @classmethod
    def load(cls, path: Path) -> "CustodyChain":
        """Reload a chain from disk and verify integrity."""
        raw = json.loads(path.read_text(encoding="utf-8"))
        manifest = CustodyChainManifest(**raw)
        chain = cls(
            analysis_id=manifest.analysis_id,
            case_id=manifest.case_id,
            apk_sha256=manifest.apk_sha256,
        )
        chain._entries = manifest.entries
        chain._sequence = len(manifest.entries)
        ok = chain.verify()
        if not ok:
            raise ValueError(f"Chain integrity FAILED loading from {path}")
        return chain

    @property
    def latest_hash(self) -> str:
        if self._entries:
            return self._entries[-1].entry_hash
        return "GENESIS"

    @property
    def entry_count(self) -> int:
        return len(self._entries)
