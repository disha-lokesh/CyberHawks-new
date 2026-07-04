"""
Garudatva v3 — JARM Database
Matches computed JARM hashes against known malicious infrastructure.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)

JARM_DB_PATH = Path(__file__).parent.parent.parent.parent / "signatures" / "jarm_malicious_hashes.json"


class JARMDatabase:
    def __init__(self):
        self._db: Dict[str, Dict] = {}
        self._loaded = False

    def load(self) -> None:
        if self._loaded:
            return
        if not JARM_DB_PATH.exists():
            logger.warning(f"JARM DB not found: {JARM_DB_PATH}")
            return
        try:
            self._db = json.loads(JARM_DB_PATH.read_text())
            malformed = [k for k in self._db if len(k) != 62 or any(c not in "0123456789abcdef" for c in k)]
            if malformed:
                logger.warning(
                    f"JARM DB has {len(malformed)} malformed hash(es) (not 62 lowercase "
                    f"hex chars) — these can never match a real probe result and should "
                    f"be re-verified against a trusted source: {malformed}"
                )
            logger.info(f"JARM DB loaded: {len(self._db)} known hashes")
            self._loaded = True
        except Exception as e:
            logger.error(f"JARM DB load failed: {e}")

    def lookup(self, jarm_hash: str) -> Optional[Dict]:
        """
        Return match info if JARM hash is known malicious.
        Returns None if hash not in database (does not mean benign).
        """
        self.load()
        return self._db.get(jarm_hash)

    def lookup_many(self, jarm_hashes: List[str]) -> List[Dict]:
        """Lookup multiple JARM hashes. Returns only matches."""
        self.load()
        results = []
        for jh in jarm_hashes:
            match = self._db.get(jh)
            if match:
                results.append({"jarm_hash": jh, **match})
        return results


# Singleton
_db = JARMDatabase()


def lookup_jarm(jarm_hash: str) -> Optional[Dict]:
    return _db.lookup(jarm_hash)
