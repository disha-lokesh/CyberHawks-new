"""
Garudatva v3 — Narrative Validator
Scans LLM output for 23 forbidden hedging phrases that make reports
inadmissible in court. Returns list of violations found.
"""

from __future__ import annotations

import re
from typing import List

FORBIDDEN_PHRASES = [
    "likely", "probably", "may ", "might", "possibly",
    "could", "suggests", "appears", "seems", "indicates",
    "implies", "generally", "typically", "usually", "often",
    "it is possible", "we believe", "it seems", "perhaps",
    "presumably", "apparently", "conceivably", "allegedly",
]


def validate_narrative(text: str) -> List[str]:
    """
    Return list of forbidden phrases found in text.
    Empty list = narrative passes validation.
    """
    text_lower = text.lower()
    violations = []
    for phrase in FORBIDDEN_PHRASES:
        if phrase in text_lower:
            violations.append(phrase)
    return violations


def is_valid(text: str) -> bool:
    return len(validate_narrative(text)) == 0
