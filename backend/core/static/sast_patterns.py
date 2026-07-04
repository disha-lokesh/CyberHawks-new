"""
Garudatva v3 — Shared Source-Level SAST Patterns
Regex patterns for hardcoded IPs/URLs/secrets/routes, shared between
jadx_decompiler.py (decompiled Java) and ghidra_analyzer.py (decompiled
native pseudo-C) so both source-level SAST passes stay in sync.
"""

from __future__ import annotations

import re
from typing import Dict, List, Set, Tuple

HARDCODED_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
HARDCODED_URL_RE = re.compile(r"https?://[^\s\"'<>]{4,300}")
SECRET_PATTERNS = {
    "AWS Access Key":        re.compile(r"AKIA[0-9A-Z]{16}"),
    "Firebase Server Key":   re.compile(r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"),
    "Generic API Key":       re.compile(r"(?i)api[_-]?key[\"']?\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,64}[\"']"),
    "Hardcoded Password":    re.compile(r"(?i)password[\"']?\s*[:=]\s*[\"'][^\"']{4,64}[\"']"),
    "Private Key Header":    re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
}
SUSPICIOUS_ROUTE_RE = re.compile(r"[\"'](/[a-zA-Z0-9_\-/]{2,80}(?:\.php|\.json|/api/[a-zA-Z0-9_\-/]*)?)[\"']")


def scan_text(text: str, rel_path: str) -> Tuple[Set[str], Set[str], Set[str], List[Dict[str, str]]]:
    """Apply all SAST patterns to a single decompiled source file's text.
    Returns (ips, urls, routes, secrets_found) for that file."""
    ips = set(HARDCODED_IP_RE.findall(text))
    urls = set(HARDCODED_URL_RE.findall(text))
    routes = {m for m in SUSPICIOUS_ROUTE_RE.findall(text) if len(m) > 3}

    secrets: List[Dict[str, str]] = []
    for label, pattern in SECRET_PATTERNS.items():
        for match in pattern.findall(text):
            secrets.append({
                "type": label,
                "file": rel_path,
                "match_preview": (match if isinstance(match, str) else match[0])[:40],
            })

    return ips, urls, routes, secrets
