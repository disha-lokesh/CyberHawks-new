"""
Garudatva v3 — YARA Scanner
Scans APK content against 6 custom YARA rulesets.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Optional

from utils.logger import get_logger
from models.ioc import YARAMatch

logger = get_logger(__name__)

YARA_RULE_FILES = [
    ("upi_fraud.yar",          "UPI_FRAUD"),
    ("banking_trojans.yar",    "BANKING_TROJAN"),
    ("fake_loan_apps.yar",     "FAKE_LOAN"),
    ("aadhaar_harvesting.yar", "AADHAAR"),
    ("rat_indicators.yar",     "RAT"),
    ("c2_infrastructure.yar",  "C2"),
]

# Score per YARA category hit (contributes to 20-point YARA score)
CATEGORY_SCORES: Dict[str, float] = {
    "UPI_FRAUD":       5.0,
    "BANKING_TROJAN":  6.0,
    "FAKE_LOAN":       4.0,
    "AADHAAR":         5.0,
    "RAT":             6.0,
    "C2":              7.0,
}


class YARAScanResult:
    def __init__(self):
        self.matches: List[YARAMatch] = []
        self.categories_hit: List[str] = []
        self.yara_score: float = 0.0
        self.errors: List[str] = []


def scan_with_yara(
    target_paths: List[Path],
    yara_rules_dir: Path,
) -> YARAScanResult:
    """
    Scan all target files against each YARA ruleset.
    target_paths: list of files to scan (DEX, APK, .so, etc.)
    """
    result = YARAScanResult()

    try:
        import yara
    except ImportError:
        result.errors.append("yara-python not installed")
        logger.error("yara-python not installed — install: pip install yara-python")
        return result

    for rule_file, category in YARA_RULE_FILES:
        rule_path = yara_rules_dir / rule_file
        if not rule_path.exists():
            logger.warning(f"YARA rule not found: {rule_path}")
            result.errors.append(f"Missing rule file: {rule_file}")
            continue

        try:
            compiled = yara.compile(filepath=str(rule_path))
        except yara.SyntaxError as e:
            result.errors.append(f"YARA syntax error in {rule_file}: {e}")
            logger.error(f"YARA compile error {rule_file}: {e}")
            continue

        category_hit = False
        for target in target_paths:
            if not target.exists() or not target.is_file():
                continue
            try:
                matches = compiled.match(str(target))
                for m in matches:
                    strings_matched = [
                        s.identifier for s in m.strings
                    ] if hasattr(m, "strings") else []
                    result.matches.append(
                        YARAMatch(
                            rule_name=m.rule,
                            rule_file=rule_file,
                            category=category,
                            strings_matched=strings_matched[:20],
                            meta=dict(m.meta) if m.meta else {},
                        )
                    )
                    category_hit = True
                    logger.info(
                        f"YARA hit: {m.rule} ({category}) in {target.name}"
                    )
            except yara.Error as e:
                result.errors.append(f"YARA scan error on {target.name}: {e}")

        if category_hit and category not in result.categories_hit:
            result.categories_hit.append(category)

    # Score = sum of category scores, capped at 20
    score = sum(CATEGORY_SCORES.get(cat, 3.0) for cat in result.categories_hit)
    result.yara_score = min(score, 20.0)

    logger.info(
        f"YARA scan complete: {len(result.matches)} matches, "
        f"{len(result.categories_hit)} categories, score={result.yara_score}"
    )
    return result
