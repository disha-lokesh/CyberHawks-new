"""
Garudatva v3 — Permission Risk Scorer
Maps toxic permissions to risk score contributions.
"""

from __future__ import annotations
from typing import Dict, List, Tuple

from utils.logger import get_logger

logger = get_logger(__name__)

# Weight of each toxic permission toward the 10-point permission score
PERMISSION_WEIGHTS: Dict[str, float] = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 2.5,
    "android.permission.BIND_DEVICE_ADMIN": 2.5,
    "android.permission.SYSTEM_ALERT_WINDOW": 2.0,
    "android.permission.REQUEST_INSTALL_PACKAGES": 2.0,
    "android.permission.READ_SMS": 1.5,
    "android.permission.RECEIVE_SMS": 1.5,
    "android.permission.PROCESS_OUTGOING_CALLS": 1.5,
    "android.permission.RECORD_AUDIO": 1.0,
    "android.permission.CAMERA": 1.0,
    "android.permission.ACCESS_FINE_LOCATION": 1.0,
    "android.permission.ACCESS_BACKGROUND_LOCATION": 1.5,
    "android.permission.READ_CONTACTS": 1.0,
    "android.permission.READ_CALL_LOG": 1.0,
    "android.permission.USE_BIOMETRIC": 1.5,
    "android.permission.USE_FINGERPRINT": 1.5,
    "android.permission.DISABLE_KEYGUARD": 2.0,
    "android.permission.SEND_SMS": 1.0,
    "android.permission.READ_PHONE_STATE": 0.5,
    "android.permission.RECEIVE_BOOT_COMPLETED": 0.5,
    "android.permission.FOREGROUND_SERVICE": 0.3,
    "android.permission.READ_EXTERNAL_STORAGE": 0.5,
    "android.permission.WRITE_EXTERNAL_STORAGE": 0.5,
    "android.permission.CHANGE_NETWORK_STATE": 0.3,
}

# Permission combinations that are especially dangerous together
DANGEROUS_COMBOS: List[Tuple[List[str], str, float]] = [
    (
        ["android.permission.BIND_ACCESSIBILITY_SERVICE",
         "android.permission.READ_SMS",
         "android.permission.INTERNET"],
        "Accessibility + SMS + Internet = classic banking trojan combo",
        2.0,
    ),
    (
        ["android.permission.RECORD_AUDIO",
         "android.permission.CAMERA",
         "android.permission.FOREGROUND_SERVICE"],
        "Audio + Camera + Foreground = spyware pattern",
        1.5,
    ),
    (
        ["android.permission.READ_CONTACTS",
         "android.permission.READ_CALL_LOG",
         "android.permission.INTERNET"],
        "Contacts + Calls + Internet = fake loan app exfil combo",
        1.5,
    ),
    (
        ["android.permission.SYSTEM_ALERT_WINDOW",
         "android.permission.INTERNET",
         "android.permission.BIND_ACCESSIBILITY_SERVICE"],
        "Overlay + Internet + Accessibility = credential overlay malware",
        2.5,
    ),
]


def score_permissions(all_permissions: List[str]) -> Tuple[float, List[str]]:
    """
    Return (score_0_to_10, list_of_contributing_reasons).
    score is capped at 10, the maximum allowed for permission component.
    """
    perm_set = set(all_permissions)
    reasons: List[str] = []
    raw_score = 0.0

    for perm, weight in PERMISSION_WEIGHTS.items():
        if perm in perm_set:
            raw_score += weight
            reasons.append(f"{perm} (+{weight})")

    # Combo bonuses
    for combo_perms, combo_desc, bonus in DANGEROUS_COMBOS:
        if all(p in perm_set for p in combo_perms):
            raw_score += bonus
            reasons.append(f"Dangerous combo: {combo_desc} (+{bonus})")

    capped = min(raw_score, 10.0)
    logger.info(f"Permission score: {capped:.1f}/10 ({len(reasons)} factors)")
    return round(capped, 2), reasons
