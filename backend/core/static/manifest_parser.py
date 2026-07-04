"""
Garudatva v3 — AndroidManifest.xml Parser
Extracts permissions, components, intent filters, and obfuscation signals.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from utils.logger import get_logger

logger = get_logger(__name__)

ANDROID_NS = "http://schemas.android.com/apk/res/android"


# Permissions that warrant automatic score additions
TOXIC_PERMISSIONS: Set[str] = {
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.READ_PHONE_STATE",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
    "android.permission.CHANGE_NETWORK_STATE",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.DISABLE_KEYGUARD",
}

DANGEROUS_COMPONENTS = {
    "android.app.admin.DeviceAdminReceiver",
    "android.accessibilityservice.AccessibilityService",
    "android.service.notification.NotificationListenerService",
    "android.inputmethodservice.InputMethodService",
}


class ManifestResult:
    def __init__(self):
        self.package_name: str = ""
        self.version_name: str = ""
        self.version_code: str = ""
        self.min_sdk: str = ""
        self.target_sdk: str = ""
        self.permissions: List[str] = []
        self.toxic_permissions: List[str] = []
        self.activities: List[str] = []
        self.services: List[str] = []
        self.receivers: List[str] = []
        self.providers: List[str] = []
        self.intent_filters: List[Dict] = []
        self.exported_components: List[str] = []
        self.dangerous_components: List[str] = []
        self.uses_cleartext_traffic: bool = False
        self.debuggable: bool = False
        self.allow_backup: bool = False
        self.obfuscation_score: int = 0
        self.obfuscation_signals: List[str] = []
        self.raw_xml: str = ""
        self.errors: List[str] = []


def parse_manifest(manifest_path: Path) -> ManifestResult:
    """Parse decoded AndroidManifest.xml from apktool output."""
    result = ManifestResult()

    if not manifest_path or not manifest_path.exists():
        result.errors.append("AndroidManifest.xml not found")
        return result

    try:
        result.raw_xml = manifest_path.read_text(encoding="utf-8", errors="replace")
        tree = ET.parse(manifest_path)
        root = tree.getroot()
    except ET.ParseError as e:
        result.errors.append(f"XML parse error: {e}")
        return result

    def attr(el, name):
        return el.get(f"{{{ANDROID_NS}}}{name}", el.get(name, ""))

    # ── Package info ───────────────────────────────────────────────────
    result.package_name = root.get("package", "")
    result.version_name = attr(root, "versionName")
    result.version_code = attr(root, "versionCode")

    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        result.min_sdk = attr(uses_sdk, "minSdkVersion")
        result.target_sdk = attr(uses_sdk, "targetSdkVersion")

    # ── Permissions ────────────────────────────────────────────────────
    for perm in root.findall("uses-permission"):
        name = attr(perm, "name")
        if name:
            result.permissions.append(name)
            if name in TOXIC_PERMISSIONS:
                result.toxic_permissions.append(name)

    # ── Application attributes ─────────────────────────────────────────
    app = root.find("application")
    if app is not None:
        result.uses_cleartext_traffic = attr(app, "usesCleartextTraffic") == "true"
        result.debuggable = attr(app, "debuggable") == "true"
        result.allow_backup = attr(app, "allowBackup") == "true"

        # ── Components ─────────────────────────────────────────────────
        for activity in app.findall("activity"):
            n = attr(activity, "name")
            result.activities.append(n)
            if attr(activity, "exported") == "true":
                result.exported_components.append(n)

        for service in app.findall("service"):
            n = attr(service, "name")
            result.services.append(n)
            if attr(service, "exported") == "true":
                result.exported_components.append(n)
            for dc in DANGEROUS_COMPONENTS:
                if dc in (attr(service, "permission"), n):
                    result.dangerous_components.append(n)

        for receiver in app.findall("receiver"):
            n = attr(receiver, "name")
            result.receivers.append(n)
            for intent_filter in receiver.findall("intent-filter"):
                for action in intent_filter.findall("action"):
                    result.intent_filters.append({
                        "component": n,
                        "action": attr(action, "name"),
                    })

        for provider in app.findall("provider"):
            result.providers.append(attr(provider, "name"))

    # ── Obfuscation detection ──────────────────────────────────────────
    result.obfuscation_score, result.obfuscation_signals = _detect_obfuscation(result)

    logger.info(
        f"Manifest: pkg={result.package_name} "
        f"perms={len(result.permissions)} toxic={len(result.toxic_permissions)} "
        f"obfuscation={result.obfuscation_score}"
    )
    return result


def _detect_obfuscation(result: ManifestResult) -> Tuple[int, List[str]]:
    """Score manifest obfuscation signals (0-5)."""
    score = 0
    signals = []

    # Single-char package components
    pkg = result.package_name
    parts = pkg.split(".")
    short_parts = [p for p in parts if len(p) <= 2]
    if len(short_parts) >= 2:
        score += 1
        signals.append(f"Short package components: {short_parts}")

    # Component names that look obfuscated (e.g. a.b.c, com.a.B)
    all_components = result.activities + result.services + result.receivers
    obf_components = [
        c for c in all_components
        if re.match(r"^[\w.]*\.[a-zA-Z]{1,3}$", c) and len(c) < 20
    ]
    if obf_components:
        score += 1
        signals.append(f"Obfuscated component names: {obf_components[:3]}")

    if result.debuggable:
        score += 1
        signals.append("debuggable=true in production APK")

    if len(result.permissions) > 15:
        score += 1
        signals.append(f"Excessive permissions: {len(result.permissions)}")

    if result.uses_cleartext_traffic:
        score += 1
        signals.append("usesCleartextTraffic=true")

    return min(score, 5), signals
