"""
Garudatva v3 — Configuration Analysis
Goes beyond manifest_parser.py's permission/component extraction to parse
the actual referenced configuration resources: network_security_config.xml
(cleartext exceptions, certificate pinning bypass, user-trusted-CA
acceptance) and backup rules (android:fullBackupContent / dataExtractionRules).
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)

ANDROID_NS = "http://schemas.android.com/apk/res/android"


@dataclass
class ConfigAnalysisResult:
    network_security_config_present: bool = False
    cleartext_permitted_domains: List[str] = field(default_factory=list)
    cleartext_permitted_globally: bool = False
    trusts_user_added_cas: bool = False       # accepts CAs added via device settings — MITM risk
    certificate_pinning_present: bool = False
    backup_rules_present: bool = False
    backup_excludes_sensitive_data: bool = False
    anomalies: List[str] = field(default_factory=list)
    anomaly_score: float = 0.0
    errors: List[str] = field(default_factory=list)


def analyze_configuration(decoded_dir: Optional[Path], manifest_raw_xml: str) -> ConfigAnalysisResult:
    """
    decoded_dir: apktool's decoded output directory (contains res/xml/*.xml)
    manifest_raw_xml: the already-parsed AndroidManifest.xml text, used to
    find which config file (if any) the app references.
    """
    result = ConfigAnalysisResult()

    if not decoded_dir or not decoded_dir.exists():
        result.errors.append("No decoded resources available for configuration analysis")
        return result

    try:
        manifest_root = ET.fromstring(manifest_raw_xml) if manifest_raw_xml else None
    except ET.ParseError as e:
        result.errors.append(f"manifest re-parse for config analysis: {e}")
        manifest_root = None

    def attr(el, name):
        return el.get(f"{{{ANDROID_NS}}}{name}", el.get(name, "")) if el is not None else ""

    app_el = manifest_root.find("application") if manifest_root is not None else None
    nsc_ref = attr(app_el, "networkSecurityConfig") if app_el is not None else ""
    backup_ref = attr(app_el, "fullBackupContent") if app_el is not None else ""

    _analyze_network_security_config(decoded_dir, nsc_ref, result)
    _analyze_backup_rules(decoded_dir, backup_ref, result)

    result.anomaly_score = min(len(result.anomalies) * 1.5, 5.0)
    logger.info(
        f"Config analysis: nsc={result.network_security_config_present} "
        f"cleartext_domains={len(result.cleartext_permitted_domains)} "
        f"anomalies={len(result.anomalies)}"
    )
    return result


def _resolve_xml_resource(decoded_dir: Path, ref: str) -> Optional[Path]:
    """Resolve a manifest '@xml/foo' reference to res/xml/foo.xml."""
    if not ref.startswith("@xml/"):
        return None
    name = ref.split("/", 1)[1]
    candidate = decoded_dir / "res" / "xml" / f"{name}.xml"
    return candidate if candidate.exists() else None


def _analyze_network_security_config(decoded_dir: Path, nsc_ref: str, result: ConfigAnalysisResult) -> None:
    nsc_path = _resolve_xml_resource(decoded_dir, nsc_ref)
    if not nsc_path:
        # No explicit config — Android defaults (cleartext blocked on API 28+,
        # allowed below) apply; nothing further to inspect here.
        return

    result.network_security_config_present = True
    try:
        root = ET.fromstring(nsc_path.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:
        result.errors.append(f"network_security_config parse: {e}")
        return

    for base_config in root.findall("base-config"):
        if base_config.get("cleartextTrafficPermitted", "").lower() == "true":
            result.cleartext_permitted_globally = True
            result.anomalies.append("network_security_config permits cleartext traffic globally")
        for trust_anchor in base_config.iter("trust-anchors"):
            for cert in trust_anchor.findall("certificates"):
                if cert.get("src") == "user":
                    result.trusts_user_added_cas = True
                    result.anomalies.append(
                        "Trusts user-installed CA certificates — enables MITM via a "
                        "device-installed rogue certificate (common malware/spyware technique)"
                    )

    for domain_config in root.findall("domain-config"):
        cleartext = domain_config.get("cleartextTrafficPermitted", "").lower() == "true"
        for domain_el in domain_config.findall("domain"):
            domain = (domain_el.text or "").strip()
            if domain and cleartext:
                result.cleartext_permitted_domains.append(domain)
        if domain_config.find("pin-set") is not None:
            result.certificate_pinning_present = True

    if result.cleartext_permitted_domains:
        result.anomalies.append(
            f"Cleartext traffic explicitly permitted for {len(result.cleartext_permitted_domains)} "
            f"domain(s): {', '.join(result.cleartext_permitted_domains[:5])}"
        )


def _analyze_backup_rules(decoded_dir: Path, backup_ref: str, result: ConfigAnalysisResult) -> None:
    backup_path = _resolve_xml_resource(decoded_dir, backup_ref)
    if not backup_path:
        return

    result.backup_rules_present = True
    try:
        root = ET.fromstring(backup_path.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:
        result.errors.append(f"backup rules parse: {e}")
        return

    excludes = root.findall(".//exclude") + root.findall(".//exclude-rule")
    result.backup_excludes_sensitive_data = len(excludes) > 0
    if not excludes:
        result.anomalies.append(
            "No backup exclusion rules found — sensitive local data (tokens, cached "
            "credentials, private keys) may be included in Android's auto-backup and "
            "extractable from a cloud/adb backup"
        )
