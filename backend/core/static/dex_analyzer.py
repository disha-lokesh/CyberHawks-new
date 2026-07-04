"""
Garudatva v3 — DEX Analyzer
Extracts strings, class names, and API calls from .dex files.
Uses androguard for deep analysis; falls back to raw string extraction.
"""

from __future__ import annotations

import re
import struct
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Set

from utils.logger import get_logger

logger = get_logger(__name__)

# API calls that are inherently suspicious
SUSPICIOUS_APIS: Set[str] = {
    # Reflection
    "Ljava/lang/reflect/Method;->invoke",
    "Ljava/lang/Class;->forName",
    # Dynamic code loading
    "Ldalvik/system/DexClassLoader;",
    "Ldalvik/system/PathClassLoader;",
    "Ljava/net/URLClassLoader;",
    # Native execution
    "Ljava/lang/Runtime;->exec",
    "Ljava/lang/ProcessBuilder;",
    # Crypto
    "Ljavax/crypto/Cipher;->getInstance",
    "Ljavax/crypto/spec/SecretKeySpec;",
    "Ljavax/crypto/spec/IvParameterSpec;",
    # SMS
    "Landroid/telephony/SmsManager;->sendTextMessage",
    "Lcom/google/android/gms/auth/api/phone/SmsRetriever;",
    # Device admin
    "Landroid/app/admin/DevicePolicyManager;",
    # Accessibility
    "Landroid/accessibilityservice/AccessibilityService;",
    # Overlay
    "Landroid/view/WindowManager;->addView",
    # Exfil helpers
    "Lorg/json/JSONObject;->put",
    "Ljava/util/Base64;->encode",
}

# Patterns that strongly suggest obfuscation
OBFUSCATION_PATTERNS = [
    r"^[a-z]{1,3}/[a-z]{1,3}/[A-Z]{1,3}$",         # Proguard short names
    r"^[a-z]/[a-z]/[a-z]$",                           # Extreme obfuscation
]


class DEXAnalysisResult:
    def __init__(self):
        self.all_strings: List[str] = []
        self.urls: List[str] = []
        self.ips: List[str] = []
        self.class_names: List[str] = []
        self.method_names: List[str] = []
        self.suspicious_apis: List[str] = []
        self.crypto_classes: List[str] = []
        self.network_classes: List[str] = []
        self.reflection_used: bool = False
        self.dynamic_loading: bool = False
        self.obfuscation_level: int = 0       # 0-3
        self.obfuscation_evidence: List[str] = []
        self.phone_numbers: List[str] = []
        self.encoded_payloads: List[str] = []
        self.errors: List[str] = []


def analyze_dex(dex_files: List[Path]) -> DEXAnalysisResult:
    """
    Analyse all DEX files in the APK.
    Tries androguard first, falls back to raw binary string extraction.
    """
    result = DEXAnalysisResult()
    if not dex_files:
        result.errors.append("No DEX files provided")
        return result

    # Try androguard
    try:
        result = _analyze_with_androguard(dex_files, result)
    except Exception as e:
        logger.warning(f"androguard failed: {e} — falling back to raw strings")
        result.errors.append(f"androguard: {e}")
        result = _analyze_raw_strings(dex_files, result)

    # Post-processing
    _extract_network_artifacts(result)
    _detect_obfuscation(result)

    logger.info(
        f"DEX: {len(result.all_strings)} strings, {len(result.urls)} URLs, "
        f"obfuscation={result.obfuscation_level}"
    )
    return result


def _analyze_with_androguard(dex_files: List[Path], result: DEXAnalysisResult) -> DEXAnalysisResult:
    # androguard >= 4.0 moved DEX parsing to androguard.core.dex.DEX
    # (the old androguard.core.bytecodes.dvm.DalvikVMFormat path no longer exists).
    from androguard.core.dex import DEX

    for dex_path in dex_files:
        try:
            dex = DEX(dex_path.read_bytes())
            for cls in dex.get_classes():
                class_name = cls.get_name()
                result.class_names.append(class_name)

                for method in cls.get_methods():
                    result.method_names.append(method.get_name())
                    for instr in method.get_instructions():
                        s = str(instr.get_output())
                        result.all_strings.append(s)
                        # Check suspicious API calls
                        for api in SUSPICIOUS_APIS:
                            if api in s:
                                result.suspicious_apis.append(api)

            # String section
            for st in dex.get_strings():
                result.all_strings.append(st)

        except Exception as e:
            logger.warning(f"androguard error on {dex_path.name}: {e}")
            result.errors.append(str(e))

    result.reflection_used = any(
        "forName" in s or "invoke" in s for s in result.suspicious_apis
    )
    result.dynamic_loading = any(
        "DexClassLoader" in s or "PathClassLoader" in s
        for s in result.suspicious_apis
    )
    return result


def _analyze_raw_strings(dex_files: List[Path], result: DEXAnalysisResult) -> DEXAnalysisResult:
    """Fallback: extract printable strings via strings(1) or regex."""
    for dex_path in dex_files:
        try:
            # Use system strings command if available
            proc = subprocess.run(
                ["strings", "-n", "6", str(dex_path)],
                capture_output=True, text=True, timeout=30,
            )
            if proc.returncode == 0:
                result.all_strings.extend(proc.stdout.splitlines())
                continue
        except Exception:
            pass

        # Manual extraction
        try:
            data = dex_path.read_bytes()
            # Extract ASCII strings >= 6 chars
            pattern = re.compile(rb"[\x20-\x7e]{6,}")
            for m in pattern.finditer(data):
                try:
                    result.all_strings.append(m.group().decode("ascii"))
                except Exception:
                    pass
        except Exception as e:
            result.errors.append(f"raw string extract {dex_path.name}: {e}")

    return result


def _extract_network_artifacts(result: DEXAnalysisResult) -> None:
    """Extract URLs and IPs from string corpus."""
    url_pattern = re.compile(
        r"https?://[^\s\"'<>{}\[\]\\]{4,200}", re.IGNORECASE
    )
    ip_pattern = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    )
    phone_pattern = re.compile(
        r"(?:\+91|0)?[6-9]\d{9}"
    )
    # Base64 blobs likely to be payloads (>= 100 chars of base64)
    b64_pattern = re.compile(
        r"[A-Za-z0-9+/]{100,}={0,2}"
    )

    corpus = "\n".join(result.all_strings)
    result.urls = list(set(url_pattern.findall(corpus)))
    result.ips = list(set(ip_pattern.findall(corpus)))
    result.phone_numbers = list(set(phone_pattern.findall(corpus)))
    result.encoded_payloads = b64_pattern.findall(corpus)[:20]


def _detect_obfuscation(result: DEXAnalysisResult) -> None:
    """Score DEX obfuscation level 0-3."""
    score = 0
    evidence = []

    # Check for very short class names
    obf_classes = [
        c for c in result.class_names
        if re.match(r"^L[a-z]/[a-z]/[a-zA-Z]{1,2};$", c)
    ]
    if len(obf_classes) > 5:
        score += 1
        evidence.append(f"{len(obf_classes)} heavily obfuscated class names")

    if result.reflection_used:
        score += 1
        evidence.append("Reflection API usage detected")

    if result.dynamic_loading:
        score += 1
        evidence.append("Dynamic DEX loading (DexClassLoader/PathClassLoader)")

    if len(result.encoded_payloads) > 3:
        score += 1
        evidence.append(f"{len(result.encoded_payloads)} large Base64 blobs")

    result.obfuscation_level = min(score, 3)
    result.obfuscation_evidence = evidence
