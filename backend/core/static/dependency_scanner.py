"""
Garudatva v3 — Dependency / Third-Party SDK Scanner
Software-composition-analysis pass: identifies bundled third-party SDKs
from the package structure of extracted DEX class names. Real, documented
package namespaces only — this does not attempt to fingerprint specific
malware families by package name (YARA + india_patterns already cover
behavioral signatures; a package-prefix guess at "known malicious SDK"
would be exactly the kind of low-confidence claim this project's
reconciliation spec warns against).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from utils.logger import get_logger

logger = get_logger(__name__)

# Real, well-documented third-party SDK package namespaces.
AD_SDK_PREFIXES: Dict[str, str] = {
    "com.google.android.gms.ads": "Google AdMob",
    "com.facebook.ads":           "Meta Audience Network",
    "com.unity3d.ads":            "Unity Ads",
    "com.applovin":               "AppLovin",
    "com.vungle":                 "Vungle",
    "com.chartboost":             "Chartboost",
    "com.ironsource":             "ironSource",
    "com.mopub":                  "MoPub",
    "com.mbridge.msdk":           "Mintegral",
}
ANALYTICS_SDK_PREFIXES: Dict[str, str] = {
    "com.google.firebase.analytics": "Firebase Analytics",
    "com.flurry.android":            "Flurry Analytics",
    "com.mixpanel.android":          "Mixpanel",
    "com.crashlytics":               "Crashlytics",
    "com.bugsnag":                   "Bugsnag",
}
# Bundling 3+ distinct ad-mediation SDKs in one app is unusual for a
# legitimate single-purpose app and is a common pattern in adware /
# fake-utility / fake-loan apps that monetize aggressively.
MULTI_AD_SDK_THRESHOLD = 3


@dataclass
class DependencyScanResult:
    ad_sdks_detected: List[str] = field(default_factory=list)
    analytics_sdks_detected: List[str] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)
    anomaly_score: float = 0.0


def scan_dependencies(class_names: List[str]) -> DependencyScanResult:
    """class_names: fully-qualified class names extracted from the DEX (dex_analyzer.py)."""
    result = DependencyScanResult()
    ad_hits: Dict[str, str] = {}
    analytics_hits: Dict[str, str] = {}

    for cls in class_names:
        # DEX class names are smali-internal form, e.g. "Lcom/google/android/gms/ads/AdView;"
        # — a substring check (not startswith/anchored) handles the leading
        # "L" and trailing ";" without needing to strip them first.
        for prefix, name in AD_SDK_PREFIXES.items():
            if prefix.replace(".", "/") in cls:
                ad_hits[prefix] = name
        for prefix, name in ANALYTICS_SDK_PREFIXES.items():
            if prefix.replace(".", "/") in cls:
                analytics_hits[prefix] = name

    result.ad_sdks_detected = sorted(ad_hits.values())
    result.analytics_sdks_detected = sorted(analytics_hits.values())

    if len(ad_hits) >= MULTI_AD_SDK_THRESHOLD:
        result.anomalies.append(
            f"{len(ad_hits)} distinct ad-mediation SDKs bundled ({', '.join(result.ad_sdks_detected)}) "
            f"— unusual density for a single-purpose app, consistent with aggressive-monetization adware"
        )

    result.anomaly_score = min(len(result.anomalies) * 2.0, 5.0)
    logger.info(
        f"Dependency scan: {len(result.ad_sdks_detected)} ad SDKs, "
        f"{len(result.analytics_sdks_detected)} analytics SDKs"
    )
    return result
