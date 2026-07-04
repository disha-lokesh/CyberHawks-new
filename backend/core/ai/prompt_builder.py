"""
Garudatva v3 — Prompt Builder
Constructs system + user prompt from machine-verified JSON facts only.
Never passes raw strings or unverified data to the LLM.
System prompt enforces court language rules.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional, Tuple


SYSTEM_PROMPT = """You are a forensic analyst writing a court-admissible technical report for Indian law enforcement.

STRICT RULES — violations cause report rejection:
1. Use ONLY the verified facts provided in the JSON input. Do not invent, assume, or extrapolate.
2. FORBIDDEN WORDS: likely, probably, may, might, possibly, could, suggests, appears, seems, indicates, implies, generally, typically, usually, often, it is possible, we believe, it seems, perhaps, presumably, apparently, conceivably, allegedly.
3. Every claim must cite its source artifact (e.g. "DEX string analysis identified...", "YARA rule banking_trojans.yar matched...").
4. Write in formal third-person passive voice suitable for submission to a sessions court.
5. Use precise technical language. Spell out all acronyms on first use.
6. Structure: one paragraph per finding. No bullet points in narrative.
7. Do not state conclusions beyond what the data directly proves."""


def build_prompt(
    static=None,
    dynamic=None,
    cloud=None,
    graph=None,
    case=None,
) -> Tuple[str, str]:
    """
    Build (system_prompt, user_prompt) from verified analysis artifacts.
    All data is pre-validated machine output — no raw user strings.
    """
    facts: Dict[str, Any] = {}

    # Case metadata
    if case:
        facts["case"] = {
            "fir_number": case.fir_number,
            "district": case.district,
            "station": case.station,
            "reporting_officer": case.reporting_officer.badge_id,
        }

    # Static analysis facts
    if static:
        facts["static"] = {}

        if static.manifest:
            facts["static"]["package_name"] = static.manifest.package_name
            facts["static"]["target_sdk"] = static.manifest.target_sdk
            facts["static"]["debuggable"] = static.manifest.debuggable
            facts["static"]["toxic_permissions"] = static.manifest.toxic_permissions[:10]
            facts["static"]["dangerous_components"] = static.manifest.dangerous_components[:5]

        if static.risk_score:
            facts["static"]["risk_score"] = static.risk_score.total
            facts["static"]["risk_tier"] = static.risk_score.tier
            facts["static"]["ml_probability"] = static.risk_score.ml_probability
            if static.risk_score.shap_features:
                facts["static"]["top_shap_features"] = [
                    {"feature": f.feature_name, "shap": round(f.shap_value, 4)}
                    for f in static.risk_score.shap_features[:5]
                ]

        if static.yara:
            facts["static"]["yara_categories_hit"] = static.yara.categories_hit
            facts["static"]["yara_rules_matched"] = [
                m.rule_name for m in static.yara.matches[:10]
            ]

        if static.india_matches:
            facts["static"]["india_patterns"] = [
                {
                    "id": m.pattern_id,
                    "name": m.pattern_name,
                    "category": m.category,
                    "severity": m.severity,
                }
                for m in static.india_matches[:10]
            ]

        if static.cert:
            facts["static"]["certificate"] = {
                "subject": static.cert.subject[:100],
                "is_self_signed": static.cert.is_self_signed,
                "is_debug": static.cert.is_debug_cert,
                "is_expired": static.cert.is_expired,
                "sha256": static.cert.signing_cert_sha256[:32] if static.cert.signing_cert_sha256 else None,
            }

        if static.iocs:
            facts["static"]["extracted_ips"] = [
                ioc.value for ioc in static.iocs
                if ioc.ioc_type.value == "IP"
            ][:10]
            facts["static"]["extracted_urls"] = [
                ioc.value for ioc in static.iocs
                if ioc.ioc_type.value == "URL"
            ][:10]

    # Dynamic analysis facts
    if dynamic:
        facts["dynamic"] = {
            "c2_urls_count": len(dynamic.get("c2_urls", [])),
            "c2_urls_sample": dynamic.get("c2_urls", [])[:5],
            "crypto_operations": len(dynamic.get("crypto_artifacts", [])),
            "sms_intercepts": len(dynamic.get("sms_intercepts", [])),
            "ja4_hashes": dynamic.get("ja4_hashes", [])[:3],
        }
        if dynamic.get("crypto_artifacts"):
            facts["dynamic"]["crypto_algorithms"] = list(set(
                a.get("algorithm", "") for a in dynamic["crypto_artifacts"][:10]
            ))

    # Cloud C2 facts
    if cloud:
        facts["cloud"] = {
            "cloud_providers_contacted": [
                h["provider"] for h in cloud.get("cloud_hits", [])
            ][:5],
            "firebase_c2_detected": len(cloud.get("firebase_c2", [])) > 0,
            "tunnel_services": [
                t["service"] for t in cloud.get("tunnel_services", [])
            ][:3],
            "dga_domains_count": len(cloud.get("dga_domains", [])),
            "score_additions": cloud.get("score_additions", {}),
        }

    # Syndicate facts
    if graph and graph.get("syndicates"):
        facts["syndicates"] = graph["syndicates"][:5]

    user_prompt = f"""
Analyze the following verified forensic artifacts and write a court-admissible technical narrative.
Each finding must cite its specific source artifact.

VERIFIED FORENSIC ARTIFACTS (JSON):
{json.dumps(facts, indent=2, ensure_ascii=True, default=str)}

Write the forensic narrative now. Cover: application identity, behavioral indicators,
network communication findings, cryptographic artifact summary, India-specific fraud
pattern matches, and risk assessment conclusion. Do not use any forbidden words.
"""

    return SYSTEM_PROMPT, user_prompt
