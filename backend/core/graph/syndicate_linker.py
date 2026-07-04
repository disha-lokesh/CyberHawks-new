"""
Garudatva v3 — Syndicate Linker
Runs cross-case linkage detection across all ingested analyses.
"""

from __future__ import annotations
from typing import Any, Dict, List
from core.graph.queries import (
    find_shared_c2, find_shared_certificate, cross_district_syndicate_query
)
from utils.logger import get_logger

logger = get_logger(__name__)


def find_syndicates(analysis_id: str) -> List[Dict]:
    """Find all syndicate links for this analysis."""
    syndicates = []

    shared_c2 = find_shared_c2(analysis_id)
    for rec in shared_c2:
        syndicates.append({
            "link_type": "SHARED_C2",
            "related_analysis": rec.get("related_analysis"),
            "related_case": rec.get("case_id"),
            "shared_ip": rec.get("shared_ip"),
            "confidence": "HIGH",
        })

    if syndicates:
        logger.info(
            f"Syndicates found for {analysis_id}: "
            f"{len(syndicates)} links"
        )
    return syndicates


def search_syndicates(
    district: str = None,
    ip: str = None,
    cert_sha1: str = None,
    jarm_hash: str = None,
) -> List[Dict]:
    """Search for syndicates matching any of the given criteria."""
    results = []

    if ip:
        try:
            from core.graph.neo4j_client import get_client
            client = get_client()
            records = client.run(
                """
                MATCH (a:APK)-[:CONNECTS_TO]->(ip:IPAddress {value: $ip})
                RETURN a.analysis_id AS analysis_id,
                       a.package_name AS package_name,
                       a.case_id AS case_id
                """,
                ip=ip,
            )
            for r in records:
                results.append({"link_type": "SHARED_IP", "ip": ip, **r})
        except Exception as e:
            logger.warning(f"IP syndicate query failed: {e}")

    if cert_sha1:
        from core.graph.queries import find_shared_certificate
        for r in find_shared_certificate(cert_sha1):
            results.append({"link_type": "SHARED_CERT", "cert_sha1": cert_sha1, **r})

    if jarm_hash:
        from core.graph.queries import find_jarm_group
        ips = find_jarm_group(jarm_hash)
        if ips:
            results.append({"link_type": "SHARED_JARM", "jarm_hash": jarm_hash, "matching_ips": ips})

    return results
