"""
Garudatva v3 — Cypher Query Library
All parameterized queries for syndicate detection, JARM grouping,
certificate clustering. No string interpolation — injection-safe.
"""

from __future__ import annotations
from typing import Any, Dict, List
from core.graph.neo4j_client import get_client
from utils.logger import get_logger

logger = get_logger(__name__)


def find_jarm_group(jarm_hash: str) -> List[str]:
    """Return all IPs sharing this JARM fingerprint across all cases."""
    try:
        client = get_client()
        records = client.run(
            """
            MATCH (j:JARMHash {value: $jarm_hash})<-[:SHARES_JARM]-(ip:IPAddress)
            RETURN ip.value AS ip
            """,
            jarm_hash=jarm_hash,
        )
        return [r["ip"] for r in records]
    except Exception as e:
        logger.warning(f"JARM group query failed: {e}")
        return []


def find_shared_c2(analysis_id: str) -> List[Dict]:
    """Find other cases sharing the same C2 infrastructure as this analysis."""
    try:
        client = get_client()
        return client.run(
            """
            MATCH (a1:APK {analysis_id: $analysis_id})-[:CONNECTS_TO]->(ip:IPAddress)
                  <-[:CONNECTS_TO]-(a2:APK)
            WHERE a2.analysis_id <> $analysis_id
            RETURN DISTINCT
                a2.analysis_id AS related_analysis,
                a2.package_name AS package_name,
                a2.case_id AS case_id,
                ip.value AS shared_ip
            LIMIT 50
            """,
            analysis_id=analysis_id,
        )
    except Exception as e:
        logger.warning(f"Shared C2 query failed: {e}")
        return []


def find_shared_certificate(cert_sha1: str) -> List[Dict]:
    """Find all APKs signed with the same certificate."""
    try:
        client = get_client()
        return client.run(
            """
            MATCH (c:Certificate {sha1: $sha1})<-[:SIGNED_BY]-(a:APK)
            RETURN a.analysis_id AS analysis_id,
                   a.package_name AS package_name,
                   a.case_id AS case_id
            """,
            sha1=cert_sha1,
        )
    except Exception as e:
        logger.warning(f"Certificate cluster query failed: {e}")
        return []


def cross_district_syndicate_query() -> List[Dict]:
    """
    Find APKs from different districts sharing the same C2 infrastructure.
    The primary cross-district syndicate detection query.
    """
    try:
        client = get_client()
        return client.run(
            """
            MATCH (a1:APK)-[:CONNECTS_TO]->(ip:IPAddress)<-[:CONNECTS_TO]-(a2:APK)
            WHERE a1.case_id <> a2.case_id
            WITH a1, a2, collect(ip.value) AS shared_ips
            RETURN
                a1.package_name AS pkg1,
                a2.package_name AS pkg2,
                a1.case_id AS case1,
                a2.case_id AS case2,
                shared_ips,
                size(shared_ips) AS shared_count
            ORDER BY shared_count DESC
            LIMIT 100
            """,
        )
    except Exception as e:
        logger.warning(f"Cross-district query failed: {e}")
        return []
