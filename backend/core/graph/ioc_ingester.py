"""
Garudatva v3 — IOC Ingester
Pushes all analysis artifacts to Neo4j.
Uses MERGE (not CREATE) to handle duplicates across cases.
"""

from __future__ import annotations

from typing import Any, Dict, List

from core.graph.neo4j_client import get_client
from models.ioc import IOC, IOCType
from utils.logger import get_logger

logger = get_logger(__name__)


def ingest_iocs(analysis_id: str, case_id: str, iocs: List[IOC]) -> None:
    """Push all IOCs from one analysis into Neo4j."""
    client = get_client()

    # Create APK node
    client.run(
        """
        MERGE (a:APK {analysis_id: $analysis_id})
        SET a.case_id = $case_id,
            a.ingested_at = datetime()
        """,
        analysis_id=analysis_id,
        case_id=case_id,
    )

    for ioc in iocs:
        try:
            _ingest_single(client, analysis_id, case_id, ioc)
        except Exception as e:
            logger.warning(f"IOC ingest failed for {ioc.value}: {e}")

    logger.info(f"Ingested {len(iocs)} IOCs for analysis {analysis_id}")


def _ingest_single(client, analysis_id: str, case_id: str, ioc: IOC) -> None:
    if ioc.ioc_type == IOCType.IP:
        client.run(
            """
            MERGE (ip:IPAddress {value: $value})
            SET ip.asn = $asn, ip.cloud_provider = $cloud
            WITH ip
            MATCH (a:APK {analysis_id: $analysis_id})
            MERGE (a)-[:CONNECTS_TO]->(ip)
            """,
            value=ioc.value,
            asn=ioc.asn or "",
            cloud=ioc.cloud_provider or "",
            analysis_id=analysis_id,
        )

    elif ioc.ioc_type in (IOCType.URL, IOCType.DOMAIN):
        client.run(
            """
            MERGE (d:Domain {value: $value})
            SET d.is_dga = $is_dga, d.is_tunnel = $is_tunnel
            WITH d
            MATCH (a:APK {analysis_id: $analysis_id})
            MERGE (a)-[:RESOLVES]->(d)
            """,
            value=ioc.value,
            is_dga=ioc.is_dga,
            is_tunnel=ioc.is_tunnel_service,
            analysis_id=analysis_id,
        )

    elif ioc.ioc_type == IOCType.CERTIFICATE_SHA1:
        client.run(
            """
            MERGE (c:Certificate {sha1: $value})
            SET c.context = $context
            WITH c
            MATCH (a:APK {analysis_id: $analysis_id})
            MERGE (a)-[:SIGNED_BY]->(c)
            """,
            value=ioc.value,
            context=ioc.context or "",
            analysis_id=analysis_id,
        )

    elif ioc.ioc_type == IOCType.PACKAGE_NAME:
        client.run(
            """
            MERGE (a:APK {analysis_id: $analysis_id})
            SET a.package_name = $value
            """,
            analysis_id=analysis_id,
            value=ioc.value,
        )

    elif ioc.ioc_type == IOCType.JARM_HASH:
        client.run(
            """
            MERGE (j:JARMHash {value: $value})
            WITH j
            MATCH (ip:IPAddress {value: $ip})
            MERGE (ip)-[:SHARES_JARM]->(j)
            """,
            value=ioc.value,
            ip=ioc.context or "",
        )

    elif ioc.ioc_type == IOCType.PHONE_NUMBER:
        client.run(
            """
            MERGE (p:PhoneNumber {value: $value})
            WITH p
            MATCH (a:APK {analysis_id: $analysis_id})
            MERGE (a)-[:CONTACTS]->(p)
            """,
            value=ioc.value,
            analysis_id=analysis_id,
        )
