"""
Garudatva v3 — Campaign Linker
When JARM match found, queries Neo4j for all other IPs
sharing the same JARM hash and maps the full C2 campaign.
"""

from __future__ import annotations

from typing import Dict, List

from utils.logger import get_logger

logger = get_logger(__name__)


def link_campaign(jarm_hash: str, matched_ips: List[str]) -> Dict:
    """
    Given a known-malicious JARM hash, find all related infrastructure
    in the Neo4j graph and return a campaign summary.
    """
    from core.jarm.jarm_database import lookup_jarm
    from core.graph.queries import find_jarm_group

    db_entry = lookup_jarm(jarm_hash)
    neo4j_group = []

    try:
        neo4j_group = find_jarm_group(jarm_hash)
    except Exception as e:
        logger.warning(f"Neo4j JARM group query failed: {e}")

    campaign = {
        "jarm_hash": jarm_hash,
        "known_malware_family": db_entry.get("family") if db_entry else None,
        "known_campaign": db_entry.get("campaign") if db_entry else None,
        "known_since": db_entry.get("first_seen") if db_entry else None,
        "matched_ips": matched_ips,
        "related_ips_in_graph": neo4j_group,
        "total_related": len(matched_ips) + len(neo4j_group),
        "is_known_malicious": db_entry is not None,
    }

    logger.info(
        f"Campaign linked: jarm={jarm_hash[:16]}… "
        f"family={campaign['known_malware_family']} "
        f"related={campaign['total_related']} IPs"
    )
    return campaign
