"""
Garudatva v3 — Neo4j Client
Connection management with 1GB heap limit for constrained hardware.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from neo4j import GraphDatabase, Driver
from neo4j.graph import Node as Neo4jNode, Relationship as Neo4jRelationship
from config import settings
from utils.logger import get_logger

logger = get_logger(__name__)

_driver: Optional[Driver] = None


def get_driver() -> Driver:
    global _driver
    if _driver is None:
        _driver = GraphDatabase.driver(
            settings.NEO4J_URI,
            auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
            max_connection_pool_size=10,
        )
        logger.info(f"Neo4j connected: {settings.NEO4J_URI}")
    return _driver


def close_driver() -> None:
    global _driver
    if _driver:
        _driver.close()
        _driver = None


class Neo4jClient:
    def run(self, query: str, **params) -> List[Dict]:
        driver = get_driver()
        with driver.session() as session:
            result = session.run(query, **params)
            return [dict(r) for r in result]

    def get_analysis_graph(self, analysis_id: str) -> Dict:
        """Return nodes + edges for a single analysis (for frontend vis)."""
        nodes_query = """
            MATCH (a:APK {analysis_id: $analysis_id})-[r]-(n)
            RETURN a, r, n LIMIT 200
        """
        try:
            records = self.run(nodes_query, analysis_id=analysis_id)
            nodes, edges = [], []
            seen_nodes, seen_edges = set(), set()
            for rec in records:
                for key in rec:
                    val = rec[key]
                    if isinstance(val, Neo4jNode):
                        if val.element_id not in seen_nodes:
                            seen_nodes.add(val.element_id)
                            nodes.append({
                                "id": val.element_id,
                                "labels": list(val.labels),
                                "properties": dict(val),
                            })
                    elif isinstance(val, Neo4jRelationship):
                        if val.element_id not in seen_edges:
                            seen_edges.add(val.element_id)
                            edges.append({
                                "id": val.element_id,
                                "source": val.start_node.element_id,
                                "target": val.end_node.element_id,
                                "type": val.type,
                                "properties": dict(val),
                            })
            return {"nodes": nodes, "edges": edges, "analysis_id": analysis_id}
        except Exception as e:
            logger.warning(f"Graph query failed: {e}")
            return {"nodes": [], "edges": [], "analysis_id": analysis_id, "error": str(e)}


def get_client() -> Neo4jClient:
    return Neo4jClient()
