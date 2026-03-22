from __future__ import annotations

from typing import Any

from app.neo4j_config import driver


def get_asset_existence(start: str, target: str) -> tuple[bool, bool]:
    """Return whether start and target assets exist in the graph."""
    query = """
    OPTIONAL MATCH (s {name:$start})
    WITH count(s) > 0 AS start_exists
    OPTIONAL MATCH (t {name:$target})
    RETURN start_exists, count(t) > 0 AS target_exists
    """

    with driver.session() as session:
        record = session.run(query, start=start, target=target).single()

    if not record:
        return False, False

    return bool(record["start_exists"]), bool(record["target_exists"])


def get_shortest_attack_path(start: str, target: str) -> dict[str, Any] | None:
    """Return shortest attack path data between two assets or None when no path exists."""
    query = """
    MATCH p = shortestPath((a {name:$start})-[*]->(b {name:$target}))
    RETURN nodes(p) as nodes, relationships(p) as rels
    """

    with driver.session() as session:
        record = session.run(query, start=start, target=target).single()

    if not record:
        return None

    nodes = record.get("nodes") if hasattr(record, "get") else record["nodes"]
    if not nodes:
        return None

    relationships = record.get("rels") if hasattr(record, "get") else record["rels"]

    return {
        "nodes": [node["name"] for node in nodes],
        "relationships": [rel.type for rel in (relationships or [])],
        "path_length": len(nodes),
    }


def get_all_attack_paths(start: str, target: str) -> list[dict[str, Any]]:
    """Return all directed attack paths between two assets."""
    query = """
    MATCH p = (a {name:$start})-[*]->(b {name:$target})
    RETURN nodes(p) AS nodes, relationships(p) AS rels
    """

    with driver.session() as session:
        results = session.run(query, start=start, target=target)
        paths: list[dict[str, Any]] = []
        for record in results:
            nodes = [node["name"] for node in record["nodes"]]
            relationships = [rel.type for rel in record["rels"]]
            paths.append({"nodes": nodes, "relationships": relationships})

    return paths