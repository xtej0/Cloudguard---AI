from __future__ import annotations

from collections import deque
from typing import Any

from app.models.graph_schema import Graph, Node, NodeType
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


def _normalize_critical_types(critical_types: list[NodeType] | set[NodeType]) -> set[NodeType]:
    """Convert critical types collection into a set for fast type lookups."""
    return set(critical_types)


def _materialize_path(graph: Graph, node_ids: list[str]) -> list[Node]:
    """Convert node-id path into node objects; return [] when any node is missing."""
    node_path: list[Node] = []
    for node_id in node_ids:
        node = graph.get_node(node_id)
        if node is None:
            return []
        node_path.append(node)
    return node_path


def find_attack_paths(
    graph: Graph,
    start_node_id: str,
    critical_types: list[NodeType] | set[NodeType],
) -> list[list[Node]]:
    """Traverse graph with BFS and return all simple paths to critical node types."""
    start_node = graph.get_node(start_node_id)
    if start_node is None:
        return []

    critical_type_set = _normalize_critical_types(critical_types)
    if not critical_type_set:
        return []

    discovered_paths: list[list[Node]] = []
    queue: deque[list[str]] = deque([[start_node_id]])

    while queue:
        current_path = queue.popleft()
        current_node_id = current_path[-1]
        current_node = graph.get_node(current_node_id)
        if current_node is None:
            continue

        if current_node.node_type in critical_type_set and len(current_path) > 1:
            node_path = _materialize_path(graph, current_path)
            if node_path:
                discovered_paths.append(node_path)

        for edge in graph.get_outgoing_edges(current_node_id):
            next_node_id = edge.target
            if next_node_id in current_path:
                continue

            queue.append(current_path + [next_node_id])

    return discovered_paths


def shortest_attack_path(
    graph: Graph,
    start_node_id: str,
    critical_types: list[NodeType] | set[NodeType],
) -> list[Node]:
    """Return shortest BFS path from start node to any node of critical types."""
    start_node = graph.get_node(start_node_id)
    if start_node is None:
        return []

    critical_type_set = _normalize_critical_types(critical_types)
    if not critical_type_set:
        return []

    queue: deque[list[str]] = deque([[start_node_id]])
    visited: set[str] = {start_node_id}

    while queue:
        current_path = queue.popleft()
        current_node_id = current_path[-1]
        current_node = graph.get_node(current_node_id)
        if current_node is None:
            continue

        if current_node.node_type in critical_type_set and len(current_path) > 1:
            return _materialize_path(graph, current_path)

        for edge in graph.get_outgoing_edges(current_node_id):
            next_node_id = edge.target
            if next_node_id in visited:
                continue

            visited.add(next_node_id)
            queue.append(current_path + [next_node_id])

    return []