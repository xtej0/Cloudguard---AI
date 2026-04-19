from __future__ import annotations

from collections import deque
from typing import Any

from app.builders.response_builder import build_attack_path_response, build_attack_risk_summary_response
from app.models.graph_schema import Graph, Node, NodeType
from app.neo4j_config import driver
from app.services.summary_service import utc_now_iso
from app.utils.graph_formatter import make_edge, make_node


def generate_attack_path(
    start: str = "Internet",
    target: str = "Database Server",
    start_exists: bool | None = None,
    target_exists: bool | None = None,
) -> dict[str, Any]:
    """Return a short linear attack path graph."""
    nodes = [start, "Web Server VM", "Application Server VM", target]
    relationships = ["EXPOSED_TO", "CONNECTS_TO", "CONNECTS_TO"]
    return build_attack_path_response(
        nodes,
        relationships,
        start=start,
        target=target,
        start_exists=start_exists,
        target_exists=target_exists,
    )


def generate_full_graph(
    start: str = "Internet",
    target: str = "Database Server",
    start_exists: bool | None = None,
    target_exists: bool | None = None,
) -> dict[str, Any]:
    """Return the full infrastructure graph with all major connections."""
    graph_nodes = [
        make_node(node_id="Internet", label="Internet", node_type="Internet"),
        make_node(node_id="Web Server VM", label="Web Server VM", node_type="VM"),
        make_node(node_id="Application Server VM", label="Application Server VM", node_type="VM"),
        make_node(node_id="Database Server", label="Database Server", node_type="Database"),
        make_node(node_id="Storage Bucket", label="Storage Bucket", node_type="Bucket"),
        make_node(node_id="IAM Role", label="IAM Role", node_type="IAMRole"),
        make_node(node_id="User", label="User", node_type="User"),
    ]

    graph_edges = [
        make_edge(source="Internet", target="Web Server VM", label="EXPOSED_TO"),
        make_edge(source="Web Server VM", target="Application Server VM", label="CONNECTS_TO"),
        make_edge(source="Application Server VM", target="Database Server", label="CONNECTS_TO"),
        make_edge(source="Web Server VM", target="Storage Bucket", label="CONNECTS_TO"),
        make_edge(source="Application Server VM", target="IAM Role", label="CAN_ASSUME_ROLE"),
        make_edge(source="IAM Role", target="Database Server", label="HAS_ACCESS"),
        make_edge(source="User", target="IAM Role", label="HAS_ACCESS"),
        make_edge(source="Database Server", target="Storage Bucket", label="STORES_DATA_IN"),
    ]

    return build_attack_risk_summary_response(
        graph={"nodes": graph_nodes, "edges": graph_edges},
        risk_top_assets=[],
        summary={
            "start_asset": start,
            "target_asset": target,
            "total_nodes": len(graph_nodes),
            "total_edges": len(graph_edges),
            "total_paths": 1,
            "path_length": 4,
            "message": "Full infrastructure graph loaded",
            "generated_at": utc_now_iso(),
        },
        prediction=[],
        mitigations=[],
    )


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
    MATCH p = shortestPath((a {name:$start})-[*..5]->(b {name:$target}))
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