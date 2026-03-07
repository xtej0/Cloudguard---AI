"""Traversal utilities for cloud attack graphs."""

from collections import deque
from typing import Deque, Iterable, List, Set

from backend.graph_schema import Edge, Graph, Node, NodeType, RelationshipType


def _normalize_critical_types(critical_types: Iterable[NodeType]) -> Set[NodeType]:
	"""Convert the input collection into a set for fast type lookups."""
	return set(critical_types)


def _materialize_path(graph: Graph, node_ids: List[str]) -> List[Node]:
	"""Convert a node-id path into a node path; return [] if any node is missing."""
	node_path: List[Node] = []
	for node_id in node_ids:
		node = graph.get_node(node_id)
		if node is None:
			return []
		node_path.append(node)
	return node_path


def find_attack_paths(
    graph: Graph,
    start_node_id: str,
    critical_types: Iterable[NodeType],
) -> List[List[Node]]:
    """
    Traverse the graph with BFS and return all simple paths from start_node_id
    to nodes whose type is in critical_types.
    """
    start_node = graph.get_node(start_node_id)
    if start_node is None:
        return []

    critical_type_set = _normalize_critical_types(critical_types)
    if not critical_type_set:
        return []

    discovered_paths: List[List[Node]] = []
    queue: Deque[List[str]] = deque([[start_node_id]])

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

            # Prevent cycles by avoiding nodes already in the current path.
            if next_node_id in current_path:
                continue

            queue.append(current_path + [next_node_id])

    return discovered_paths


def shortest_attack_path(
    graph: Graph,
    start_node_id: str,
    critical_types: Iterable[NodeType],
) -> List[Node]:
    """
    Return the shortest BFS path from start_node_id to any node in critical_types.
    Returns an empty list if no path exists.
    """
    start_node = graph.get_node(start_node_id)
    if start_node is None:
        return []

    critical_type_set = _normalize_critical_types(critical_types)
    if not critical_type_set:
        return []

    queue: Deque[List[str]] = deque([[start_node_id]])
    visited: Set[str] = {start_node_id}

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


def _format_path(path: List[Node]) -> str:
    """Render a path as a readable chain of node names and types."""
    return " -> ".join(f"{node.name}({node.node_type.value})" for node in path)


if __name__ == "__main__":
    # Create nodes: User, VM, IAM Role, Database, Bucket
    user = Node(id="u1", node_type=NodeType.USER, name="Alice")
    vm = Node(id="vm1", node_type=NodeType.VM, name="AppServer01")
    iam_role = Node(id="iam1", node_type=NodeType.IAM_ROLE, name="OpsRole")
    database = Node(id="db1", node_type=NodeType.DATABASE, name="CustomerDB")
    bucket = Node(id="b1", node_type=NodeType.BUCKET, name="BackupsBucket")

    graph = Graph()
    for node in [user, vm, iam_role, database, bucket]:
        graph.add_node(node)

    # Build sample edges: HAS_ACCESS, CONNECTS_TO, CAN_ASSUME_ROLE, EXPOSED_TO
    graph.add_edge(Edge("u1", "vm1", RelationshipType.HAS_ACCESS))
    graph.add_edge(Edge("vm1", "db1", RelationshipType.CONNECTS_TO))
    graph.add_edge(Edge("u1", "iam1", RelationshipType.CAN_ASSUME_ROLE))
    graph.add_edge(Edge("iam1", "b1", RelationshipType.EXPOSED_TO))

    critical_assets = {NodeType.DATABASE, NodeType.BUCKET}
    all_paths = find_attack_paths(graph, start_node_id="u1", critical_types=critical_assets)

    print("All attack paths from User to critical assets (Database & Bucket):")
    if not all_paths:
        print("No attack paths found.")
    for idx, path in enumerate(all_paths, start=1):
        print(f"{idx}. {_format_path(path)}")

    shortest_to_database = shortest_attack_path(
        graph,
        start_node_id="u1",
        critical_types={NodeType.DATABASE},
    )

    print("\nShortest attack path from User to Database:")
    if shortest_to_database:
        print(_format_path(shortest_to_database))
    else:
        print("No path to Database found.")
