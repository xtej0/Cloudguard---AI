import pytest

from backend.attack_graph import find_attack_paths, shortest_attack_path
from backend.graph_schema import Edge, Graph, Node, NodeType, RelationshipType


@pytest.fixture
def sample_graph() -> Graph:
	graph = Graph()

	user = Node(id="u1", node_type=NodeType.USER, name="User")
	vm = Node(id="vm1", node_type=NodeType.VM, name="VM")
	iam_role = Node(id="iam1", node_type=NodeType.IAM_ROLE, name="IAM Role")
	database = Node(id="db1", node_type=NodeType.DATABASE, name="Database")
	bucket = Node(id="b1", node_type=NodeType.BUCKET, name="Bucket")

	for node in [user, vm, iam_role, database, bucket]:
		graph.add_node(node)

	graph.add_edge(Edge(source="u1", target="vm1", relationship_type=RelationshipType.HAS_ACCESS))
	graph.add_edge(Edge(source="vm1", target="db1", relationship_type=RelationshipType.CONNECTS_TO))
	graph.add_edge(Edge(source="u1", target="iam1", relationship_type=RelationshipType.CAN_ASSUME_ROLE))
	graph.add_edge(Edge(source="iam1", target="b1", relationship_type=RelationshipType.EXPOSED_TO))

	return graph


def test_find_attack_paths(sample_graph: Graph) -> None:
	critical_types = {NodeType.DATABASE, NodeType.BUCKET}

	paths = find_attack_paths(sample_graph, start_node_id="u1", critical_types=critical_types)

	path_ids = {tuple(node.id for node in path) for path in paths}
	expected_paths = {
		("u1", "vm1", "db1"),
		("u1", "iam1", "b1"),
	}

	assert path_ids == expected_paths
	assert len(paths) == 2


def test_shortest_attack_path(sample_graph: Graph) -> None:
	path = shortest_attack_path(
		sample_graph,
		start_node_id="u1",
		critical_types={NodeType.DATABASE},
	)

	assert [node.id for node in path] == ["u1", "vm1", "db1"]


def test_no_paths_for_nonexistent_node(sample_graph: Graph) -> None:
	critical_types = {NodeType.DATABASE, NodeType.BUCKET}

	assert (
		find_attack_paths(sample_graph, start_node_id="does-not-exist", critical_types=critical_types)
		== []
	)
	assert (
		shortest_attack_path(
			sample_graph,
			start_node_id="does-not-exist",
			critical_types=critical_types,
		)
		== []
	)


def test_no_paths_for_empty_critical_types(sample_graph: Graph) -> None:
	assert find_attack_paths(sample_graph, start_node_id="u1", critical_types=[]) == []
	assert shortest_attack_path(sample_graph, start_node_id="u1", critical_types=[]) == []
