"""Attack graph schema models used by in-memory traversal utilities."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class NodeType(Enum):
    """Types of nodes in the attack graph."""

    USER = "User"
    VM = "VM"
    IAM_ROLE = "IAMRole"
    DATABASE = "Database"
    BUCKET = "Bucket"


class RelationshipType(Enum):
    """Types of relationships between nodes in the attack graph."""

    HAS_ACCESS = "HAS_ACCESS"
    CONNECTS_TO = "CONNECTS_TO"
    CAN_ASSUME_ROLE = "CAN_ASSUME_ROLE"
    EXPOSED_TO = "EXPOSED_TO"


@dataclass
class Node:
    """Represents a node in the attack graph."""

    id: str
    node_type: NodeType
    name: str
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class Edge:
    """Represents an edge in the attack graph."""

    source: str
    target: str
    relationship_type: RelationshipType
    properties: dict[str, Any] = field(default_factory=dict)


class Graph:
    """Represents an attack graph containing nodes and edges."""

    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self._adjacency_list: dict[str, list[Edge]] = {}
        self._reverse_adjacency_list: dict[str, list[Edge]] = {}

    def add_node(self, node: Node) -> None:
        self.nodes[node.id] = node
        self._adjacency_list.setdefault(node.id, [])
        self._reverse_adjacency_list.setdefault(node.id, [])

    def add_edge(self, edge: Edge) -> None:
        if edge.source not in self.nodes:
            raise ValueError(f"Source node '{edge.source}' does not exist in the graph")
        if edge.target not in self.nodes:
            raise ValueError(f"Target node '{edge.target}' does not exist in the graph")

        self.edges.append(edge)
        self._adjacency_list[edge.source].append(edge)
        self._reverse_adjacency_list[edge.target].append(edge)

    def get_node(self, node_id: str) -> Node | None:
        return self.nodes.get(node_id)

    def get_outgoing_edges(self, node_id: str) -> list[Edge]:
        return self._adjacency_list.get(node_id, [])

    def get_incoming_edges(self, node_id: str) -> list[Edge]:
        return self._reverse_adjacency_list.get(node_id, [])

    def get_neighbors(self, node_id: str) -> list[str]:
        return [edge.target for edge in self.get_outgoing_edges(node_id)]

    def get_nodes_by_type(self, node_type: NodeType) -> list[Node]:
        return [node for node in self.nodes.values() if node.node_type == node_type]

    def get_edges_by_type(self, relationship_type: RelationshipType) -> list[Edge]:
        return [edge for edge in self.edges if edge.relationship_type == relationship_type]

    def remove_node(self, node_id: str) -> None:
        if node_id not in self.nodes:
            return

        self.edges = [edge for edge in self.edges if edge.source != node_id and edge.target != node_id]
        del self.nodes[node_id]
        del self._adjacency_list[node_id]
        del self._reverse_adjacency_list[node_id]

        for edges in self._adjacency_list.values():
            edges[:] = [edge for edge in edges if edge.target != node_id]
        for edges in self._reverse_adjacency_list.values():
            edges[:] = [edge for edge in edges if edge.source != node_id]

    def clear(self) -> None:
        self.nodes.clear()
        self.edges.clear()
        self._adjacency_list.clear()
        self._reverse_adjacency_list.clear()

    def __len__(self) -> int:
        return len(self.nodes)
