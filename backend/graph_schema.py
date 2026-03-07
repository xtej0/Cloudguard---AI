"""
Attack Graph Schema for CloudGuard AI
Defines the structure for modeling security relationships between cloud resources.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


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
    properties: Dict[str, Any] = field(default_factory=dict)
    
    def __hash__(self):
        return hash(self.id)
    
    def __eq__(self, other):
        if not isinstance(other, Node):
            return False
        return self.id == other.id
    
    def __repr__(self):
        return f"Node(id='{self.id}', type={self.node_type.value}, name='{self.name}')"


@dataclass
class Edge:
    """Represents an edge/relationship in the attack graph."""
    source: str
    target: str
    relationship_type: RelationshipType
    properties: Dict[str, Any] = field(default_factory=dict)
    
    def __repr__(self):
        return f"Edge({self.source} --[{self.relationship_type.value}]--> {self.target})"


class Graph:
    """Represents an attack graph containing nodes and edges."""
    
    def __init__(self):
        self.nodes: Dict[str, Node] = {}
        self.edges: List[Edge] = []
        self._adjacency_list: Dict[str, List[Edge]] = {}
        self._reverse_adjacency_list: Dict[str, List[Edge]] = {}
    
    def add_node(self, node: Node) -> None:
        self.nodes[node.id] = node
        if node.id not in self._adjacency_list:
            self._adjacency_list[node.id] = []
        if node.id not in self._reverse_adjacency_list:
            self._reverse_adjacency_list[node.id] = []
    
    def add_edge(self, edge: Edge) -> None:
        if edge.source not in self.nodes:
            raise ValueError(f"Source node '{edge.source}' does not exist in the graph")
        if edge.target not in self.nodes:
            raise ValueError(f"Target node '{edge.target}' does not exist in the graph")
        
        self.edges.append(edge)
        self._adjacency_list[edge.source].append(edge)
        self._reverse_adjacency_list[edge.target].append(edge)
    
    def get_node(self, node_id: str) -> Optional[Node]:
        return self.nodes.get(node_id)
    
    def get_outgoing_edges(self, node_id: str) -> List[Edge]:
        return self._adjacency_list.get(node_id, [])
    
    def get_incoming_edges(self, node_id: str) -> List[Edge]:
        return self._reverse_adjacency_list.get(node_id, [])
    
    def get_neighbors(self, node_id: str) -> List[str]:
        return [edge.target for edge in self.get_outgoing_edges(node_id)]
    
    def get_nodes_by_type(self, node_type: NodeType) -> List[Node]:
        return [node for node in self.nodes.values() if node.node_type == node_type]
    
    def get_edges_by_type(self, relationship_type: RelationshipType) -> List[Edge]:
        return [edge for edge in self.edges if edge.relationship_type == relationship_type]
    
    def remove_node(self, node_id: str) -> None:
        if node_id not in self.nodes:
            return
        self.edges = [
            edge for edge in self.edges 
            if edge.source != node_id and edge.target != node_id
        ]
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
    
    def __repr__(self):
        return f"Graph(nodes={len(self.nodes)}, edges={len(self.edges)})"


# =======================
# Test / Example Usage
# =======================
if __name__ == "__main__":
    # Create example nodes
    user1 = Node(id="u1", node_type=NodeType.USER, name="Alice")
    vm1 = Node(id="vm1", node_type=NodeType.VM, name="WebServer01")
    iam1 = Node(id="iam1", node_type=NodeType.IAM_ROLE, name="AdminRole")
    db1 = Node(id="db1", node_type=NodeType.DATABASE, name="CustomerDB")
    bucket1 = Node(id="b1", node_type=NodeType.BUCKET, name="LogsBucket")

    # Build graph
    g = Graph()
    for n in [user1, vm1, iam1, db1, bucket1]:
        g.add_node(n)

    # Add relationships
    g.add_edge(Edge(source="u1", target="vm1", relationship_type=RelationshipType.HAS_ACCESS))
    g.add_edge(Edge(source="vm1", target="db1", relationship_type=RelationshipType.CONNECTS_TO))
    g.add_edge(Edge(source="u1", target="iam1", relationship_type=RelationshipType.CAN_ASSUME_ROLE))
    g.add_edge(Edge(source="b1", target="vm1", relationship_type=RelationshipType.EXPOSED_TO))

    # Print nodes and edges
    print(g)
    for edge in g.edges:
        print(edge)