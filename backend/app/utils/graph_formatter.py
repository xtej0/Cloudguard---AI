def make_node(node_id, label=None, node_type="unknown"):
    """Build a Cytoscape node payload."""
    return {
        "data": {
            "id": node_id,
            "label": label if label is not None else node_id,
            "type": node_type,
        }
    }


def make_edge(source, target, label="LINK"):
    """Build a Cytoscape edge payload."""
    return {
        "data": {
            "source": source,
            "target": target,
            "label": label,
        }
    }


def format_for_cytoscape(nodes, edges):
    cytoscape_nodes = []
    cytoscape_edges = []

    # Convert nodes
    for node in nodes:
        cytoscape_nodes.append(
            make_node(
                node_id=node["id"],
                label=node.get("label", node["id"]),
                node_type=node.get("type", "unknown"),
            )
        )

    # Convert edges
    for edge in edges:
        cytoscape_edges.append(
            make_edge(
                source=edge["source"],
                target=edge["target"],
                label=edge.get("relationship", "LINK"),
            )
        )

    return cytoscape_nodes, cytoscape_edges


def path_to_cytoscape_nodes_edges(nodes, relationships=None):
    """
    Convert a path (list of node names and list of relationship types) to Cytoscape format.
    If relationships is None or shorter, assume default relationships.
    """
    if relationships is None:
        relationships = []
    elif len(relationships) < len(nodes) - 1:
        relationships.extend(["UNKNOWN"] * (len(nodes) - 1 - len(relationships)))

    cytoscape_nodes = [make_node(node_id=node, label=node, node_type="asset") for node in nodes]
    cytoscape_edges = []
    for i in range(len(nodes) - 1):
        source = nodes[i]
        target = nodes[i + 1]
        label = relationships[i] if i < len(relationships) else "UNKNOWN"
        cytoscape_edges.append(make_edge(source=source, target=target, label=label))
    return cytoscape_nodes, cytoscape_edges