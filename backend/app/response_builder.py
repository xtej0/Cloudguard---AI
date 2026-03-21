from datetime import datetime, timezone
from .utils.graph_formatter import path_to_cytoscape_nodes_edges


def build_attack_path_response(nodes, relationships):
    cytoscape_nodes, cytoscape_edges = path_to_cytoscape_nodes_edges(nodes, relationships)
    return {
        "version": "v1",
        "graph": {
            "nodes": cytoscape_nodes,
            "edges": cytoscape_edges
        },
        "risk": {
            "top_assets": []
        },
        "prediction": {
            "next_targets": []
        },
        "summary": {
            "start_asset": nodes[0] if nodes else None,
            "target_asset": nodes[-1] if nodes else None,
            "path_length": len(nodes),
            "overall_risk_level": "UNKNOWN",
            "highest_risk": None,
            "generated_at": datetime.now(timezone.utc).isoformat()
        },
        "mitigations": []
    }


def build_all_paths_response(paths):
    all_nodes = set()
    all_edges = set()

    # Determine start and target from first path if available
    start_asset = None
    target_asset = None
    path_length = 0

    if paths:
        first = paths[0]
        if isinstance(first, dict):
            first_nodes = first.get("nodes", [])
        else:
            first_nodes = first

        if isinstance(first_nodes, list) and first_nodes:
            start_asset = first_nodes[0]
            target_asset = first_nodes[-1]
            path_length = len(first_nodes)

    for path in paths:
        if isinstance(path, dict):
            nodes = path.get("nodes", []) or []
            relationships = path.get("relationships", []) or []
        else:
            nodes = path or []
            relationships = []

        if not isinstance(nodes, list):
            continue

        for node in nodes:
            all_nodes.add(node)

        for i in range(len(nodes) - 1):
            source = nodes[i]
            target = nodes[i + 1]
            relationship = relationships[i] if i < len(relationships) else None
            edge_label = relationship if relationship is not None else "UNKNOWN"
            all_edges.add((source, target, edge_label))

    cytoscape_nodes = [{"data": {"id": n, "label": n, "type": "asset"}} for n in all_nodes]
    cytoscape_edges = [{"data": {"source": s, "target": t, "label": l}} for s, t, l in all_edges]

    return {
        "version": "v1",
        "graph": {
            "nodes": cytoscape_nodes,
            "edges": cytoscape_edges
        },
        "risk": {
            "top_assets": []
        },
        "prediction": {
            "next_targets": []
        },
        "summary": {
            "start_asset": start_asset,
            "target_asset": target_asset,
            "total_paths": len(paths),
            "path_length": path_length,
            "overall_risk_level": "UNKNOWN",
            "highest_risk": None,
            "generated_at": datetime.now(timezone.utc).isoformat()
        },
        "mitigations": []
    }


def build_risk_score_response(top_assets):
    return {
        "version": "v1",
        "graph": {
            "nodes": [],
            "edges": []
        },
        "risk": {
            "top_assets": top_assets
        },
        "prediction": {
            "next_targets": []
        },
        "summary": {
            "highest_risk": top_assets[0]["asset_name"] if top_assets else None,
            "overall_risk_level": top_assets[0]["risk_level"] if top_assets else None,
            "total_assets": len(top_assets),
            "generated_at": datetime.now(timezone.utc).isoformat()
        },
        "mitigations": []
    }


def build_attack_risk_response(summary_data):
    nodes = summary_data.get("attack_path", {}).get("nodes", [])
    relationships = []  # Not provided in summary
    cytoscape_nodes, cytoscape_edges = path_to_cytoscape_nodes_edges(nodes, relationships)
    
    # Extract data from service response
    start_asset = summary_data.get("start", "Unknown")
    target_asset = summary_data.get("target", "Unknown")
    path_length = summary_data.get("attack_path", {}).get("length", len(nodes))
    risk_analysis = summary_data.get("risk_analysis", {})
    
    # Build top_assets array with risk data
    top_assets = []
    if risk_analysis:
        top_assets.append({
            "asset_name": target_asset,
            "risk_score": risk_analysis.get("risk_score", 0),
            "risk_level": risk_analysis.get("risk_level", "UNKNOWN"),
            "explanation": risk_analysis.get("explanation", ""),
            "contributing_factors": risk_analysis.get("factors", [])
        })
    
    return {
        "version": "v1",
        "graph": {
            "nodes": cytoscape_nodes,
            "edges": cytoscape_edges
        },
        "risk": {
            "top_assets": top_assets
        },
        "prediction": {
            "next_targets": []
        },
        "summary": {
            "start_asset": start_asset,
            "target_asset": target_asset,
            "path_length": path_length,
            "overall_risk_level": risk_analysis.get("risk_level", "UNKNOWN"),
            "highest_risk": target_asset,
            "generated_at": datetime.now(timezone.utc).isoformat()
        },
        "mitigations": []
    }

def build_single_asset_risk_response(asset_data):
    asset_name = asset_data.get("asset_name", "Unknown")
    risk_score = asset_data.get("risk_score", 0)
    risk_level = asset_data.get("risk_level", "UNKNOWN")
    attack_path_details = asset_data.get("attack_path_details", {})

    return {
        "version": "v1",
        "graph": {
            "nodes": [],
            "edges": []
        },
        "risk": {
            "top_assets": [
                {
                    "asset_name": asset_name,
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                    "attack_path_details": attack_path_details
                }
            ]
        },
        "prediction": {
            "next_targets": []
        },
        "summary": {
            "target_asset": asset_name,
            "overall_risk_level": risk_level,
            "generated_at": datetime.now(timezone.utc).isoformat()
        },
        "mitigations": []
    }


def build_response(graph_nodes, graph_edges, risk_assets):
    return {
        "version": "v1",
        "graph": {
            "nodes": graph_nodes,
            "edges": graph_edges
        },
        "risk": {
            "top_assets": risk_assets
        },
        "prediction": {
            "next_targets": []
        },
        "summary": {
            "total_nodes": len(graph_nodes),
            "total_edges": len(graph_edges),
            "highest_risk": risk_assets[0]["asset_name"] if risk_assets else None,
            "generated_at": datetime.now(timezone.utc).isoformat()
        },
        "mitigations": []
    }