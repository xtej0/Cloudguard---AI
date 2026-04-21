from __future__ import annotations

from typing import Any

from app.services.mitigation_service import get_mitigation_recommendations
from app.services.prediction_service import predict_next_targets
from app.services.summary_service import build_attack_summary_message, utc_now_iso
from app.utils.graph_formatter import make_edge, make_node, path_to_cytoscape_nodes_edges


def build_error_response(
    message: str,
    *,
    start: str | None = None,
    target: str | None = None,
) -> dict[str, Any]:
    """Build standardized error payload using the unified response schema."""
    summary: dict[str, Any] = {
        "error": message,
        "generated_at": utc_now_iso(),
    }
    if start is not None:
        summary["start_asset"] = start
    if target is not None:
        summary["target_asset"] = target

    return build_attack_risk_summary_response(
        graph={"nodes": [], "edges": []},
        risk_top_assets=[],
        summary=summary,
        prediction=[],
        mitigations=[],
    )


def build_graph_response(nodes: list[str], relationships: list[str] | None = None) -> dict[str, list[dict[str, Any]]]:
    """Build graph section in Cytoscape format from ordered path nodes and relationships."""
    cytoscape_nodes, cytoscape_edges = path_to_cytoscape_nodes_edges(nodes, relationships)
    return {
        "nodes": cytoscape_nodes,
        "edges": cytoscape_edges,
    }


def build_attack_risk_summary_response(
    *,
    graph: dict[str, Any],
    risk_top_assets: list[dict[str, Any]],
    summary: dict[str, Any],
    prediction: list[dict[str, Any]] | None = None,
    mitigations: list[str] | None = None,
) -> dict[str, Any]:
    """Build unified attack-risk summary response schema."""
    return {
        "version": "v1",
        "graph": graph,
        "risk": {"top_assets": risk_top_assets},
        "prediction": {"next_targets": prediction if prediction is not None else []},
        "summary": summary,
        "mitigations": mitigations if mitigations is not None else [],
    }


def build_attack_path_response(
    nodes: list[str],
    relationships: list[str],
    start: str | None = None,
    target: str | None = None,
    start_exists: bool | None = None,
    target_exists: bool | None = None,
) -> dict[str, Any]:
    """Build response payload for shortest attack path endpoint."""
    message = build_attack_summary_message(
        start=start,
        target=target,
        path_exists=bool(nodes),
        start_exists=start_exists,
        target_exists=target_exists,
    )
    summary = {
        "start_asset": start,
        "target_asset": target,
        "path_length": len(nodes),
        "overall_risk_level": "UNKNOWN",
        "highest_risk": None,
        "message": message,
        "generated_at": utc_now_iso(),
    }
    graph = build_graph_response(nodes, relationships)

    return build_attack_risk_summary_response(
        graph=graph,
        risk_top_assets=[],
        summary=summary,
        prediction=predict_next_targets(nodes=nodes, target=target),
        mitigations=get_mitigation_recommendations(),
    )


def build_all_paths_response(
    paths: list[dict[str, Any]],
    start: str | None = None,
    target: str | None = None,
    start_exists: bool | None = None,
    target_exists: bool | None = None,
) -> dict[str, Any]:
    """Build response payload for all attack paths endpoint."""
    all_nodes: set[str] = set()
    all_edges: set[tuple[str, str, str]] = set()

    path_length = 0
    if paths:
        first_nodes = paths[0].get("nodes", []) or []
        if isinstance(first_nodes, list) and first_nodes:
            path_length = len(first_nodes)

    for path in paths:
        nodes = path.get("nodes", []) or []
        relationships = path.get("relationships", []) or []
        if not isinstance(nodes, list):
            continue
        for node in nodes:
            all_nodes.add(node)
        for index in range(len(nodes) - 1):
            source = nodes[index]
            path_target = nodes[index + 1]
            relationship = relationships[index] if index < len(relationships) else "UNKNOWN"
            all_edges.add((source, path_target, relationship))

    graph = {
        "nodes": [make_node(node_id=node, label=node, node_type="asset") for node in all_nodes],
        "edges": [make_edge(source=source, target=path_target, label=label) for source, path_target, label in all_edges],
    }
    message = build_attack_summary_message(
        start=start,
        target=target,
        path_exists=bool(paths),
        start_exists=start_exists,
        target_exists=target_exists,
    )
    summary = {
        "start_asset": start,
        "target_asset": target,
        "total_paths": len(paths),
        "path_length": path_length,
        "overall_risk_level": "UNKNOWN",
        "highest_risk": None,
        "message": message,
        "generated_at": utc_now_iso(),
    }

    return build_attack_risk_summary_response(
        graph=graph,
        risk_top_assets=[],
        summary=summary,
        prediction=predict_next_targets(paths=paths, target=target),
        mitigations=get_mitigation_recommendations(),
    )


def build_risk_score_response(top_assets: list[dict[str, Any]]) -> dict[str, Any]:
    """Build response payload for top asset risk scores endpoint."""
    transformed_assets = []
    for asset in top_assets:
        if not isinstance(asset, dict):
            continue
        normalized_asset = dict(asset)
        normalized_asset.pop("asset", None)
        transformed_assets.append(normalized_asset)
    
    summary = {
        "highest_risk": top_assets[0]["asset_name"] if top_assets else None,
        "overall_risk_level": top_assets[0]["risk_level"] if top_assets else None,
        "total_assets": len(top_assets),
        "generated_at": utc_now_iso(),
    }

    return build_attack_risk_summary_response(
        graph={"nodes": [], "edges": []},
        risk_top_assets=transformed_assets,
        summary=summary,
        prediction=predict_next_targets(top_assets=top_assets),
        mitigations=get_mitigation_recommendations(),
    )


def build_attack_risk_response(
    summary_data: dict[str, Any],
    start: str | None = None,
    target: str | None = None,
    start_exists: bool | None = None,
    target_exists: bool | None = None,
) -> dict[str, Any]:
    """Build response payload for attack-risk summary endpoint."""
    if "error" in summary_data:
        return build_error_response(
            str(summary_data.get("error") or "Unknown error"),
            start=start,
            target=target,
        )

    nodes = summary_data.get("attack_path", {}).get("nodes", [])

    start_asset = start if start is not None else summary_data.get("start")
    target_asset = target if target is not None else summary_data.get("target")
    path_length = summary_data.get("attack_path", {}).get("length", len(nodes))
    risk_analysis = summary_data.get("risk_analysis", {})

    message = build_attack_summary_message(
        start=start_asset,
        target=target_asset,
        path_exists=bool(nodes),
        start_exists=start_exists,
        target_exists=target_exists,
    )

    top_assets: list[dict[str, Any]] = []
    if risk_analysis:
        top_assets.append(
            {
                "asset_name": target_asset,
                "risk_score": risk_analysis.get("risk_score", 0),
                "risk_level": risk_analysis.get("risk_level", "UNKNOWN"),
                "explanation": risk_analysis.get("explanation", ""),
                "contributing_factors": risk_analysis.get("factors", []),
            }
        )

    summary = {
        "start_asset": start_asset,
        "target_asset": target_asset,
        "path_length": path_length,
        "overall_risk_level": risk_analysis.get("risk_level", "UNKNOWN"),
        "highest_risk": target_asset,
        "message": message,
        "generated_at": utc_now_iso(),
    }

    return build_attack_risk_summary_response(
        graph=build_graph_response(nodes, []),
        risk_top_assets=top_assets,
        summary=summary,
        prediction=predict_next_targets(nodes=nodes, target=target_asset),
        mitigations=get_mitigation_recommendations(risk_level=risk_analysis.get("risk_level")),
    )


def build_single_asset_risk_response(asset_data: dict[str, Any]) -> dict[str, Any]:
    """Build response payload for single asset risk score endpoint."""
    asset_name = asset_data.get("asset_name", "Unknown")
    risk_score = asset_data.get("risk_score", 0)
    risk_level = asset_data.get("risk_level", "UNKNOWN")
    attack_path_details = asset_data.get("attack_path_details", {})

    summary = {
        "target_asset": asset_name,
        "overall_risk_level": risk_level,
        "generated_at": utc_now_iso(),
    }

    return build_attack_risk_summary_response(
        graph={"nodes": [], "edges": []},
        risk_top_assets=[
            {
                "asset_name": asset_name,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "attack_path_details": attack_path_details,
            }
        ],
        summary=summary,
        prediction=predict_next_targets(asset_name=asset_name),
        mitigations=get_mitigation_recommendations(risk_level=risk_level),
    )


def build_response(graph_nodes: list[dict[str, Any]], graph_edges: list[dict[str, Any]], risk_assets: list[dict[str, Any]]) -> dict[str, Any]:
    """Build generic unified response payload from graph and risk sections."""
    summary = {
        "total_nodes": len(graph_nodes),
        "total_edges": len(graph_edges),
        "highest_risk": risk_assets[0]["asset_name"] if risk_assets else None,
        "generated_at": utc_now_iso(),
    }

    return build_attack_risk_summary_response(
        graph={"nodes": graph_nodes, "edges": graph_edges},
        risk_top_assets=risk_assets,
        summary=summary,
        prediction=predict_next_targets(risk_assets=risk_assets),
        mitigations=get_mitigation_recommendations(),
    )