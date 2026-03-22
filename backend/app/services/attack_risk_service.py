from __future__ import annotations

from typing import Any

from app.services.attack_graph_service import get_shortest_attack_path
from app.services.risk_service import calculate_risk_score


def _extract_attack_path_summary(path_result: Any) -> dict[str, Any]:
    if not isinstance(path_result, dict):
        return {"nodes": [], "length": 0}

    nodes = path_result.get("nodes")
    if not isinstance(nodes, list):
        nodes = []

    if not nodes:
        return {"nodes": [], "length": 0}

    path_length = path_result.get("path_length")
    if not isinstance(path_length, int):
        path_length = len(nodes)

    return {
        "nodes": nodes,
        "length": path_length,
    }


def _extract_risk_summary(risk_result: Any, target: str) -> dict[str, Any]:
    if not isinstance(risk_result, dict):
        return {
            "risk_score": 0.0,
            "risk_level": "UNKNOWN",
            "explanation": f"Risk analysis unavailable for {target}.",
            "factors": [],
        }

    # Safe conversion
    try:
        risk_score = float(risk_result.get("risk_score", 0.0))
    except (TypeError, ValueError):
        risk_score = 0.0

    risk_level = str(risk_result.get("risk_level", "UNKNOWN"))

    factors = (
        risk_result.get("contributing_factors")
        or risk_result.get("factors")
        or []
    )

    if not isinstance(factors, list):
        factors = []

    explanation = risk_result.get("explanation")
    if not isinstance(explanation, str) or not explanation.strip():
        explanation = f"{target} is assessed as {risk_level} risk ({risk_score}/100)."

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "explanation": explanation,
        "factors": factors,
    }


def get_attack_risk_summary(start: str, target: str) -> dict[str, Any]:
    """Return attack path and risk summary between start and target assets."""
    start_value = str(start).strip() if start else ""
    target_value = str(target).strip() if target else ""

    # Validate input
    if not start_value or not target_value:
        return {"error": "Start and target must be provided"}

    # --- ATTACK PATH QUERY ---
    try:
        path_result = get_shortest_attack_path(start=start_value, target=target_value)
        if not path_result:
            return {"error": "No attack path found between given nodes"}

    except Exception as e:
        return {"error": f"Attack path computation failed: {str(e)}"}

    # Extract path summary
    attack_path = _extract_attack_path_summary(path_result)

    # --- RISK CALCULATION ---
    try:
        risk_result = calculate_risk_score(target_value)
    except Exception as e:
        return {"error": f"Risk computation failed: {str(e)}"}

    if not isinstance(risk_result, dict):
        return {"error": f"Risk data not found for asset: {target_value}"}

    risk_analysis = _extract_risk_summary(risk_result, target_value)

    # --- FINAL RESPONSE ---
    return {
        "start": start_value,
        "target": target_value,
        "attack_path": {
            "nodes": attack_path["nodes"],
            "length": attack_path["length"],
        },
        "risk_analysis": {
            "risk_score": risk_analysis["risk_score"],
            "risk_level": risk_analysis["risk_level"],
            "explanation": risk_analysis["explanation"],
            "factors": risk_analysis["factors"],
        },
    }