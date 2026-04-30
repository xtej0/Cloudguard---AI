from __future__ import annotations

from typing import Any

from app.mitigation_engine import generate_mitigations


def _normalize_text(value: Any) -> str:
    return str(value or "").strip().lower()


def _is_high_risk(level: Any) -> bool:
    return _normalize_text(level).upper() in {"HIGH", "CRITICAL"}


def _context_from_asset(asset: dict[str, Any]) -> dict[str, Any]:
    """Translate existing risk API payloads into mitigation-engine inputs."""

    payload = asset if isinstance(asset, dict) else {}
    name = _normalize_text(payload.get("asset_name") or payload.get("name") or payload.get("node"))
    node_type = _normalize_text(payload.get("node_type") or payload.get("asset_type") or payload.get("type"))
    risk_level = payload.get("risk_level") or payload.get("label")

    factors = payload.get("contributing_factors") or payload.get("factors") or payload.get("reasons") or []
    if isinstance(factors, str):
        factors = [factors]
    factor_text = " ".join(_normalize_text(item) for item in factors if item)

    attack_details = payload.get("attack_path_details") or {}
    attack_path_count = int(attack_details.get("attack_path_count") or payload.get("attack_path_count") or 0)
    shortest_path = attack_details.get("shortest_attack_path_length") or payload.get("shortest_path_length")

    is_database_or_bucket = any(token in f"{name} {node_type}" for token in ("database", "bucket", "storage"))
    is_identity = any(token in f"{name} {node_type}" for token in ("iam", "role", "identity", "user"))
    has_exposure_signal = any(token in factor_text for token in ("internet", "public", "exposure", "exposed"))
    has_vulnerability_signal = "vulnerab" in factor_text or "severity" in factor_text
    has_privilege_signal = any(token in factor_text for token in ("privilege", "iam", "role", "escalation"))

    return {
        "internet_exposed": 1 if has_exposure_signal else 0,
        "public_access": 1 if "public" in factor_text else 0,
        "has_critical_data": 1 if is_database_or_bucket else 0,
        "weak_iam": 1 if is_identity or has_privilege_signal else 0,
        "lateral_movement_possible": 1 if attack_path_count > 0 else 0,
        "privilege_escalation_possible": 1 if is_identity or has_privilege_signal else 0,
        "critical_vulnerability_count": 1 if has_vulnerability_signal and _is_high_risk(risk_level) else 0,
        "vulnerability_count": 6 if has_vulnerability_signal else 0,
        "misconfiguration_count": 1 if has_exposure_signal and _is_high_risk(risk_level) else 0,
        "attack_path_count": attack_path_count,
        "shortest_path_length": shortest_path or 0,
    }


def _fallback_recommendation(asset: dict[str, Any]) -> list[dict[str, str]]:
    risk_level = str(asset.get("risk_level") or asset.get("label") or "MEDIUM").upper()
    asset_name = str(asset.get("asset_name") or asset.get("name") or asset.get("node") or "asset")
    severity = "HIGH" if risk_level in {"HIGH", "CRITICAL"} else "MEDIUM"
    priority = "P1" if severity == "HIGH" else "P2"

    return [
        {
            "title": "Review Asset Risk Controls",
            "recommendation": "Review exposure, identity permissions, patch status, and network segmentation for this asset.",
            "severity": severity,
            "priority": priority,
            "reason": f"{asset_name} is currently assessed as {risk_level} risk.",
        }
    ]


def get_mitigation_recommendations(*_args: Any, **kwargs: Any) -> list[dict[str, Any]]:
    """Return contextual mitigation recommendations for response builders."""

    if "risk_assets" in kwargs and isinstance(kwargs["risk_assets"], list):
        recommendations: list[dict[str, Any]] = []
        seen_titles: set[str] = set()
        for asset in kwargs["risk_assets"][:3]:
            if not isinstance(asset, dict):
                continue
            for item in get_mitigation_recommendations(asset=asset):
                title = str(item.get("title") or "")
                if title and title not in seen_titles:
                    seen_titles.add(title)
                    recommendations.append(item)
        return recommendations

    asset = kwargs.get("asset")
    if not isinstance(asset, dict):
        asset = dict(kwargs)

    context = _context_from_asset(asset)
    recommendations = generate_mitigations(context)
    if recommendations:
        return recommendations

    if asset:
        return _fallback_recommendation(asset)

    return []
