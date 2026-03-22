from __future__ import annotations

from typing import Any

from app.neo4j_config import driver


WEIGHTS: dict[str, float] = {
    "vulnerability_severity": 0.25,
    "exposure_weight": 0.20,
    "privilege_escalation_potential": 0.15,
    "asset_criticality": 0.15,
    "attack_paths": 0.15,
    "shortest_attack_path_length": 0.10,
}


def _normalize_0_to_1(value: Any, mapping: dict[str, float], default: float = 0.0) -> float:
    """Normalize string/number factor values into a 0..1 score."""
    if value is None:
        return default

    if isinstance(value, bool):
        return 1.0 if value else 0.0

    if isinstance(value, (int, float)):
        if value <= 1:
            return max(0.0, min(float(value), 1.0))
        return max(0.0, min(float(value) / 10.0, 1.0))

    key = str(value).strip().lower()
    return mapping.get(key, default)


def fetch_attack_paths(asset_name: str) -> int:
    """Return number of graph attack paths that lead to the asset."""
    query = """
    MATCH p = (start)-[*1..6]->(asset {name: $asset_name})
    WHERE start:Internet OR start:User
    RETURN count(DISTINCT p) AS path_count
    """

    with driver.session() as session:
        result = session.run(query, asset_name=asset_name)
        record = result.single()

    if not record:
        return 0

    return int(record.get("path_count", 0) or 0)


def fetch_shortest_attack_path_length(asset_name: str) -> int | None:
    """Return shortest path length from known entry points to the asset, if found."""
    query = """
    MATCH p = (start)-[*1..6]->(asset {name: $asset_name})
    WHERE start:Internet OR start:User
    RETURN min(length(p)) AS shortest_length
    """

    with driver.session() as session:
        result = session.run(query, asset_name=asset_name)
        record = result.single()

    if not record:
        return None

    shortest_length = record.get("shortest_length")
    if shortest_length is None:
        return None

    return int(shortest_length)


def fetch_asset_properties(asset_name: str) -> dict[str, Any]:
    """Fetch single asset properties from Neo4j by name."""
    query = """
    MATCH (asset {name: $asset_name})
    RETURN properties(asset) AS props, labels(asset) AS labels
    LIMIT 1
    """

    with driver.session() as session:
        result = session.run(query, asset_name=asset_name)
        record = result.single()

    if not record:
        return {}

    props = dict(record.get("props") or {})
    props["labels"] = record.get("labels") or []
    return props


def fetch_all_asset_names() -> list[str]:
    """Return names of all named asset nodes in graph."""
    query = """
    MATCH (asset)
    WHERE asset.name IS NOT NULL
    RETURN DISTINCT asset.name AS name
    """

    with driver.session() as session:
        result = session.run(query)
        return [str(record["name"]) for record in result if record["name"]]


def fetch_important_asset_names() -> list[str]:
    """Return names of important assets, excluding entry-point entities."""
    query = """
    MATCH (asset)
    WHERE asset.name IS NOT NULL
      AND NOT asset:Internet
      AND NOT asset:User
    WITH asset,
         coalesce(toLower(toString(asset.criticality)), toLower(toString(asset.asset_criticality)), '') AS crit,
         coalesce(toLower(toString(asset.severity)), toLower(toString(asset.vulnerability_severity)), '') AS sev,
         coalesce(toLower(toString(asset.exposure_level)), toLower(toString(asset.exposure_weight)), '') AS exp,
         coalesce(asset.internet_exposed, false) AS internet_exposed
    OPTIONAL MATCH (asset)--(neighbor)
    WITH asset, crit, sev, exp, internet_exposed, count(neighbor) AS degree
    WHERE crit IN ['critical', 'high']
       OR sev IN ['critical', 'high']
       OR exp IN ['internet_exposed', 'public', 'external']
       OR internet_exposed = true
       OR degree > 0
    RETURN DISTINCT asset.name AS name
    """

    with driver.session() as session:
        result = session.run(query)
        important = [str(record["name"]) for record in result if record["name"]]

    if important:
        return important

    return fetch_all_asset_names()


def fetch_asset_relationships(asset_name: str) -> list[dict[str, Any]]:
    """Return relationships connected to an asset node (up to 50)."""
    query = """
    MATCH (asset {name: $asset_name})-[r]-(neighbor)
    RETURN type(r) AS rel_type,
           neighbor.name AS neighbor_name,
           labels(neighbor) AS neighbor_labels,
           CASE WHEN startNode(r) = asset THEN 'outgoing' ELSE 'incoming' END AS direction
    LIMIT 50
    """

    with driver.session() as session:
        result = session.run(query, asset_name=asset_name)
        return [
            {
                "type": record["rel_type"],
                "direction": record["direction"],
                "neighbor": record["neighbor_name"],
                "neighbor_labels": list(record["neighbor_labels"] or []),
            }
            for record in result
        ]


def _risk_level_from_score(risk_score: float) -> str:
    """Return risk label for a 0-100 score."""
    return (
        "CRITICAL"
        if risk_score >= 80
        else "HIGH"
        if risk_score >= 60
        else "MEDIUM"
        if risk_score >= 35
        else "LOW"
    )


def _build_contributing_factors(
    asset_props: dict[str, Any],
    factor_scores: dict[str, float],
    attack_path_count: int,
    shortest_attack_path_length: int | None,
    relationship_count: int,
) -> list[str]:
    """Generate concise, human-readable factors driving risk for an asset."""
    factors: list[str] = []

    exposure_raw = asset_props.get(
        "exposure_weight",
        asset_props.get("exposure_level", asset_props.get("internet_exposed", False)),
    )
    exposure_text = str(exposure_raw).strip().lower()
    if factor_scores.get("exposure_weight", 0.0) >= 0.7:
        if exposure_text in {"public", "internet_exposed", "external", "true"} or exposure_raw is True:
            factors.append("Internet/public exposure increases attack surface")
        else:
            factors.append("High external exposure increases attack surface")

    if factor_scores.get("vulnerability_severity", 0.0) >= 0.7:
        factors.append("High vulnerability severity on this asset")

    if factor_scores.get("privilege_escalation_potential", 0.0) >= 0.7:
        factors.append("Strong privilege-escalation potential")

    if factor_scores.get("asset_criticality", 0.0) >= 0.7:
        factors.append("Business-critical asset impact is high")

    if attack_path_count > 0:
        factors.append(f"{attack_path_count} distinct attack path(s) from likely entry points")

    if shortest_attack_path_length is not None:
        if shortest_attack_path_length <= 2:
            factors.append(f"Very short attack path ({shortest_attack_path_length} hops)")
        elif shortest_attack_path_length <= 4:
            factors.append(f"Moderate attack path length ({shortest_attack_path_length} hops)")

    if relationship_count >= 10:
        factors.append("Highly connected node increases lateral-movement options")

    if not factors:
        factors.append("Limited observed exposure and attack-path reachability")

    return factors


def _build_risk_explanation(asset_name: str, risk_score: float, risk_level: str, factors: list[str]) -> str:
    """Build concise explanation sentence for API/UI consumption."""
    lead = f"{asset_name} is assessed as {risk_level} risk ({risk_score}/100)."
    if not factors:
        return lead
    return f"{lead} Key drivers: {'; '.join(factors[:3])}."


def get_all_asset_risk_scores() -> list[dict[str, Any]]:
    """Evaluate and return risk results for all important assets."""
    asset_names = fetch_important_asset_names()
    results: list[dict[str, Any]] = []

    for asset_name in asset_names:
        score_details = compute_risk_score(asset_name)
        raw_inputs = dict(score_details.get("raw_inputs") or {})
        factor_scores = dict(score_details.get("factor_scores") or {})
        asset_props = dict(raw_inputs.get("asset_properties") or {})

        attack_path_count = int(raw_inputs.get("attack_path_count") or 0)
        shortest_attack_path_length = raw_inputs.get("shortest_attack_path_length")
        relationships = fetch_asset_relationships(asset_name)

        risk_score = float(score_details.get("risk_score") or 0.0)
        risk_level = _risk_level_from_score(risk_score)

        contributing_factors = _build_contributing_factors(
            asset_props=asset_props,
            factor_scores=factor_scores,
            attack_path_count=attack_path_count,
            shortest_attack_path_length=shortest_attack_path_length,
            relationship_count=len(relationships),
        )

        attack_path_details = {
            "attack_path_count": attack_path_count,
            "shortest_attack_path_length": shortest_attack_path_length,
            "relationship_count": len(relationships),
            "entrypoint_reachability": (
                "reachable" if attack_path_count > 0 else "not_reachable_from_known_entrypoints"
            ),
        }

        results.append(
            {
                "asset_name": asset_name,
                "risk_score": round(risk_score, 2),
                "risk_level": risk_level,
                "explanation": _build_risk_explanation(asset_name, round(risk_score, 2), risk_level, contributing_factors),
                "contributing_factors": contributing_factors,
                "attack_path_details": attack_path_details,
            }
        )

    results.sort(key=lambda item: item["risk_score"], reverse=True)
    return results


def compute_risk_score(asset_name: str) -> dict[str, Any]:
    """Compute and return weighted risk score details for an asset."""
    asset_props = fetch_asset_properties(asset_name)
    attack_path_count = fetch_attack_paths(asset_name)
    shortest_attack_path_length = fetch_shortest_attack_path_length(asset_name)

    vulnerability_factor = _normalize_0_to_1(
        asset_props.get("vulnerability_severity", asset_props.get("severity")),
        {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.2,
            "none": 0.0,
        },
        default=0.0,
    )

    exposure_raw = asset_props.get(
        "exposure_weight",
        asset_props.get("exposure_level", asset_props.get("internet_exposed", False)),
    )
    exposure_factor = _normalize_0_to_1(
        exposure_raw,
        {
            "internet_exposed": 1.0,
            "public": 1.0,
            "external": 0.8,
            "internal": 0.3,
            "private": 0.1,
            "none": 0.0,
            "true": 1.0,
            "false": 0.0,
        },
        default=0.0,
    )

    privilege_escalation_factor = _normalize_0_to_1(
        asset_props.get("privilege_escalation_potential", asset_props.get("privilege_level")),
        {
            "very_high": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.2,
            "none": 0.0,
            "root": 1.0,
            "admin": 0.9,
            "write": 0.7,
            "read": 0.3,
        },
        default=0.0,
    )

    criticality_factor = _normalize_0_to_1(
        asset_props.get("asset_criticality", asset_props.get("criticality")),
        {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.2,
            "noncritical": 0.1,
        },
        default=0.3,
    )

    attack_paths_factor = min(attack_path_count / 10.0, 1.0)

    if shortest_attack_path_length is None:
        shortest_path_factor = 0.0
    else:
        max_hops = 6.0
        shortest_path_factor = max(0.0, min((max_hops - float(shortest_attack_path_length) + 1.0) / max_hops, 1.0))

    weighted_score = (
        vulnerability_factor * WEIGHTS["vulnerability_severity"]
        + exposure_factor * WEIGHTS["exposure_weight"]
        + privilege_escalation_factor * WEIGHTS["privilege_escalation_potential"]
        + criticality_factor * WEIGHTS["asset_criticality"]
        + attack_paths_factor * WEIGHTS["attack_paths"]
        + shortest_path_factor * WEIGHTS["shortest_attack_path_length"]
    )

    risk_score = round(max(0.0, min(weighted_score, 1.0)) * 100.0, 2)

    labels = asset_props.get("labels") or []
    generic_labels = {"Asset", "Node", "Resource"}
    node_type = next((label for label in labels if label not in generic_labels), labels[0] if labels else "Unknown")

    return {
        "asset_name": asset_name,
        "node_type": node_type,
        "risk_score": risk_score,
        "risk_level": _risk_level_from_score(risk_score),
        "weights": dict(WEIGHTS),
        "factor_scores": {
            "vulnerability_severity": round(vulnerability_factor, 3),
            "exposure_weight": round(exposure_factor, 3),
            "privilege_escalation_potential": round(privilege_escalation_factor, 3),
            "asset_criticality": round(criticality_factor, 3),
            "attack_paths": round(attack_paths_factor, 3),
            "shortest_attack_path_length": round(shortest_path_factor, 3),
        },
        "raw_inputs": {
            "attack_path_count": attack_path_count,
            "shortest_attack_path_length": shortest_attack_path_length,
            "asset_properties": asset_props,
        },
    }


def rank_assets(
    asset_names: list[str] | None = None,
    top_n: int = 10,
) -> list[dict[str, Any]]:
    """Score and rank assets by risk score, returning top_n highest-risk assets."""
    if asset_names is None:
        asset_names = fetch_all_asset_names()

    scored: list[dict[str, Any]] = []
    for name in asset_names:
        result = compute_risk_score(name)
        relationships = fetch_asset_relationships(name)
        scored.append(
            {
                "asset_name": result["asset_name"],
                "node_type": result["node_type"],
                "risk_score": result["risk_score"],
                "risk_level": result["risk_level"],
                "relationships": relationships,
                "factor_scores": result["factor_scores"],
            }
        )

    scored.sort(key=lambda item: item["risk_score"], reverse=True)
    return scored[:top_n]


def score_and_rank_query_results(
    records: list[dict[str, Any]],
    top_n: int = 10,
) -> list[dict[str, Any]]:
    """Score, normalize, and rank a list of pre-fetched asset records."""
    generic_labels = {"Asset", "Node", "Resource"}
    scored: list[dict[str, Any]] = []

    for record in records:
        props: dict[str, Any] = dict(record.get("props") or {})
        labels: list[str] = list(record.get("labels") or [])
        asset_name: str = str(record.get("asset_name") or props.get("name", ""))

        vulnerability_factor = _normalize_0_to_1(
            props.get("vulnerability_severity", props.get("severity")),
            {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "none": 0.0},
            default=0.0,
        )

        exposure_raw = props.get(
            "exposure_weight",
            props.get("exposure_level", props.get("internet_exposed", False)),
        )
        exposure_factor = _normalize_0_to_1(
            exposure_raw,
            {
                "internet_exposed": 1.0,
                "public": 1.0,
                "external": 0.8,
                "internal": 0.3,
                "private": 0.1,
                "none": 0.0,
                "true": 1.0,
                "false": 0.0,
            },
            default=0.0,
        )

        privilege_escalation_factor = _normalize_0_to_1(
            props.get("privilege_escalation_potential", props.get("privilege_level")),
            {
                "very_high": 1.0,
                "high": 0.8,
                "medium": 0.5,
                "low": 0.2,
                "none": 0.0,
                "root": 1.0,
                "admin": 0.9,
                "write": 0.7,
                "read": 0.3,
            },
            default=0.0,
        )

        criticality_factor = _normalize_0_to_1(
            props.get("asset_criticality", props.get("criticality")),
            {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "noncritical": 0.1},
            default=0.3,
        )

        raw_attack_path_count = record.get("attack_path_count")
        if raw_attack_path_count is None:
            raw_attack_path_count = props.get("attack_path_count")
        attack_path_count = int(raw_attack_path_count or 0)
        attack_paths_factor = min(attack_path_count / 10.0, 1.0)

        raw_shortest = record.get("shortest_attack_path_length")
        if raw_shortest is None:
            raw_shortest = props.get("shortest_attack_path_length")
        if raw_shortest is None:
            shortest_path_factor = 0.0
        else:
            max_hops = 6.0
            shortest_path_factor = max(0.0, min((max_hops - float(raw_shortest) + 1.0) / max_hops, 1.0))

        weighted_score = (
            vulnerability_factor * WEIGHTS["vulnerability_severity"]
            + exposure_factor * WEIGHTS["exposure_weight"]
            + privilege_escalation_factor * WEIGHTS["privilege_escalation_potential"]
            + criticality_factor * WEIGHTS["asset_criticality"]
            + attack_paths_factor * WEIGHTS["attack_paths"]
            + shortest_path_factor * WEIGHTS["shortest_attack_path_length"]
        )
        risk_score = round(max(0.0, min(weighted_score, 1.0)) * 100.0, 2)

        risk_level = _risk_level_from_score(risk_score)
        node_type = next((label for label in labels if label not in generic_labels), labels[0] if labels else "Unknown")

        raw_relationships = record.get("relationships") or []
        relationships = [
            {
                "type": str(item.get("type", "")),
                "direction": str(item.get("direction", "")),
                "neighbor": item.get("neighbor"),
                "neighbor_labels": list(item.get("neighbor_labels") or []),
            }
            for item in raw_relationships
            if item and item.get("type")
        ]

        scored.append(
            {
                "asset_name": asset_name,
                "node_type": node_type,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "relationships": relationships,
                "factor_scores": {
                    "vulnerability_severity": round(vulnerability_factor, 3),
                    "exposure_weight": round(exposure_factor, 3),
                    "privilege_escalation_potential": round(privilege_escalation_factor, 3),
                    "asset_criticality": round(criticality_factor, 3),
                    "attack_paths": round(attack_paths_factor, 3),
                    "shortest_attack_path_length": round(shortest_path_factor, 3),
                },
            }
        )

    scored.sort(key=lambda item: item["risk_score"], reverse=True)
    return scored[:top_n]


def calculate_risk_score(asset_name: str) -> dict[str, Any]:
    """Calculate risk score details for a single asset."""
    return compute_risk_score(asset_name)


def get_top_asset_risk_scores() -> list[dict[str, Any]]:
    """Return ranked risk scores for all assets."""
    return get_all_asset_risk_scores()


def get_single_asset_risk_data(asset_name: str) -> dict[str, Any]:
    """Return normalized single-asset risk payload for response builders."""
    risk_data = calculate_risk_score(asset_name)
    raw_inputs = risk_data.get("raw_inputs", {})

    return {
        "asset_name": risk_data.get("asset_name", asset_name),
        "risk_score": risk_data.get("risk_score"),
        "risk_level": risk_data.get("risk_level"),
        "attack_path_details": {
            "attack_path_count": raw_inputs.get("attack_path_count"),
            "shortest_attack_path_length": raw_inputs.get("shortest_attack_path_length"),
        },
    }