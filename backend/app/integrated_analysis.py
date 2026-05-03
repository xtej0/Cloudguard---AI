from __future__ import annotations

import os
from typing import Any

from app.ml_engine import predict_compromise
from app.mitigation_engine import generate_mitigations
from app.neo4j_config import driver
from app.services.risk_service import get_single_asset_risk_data


MAX_CANDIDATE_PATH_DEPTH = 3
MAX_CANDIDATES = 25
DEBUG = os.getenv("CLOUDGUARD_DEBUG", "false").strip().lower() in {"1", "true", "yes", "on"}


ASSET_PROFILE_DEFAULTS: dict[str, dict[str, float]] = {
    "vm": {
        "min_open_port_count": 2,
        "min_vulnerability_count": 3,
        "min_critical_vulnerability_count": 1,
        "min_misconfiguration_count": 1,
        "min_exposure_score": 45.0,
        "min_identity_risk_score": 60.0,
        "min_network_risk_score": 55.0,
        "default_weak_iam": 1,
        "default_privilege_escalation_possible": 1,
        "default_has_critical_data": 0,
    },
    "database": {
        "min_open_port_count": 1,
        "min_vulnerability_count": 4,
        "min_critical_vulnerability_count": 1,
        "min_misconfiguration_count": 1,
        "min_exposure_score": 50.0,
        "min_identity_risk_score": 65.0,
        "min_network_risk_score": 45.0,
        "default_weak_iam": 1,
        "default_privilege_escalation_possible": 0,
        "default_has_critical_data": 1,
    },
    "bucket": {
        "min_open_port_count": 0,
        "min_vulnerability_count": 2,
        "min_critical_vulnerability_count": 0,
        "min_misconfiguration_count": 1,
        "min_exposure_score": 35.0,
        "min_identity_risk_score": 50.0,
        "min_network_risk_score": 35.0,
        "default_weak_iam": 1,
        "default_privilege_escalation_possible": 0,
        "default_has_critical_data": 1,
    },
    "iam": {
        "min_open_port_count": 0,
        "min_vulnerability_count": 1,
        "min_critical_vulnerability_count": 0,
        "min_misconfiguration_count": 1,
        "min_exposure_score": 25.0,
        "min_identity_risk_score": 75.0,
        "min_network_risk_score": 25.0,
        "default_weak_iam": 1,
        "default_privilege_escalation_possible": 1,
        "default_has_critical_data": 0,
    },
    "default": {
        "min_open_port_count": 1,
        "min_vulnerability_count": 2,
        "min_critical_vulnerability_count": 0,
        "min_misconfiguration_count": 1,
        "min_exposure_score": 30.0,
        "min_identity_risk_score": 45.0,
        "min_network_risk_score": 40.0,
        "default_weak_iam": 1,
        "default_privilege_escalation_possible": 0,
        "default_has_critical_data": 0,
    },
}


def _to_bool_int(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return 1 if float(value) > 0 else 0
    normalized = str(value).strip().lower()
    return 1 if normalized in {"1", "true", "yes", "y", "public", "external", "internet_exposed"} else 0


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return parsed


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _clamp(value: float, lower: float, upper: float) -> float:
    return max(lower, min(value, upper))


def _risk_level_from_score(score: float) -> str:
    return (
        "CRITICAL"
        if score >= 80
        else "HIGH"
        if score >= 60
        else "MEDIUM"
        if score >= 35
        else "LOW"
    )


def _asset_profile_key(asset_type: str, labels: list[Any], asset_name: str) -> str:
    asset_type_lower = str(asset_type).strip().lower()
    labels_lower = {str(label).strip().lower() for label in labels}
    name_lower = str(asset_name).strip().lower()

    if "database" in asset_type_lower or "database" in labels_lower or "db" in name_lower:
        return "database"
    if (
        "bucket" in asset_type_lower
        or "storage" in asset_type_lower
        or "bucket" in labels_lower
        or "storage" in labels_lower
        or "s3" in name_lower
    ):
        return "bucket"
    if "iam" in asset_type_lower or "role" in asset_type_lower or "iam" in labels_lower or "role" in labels_lower:
        return "iam"
    if (
        "vm" in asset_type_lower
        or "server" in asset_type_lower
        or "compute" in asset_type_lower
        or "vm" in labels_lower
        or "server" in labels_lower
    ):
        return "vm"
    return "default"


def _path_intensity(path_length: int) -> float:
    if path_length <= 1:
        return 1.0
    if path_length == 2:
        return 0.78
    return 0.55


def _scaled_floor(base_value: float, intensity: float) -> float:
    return round(base_value * intensity, 2)


def _debug_print(*parts: Any) -> None:
    if DEBUG:
        print(*parts)


def _get_asset_graph_context(asset_name: str) -> dict[str, Any]:
    snapshot_query = """
    MATCH (n)
    RETURN n.name AS name, labels(n) AS labels
    """

    edge_snapshot_query = """
    MATCH (s)-[r]->(t)
    RETURN s.name AS source, t.name AS target, type(r) AS label, type(r) AS type
    """

    context_query = """
    MATCH (n)
    WITH count(n) AS total_nodes
    MATCH ()-[r]->()
    WITH total_nodes, count(r) AS total_edges
    OPTIONAL MATCH (source {name: $asset_name})-[out_r]->(target)
    WITH total_nodes, total_edges,
           collect({
               source: source.name,
               target: target.name,
               label: type(out_r),
               type: type(out_r)
           }) AS outgoing_edges
    OPTIONAL MATCH (incoming_source)-[in_r]->(incoming_target {name: $asset_name})
    RETURN total_nodes,
             total_edges,
             [edge IN outgoing_edges WHERE edge.source IS NOT NULL AND edge.target IS NOT NULL] AS outgoing_edges,
             collect({
                 source: incoming_source.name,
                 target: incoming_target.name,
                 label: type(in_r),
                 type: type(in_r)
             }) AS incoming_edges
    """

    with driver.session() as session:
        raw_node_records = list(session.run(snapshot_query))
        raw_edge_records = list(session.run(edge_snapshot_query))
        record = session.run(context_query, asset_name=asset_name).single()

    nodes = [
        {
            "name": str(node_record.get("name") or ""),
            "labels": list(node_record.get("labels") or []),
        }
        for node_record in raw_node_records
    ]
    edges = [
        {
            "source": str(edge_record.get("source") or ""),
            "target": str(edge_record.get("target") or ""),
            "label": str(edge_record.get("label") or ""),
            "type": str(edge_record.get("type") or ""),
        }
        for edge_record in raw_edge_records
    ]

    _debug_print("\n=== GRAPH FETCH DEBUG ===")
    _debug_print("Asset requested:", asset_name)
    _debug_print("Graph fetch function used:", "_get_asset_graph_context")
    _debug_print("Cypher Query:", context_query.strip())
    _debug_print("Nodes returned:", nodes)
    _debug_print("Edges returned:", edges)
    _debug_print("\n--- RAW GRAPH SIZE ---")
    _debug_print("Total nodes (raw):", len(nodes))
    _debug_print("Total edges (raw):", len(edges))
    _debug_print("\n--- NODE NAMES ---")
    if nodes:
        for node in nodes:
            _debug_print(node.get("name") or node)
    else:
        _debug_print("None")

    if not record:
        _debug_print("\n--- BEFORE FILTER ---")
        _debug_print(len(nodes), len(edges))
        _debug_print("\n--- AFTER FILTER ---")
        _debug_print(0, 0)
        return {
            "total_nodes": 0,
            "total_edges": 0,
            "outgoing_edges": [],
            "incoming_edges": [],
            "neighbors": [],
        }

    outgoing_edges = list(record.get("outgoing_edges") or [])
    incoming_edges = [
        edge for edge in list(record.get("incoming_edges") or [])
        if edge.get("source") is not None and edge.get("target") is not None
    ]

    _debug_print("\n--- BEFORE FILTER ---")
    _debug_print(len(nodes), len(edges))
    _debug_print("\n--- AFTER FILTER ---")
    _debug_print(len(nodes), len(outgoing_edges) + len(incoming_edges))

    neighbors = set()
    for edge in outgoing_edges:
        target_name = str(edge.get("target") or "").strip()
        if target_name:
            neighbors.add(target_name)
    for edge in incoming_edges:
        source_name = str(edge.get("source") or "").strip()
        if source_name:
            neighbors.add(source_name)

    _debug_print("Filter FIX APPLIED - neighbors:", neighbors)

    if len(neighbors) == 0:
        _debug_print("\n--- BEFORE FILTER ---")
        _debug_print(len(nodes), len(edges))
        _debug_print("\n--- AFTER FILTER ---")
        _debug_print(0, 0)
        return {
            "total_nodes": _to_int(record.get("total_nodes"), default=0),
            "total_edges": _to_int(record.get("total_edges"), default=0),
            "outgoing_edges": [],
            "incoming_edges": [],
            "neighbors": [],
        }

    return {
        "total_nodes": _to_int(record.get("total_nodes"), default=0),
        "total_edges": _to_int(record.get("total_edges"), default=0),
        "outgoing_edges": outgoing_edges,
        "incoming_edges": incoming_edges,
        "neighbors": sorted(neighbors),
    }


def _build_source_progression_context(source_asset: str) -> dict[str, int]:
    risk_data = get_single_asset_risk_data(source_asset)
    attack_path_details = risk_data.get("attack_path_details") or {}
    attack_path_count = max(_to_int(attack_path_details.get("attack_path_count"), default=0), 0)
    shortest = max(_to_int(attack_path_details.get("shortest_attack_path_length"), default=0), 0)
    return {
        "source_attack_path_count": attack_path_count,
        "source_shortest_attack_path_length": shortest,
    }


def _asset_type_from_candidate(candidate: dict[str, Any]) -> str:
    explicit_type = candidate.get("asset_type")
    if isinstance(explicit_type, str) and explicit_type.strip():
        return explicit_type.strip()

    labels = candidate.get("labels") or []
    generic_labels = {"Asset", "Node", "Resource"}
    for label in labels:
        if label not in generic_labels:
            return str(label)

    return "Unknown"


def asset_exists(asset_name: str) -> bool:
    query = """
    MATCH (asset {name: $asset_name})
    RETURN count(asset) > 0 AS exists
    """
    with driver.session() as session:
        record = session.run(query, asset_name=asset_name).single()
    return bool(record and record.get("exists"))


def get_asset_risk_summary(asset_name: str) -> dict[str, Any]:
    risk_data = get_single_asset_risk_data(asset_name)
    risk_score = round(_to_float(risk_data.get("risk_score"), 0.0), 2)
    risk_level = str(risk_data.get("risk_level") or _risk_level_from_score(risk_score))
    explanation = (
        f"{asset_name} is currently assessed as {risk_level} risk ({risk_score}/100) "
        "based on attack-path reachability and asset posture."
    )

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "explanation": explanation,
    }


ATTACK_PRIORITY: dict[str, int] = {
    "INTERNET": 0,
    "STORAGE_BUCKET": 1,
    "WEB_SERVER": 2,
    "APPLICATION_SERVER": 3,
    "IAM_ROLE": 4,
    "DATABASE": 5,
    "USER": 2,
    "UNKNOWN": 2,
}


def _attack_category(asset_name: str, asset_type: str, labels: list[Any]) -> str:
    name_lower = str(asset_name or "").strip().lower()
    type_lower = str(asset_type or "").strip().lower()
    raw_labels = [str(label).strip() for label in labels if str(label).strip()]
    labels_lower = {label.lower() for label in raw_labels}
    compact_labels = {label.replace(" ", "").replace("_", "").replace("-", "") for label in labels_lower}

    category = "UNKNOWN"

    if "IAMRole" in raw_labels or "iamrole" in compact_labels or "iam role" in labels_lower or "iam_role" in labels_lower:
        category = "IAM_ROLE"
    elif "User" in raw_labels or "user" in labels_lower:
        category = "USER"
    elif "internet" in name_lower or "internet" in type_lower or "internet" in labels_lower:
        category = "INTERNET"
    elif "database" in type_lower or "database" in labels_lower or "db" in name_lower:
        category = "DATABASE"
    elif (
        "bucket" in type_lower
        or "storage" in type_lower
        or "bucket" in labels_lower
        or "storage" in labels_lower
        or "s3" in name_lower
    ):
        category = "STORAGE_BUCKET"
    elif "application" in name_lower or "application" in type_lower or "app" in name_lower:
        category = "APPLICATION_SERVER"
    elif "web" in name_lower or "web" in type_lower:
        category = "WEB_SERVER"
    elif "server" in type_lower or "vm" in type_lower or "compute" in type_lower:
        category = "APPLICATION_SERVER"
    elif name_lower == "iam role" or "iam role" in name_lower:
        category = "IAM_ROLE"
    elif name_lower == "user":
        category = "USER"

    _debug_print("CATEGORY DETECTED:", asset_name, "->", category)
    return category


def _is_valid_attack_transition(source_category: str, candidate_category: str) -> bool:
    if source_category == "DATABASE":
        return False

    allowed_transitions = {
        ("INTERNET", "WEB_SERVER"),
        ("WEB_SERVER", "APPLICATION_SERVER"),
        ("APPLICATION_SERVER", "DATABASE"),
        ("IAM_ROLE", "DATABASE"),
        ("STORAGE_BUCKET", "APPLICATION_SERVER"),
    }

    if (source_category, candidate_category) in allowed_transitions:
        return True

    source_priority = ATTACK_PRIORITY.get(source_category, ATTACK_PRIORITY["UNKNOWN"])
    candidate_priority = ATTACK_PRIORITY.get(candidate_category, ATTACK_PRIORITY["UNKNOWN"])

    if candidate_priority < source_priority:
        return False

    # Keep only meaningful forward paths: privilege increase, deeper movement, or sensitive targets.
    if candidate_priority > source_priority:
        return True

    return candidate_category in {"IAM_ROLE", "DATABASE"}


def get_candidate_next_hops(asset_name: str) -> list[dict[str, Any]]:
    graph_debug_context = _get_asset_graph_context(asset_name)
    outgoing_edges = list(graph_debug_context.get("outgoing_edges") or [])
    incoming_edges = list(graph_debug_context.get("incoming_edges") or [])
    neighbors = list(graph_debug_context.get("neighbors") or [])
    identity_categories = {"IAM_ROLE", "USER"}

    _debug_print("\n=== CANDIDATE FUNCTION START ===")
    _debug_print("Source asset:", asset_name)
    _debug_print("Incoming neighbors:", neighbors)

    query = """
        MATCH (source {name: $asset_name})-[r]->(candidate)
        WHERE candidate.name IS NOT NULL
            AND candidate.name <> $asset_name
        RETURN
            source.name AS source_name,
            labels(source) AS source_labels,
            properties(source) AS source_props,
            candidate.name AS asset_name,
            labels(candidate) AS labels,
            properties(candidate) AS props,
            1 AS path_length,
            count(r) AS attack_path_count
        ORDER BY attack_path_count DESC, asset_name ASC
        LIMIT $limit
    """

    candidates: list[dict[str, Any]] = []
    with driver.session() as session:
        results = list(session.run(
            query,
            asset_name=asset_name,
            limit=MAX_CANDIDATES,
        ))
        record_by_name = {
            str(record.get("asset_name") or ""): record
            for record in results
            if str(record.get("asset_name") or "").strip()
        }
        source_category: str | None = None
        source_priority = ATTACK_PRIORITY["UNKNOWN"]

        if not results:
            source_category = _attack_category(asset_name, "", [])
            source_priority = ATTACK_PRIORITY.get(source_category, ATTACK_PRIORITY["UNKNOWN"])

        for record in results:
            if source_category is None:
                source_props = dict(record.get("source_props") or {})
                source_labels = list(record.get("source_labels") or [])
                source_name = str(record.get("source_name") or asset_name)
                source_asset_type = str(source_props.get("asset_type") or "")
                source_category = _attack_category(source_name, source_asset_type, source_labels)
                source_priority = ATTACK_PRIORITY.get(source_category, ATTACK_PRIORITY["UNKNOWN"])

                # Terminal high-value data assets should not emit downstream candidates.
                if source_category == "DATABASE":
                    _debug_print("REJECTED:", asset_name, "| Reason: source category is DATABASE (terminal)")
                    _debug_print("\n=== CANDIDATE FUNCTION END ===")
                    _debug_print("Final candidates list:", candidates)
                    return []

        _debug_print("Loop input neighbors:", neighbors)
        _debug_print("Neighbor count:", len(neighbors))

        for candidate_name in neighbors:
            candidate_name = str(candidate_name or "")
            record = record_by_name.get(candidate_name)
            if record is None:
                record = {
                    "asset_name": candidate_name,
                    "labels": [],
                    "props": {},
                    "path_length": 1,
                    "attack_path_count": 1,
                }

            props = dict(record.get("props") or {})
            labels = list(record.get("labels") or [])
            candidate_asset_type = _asset_type_from_candidate({"asset_type": props.get("asset_type"), "labels": labels})
            candidate_category = _attack_category(candidate_name, candidate_asset_type, labels)
            candidate_priority = ATTACK_PRIORITY.get(candidate_category, ATTACK_PRIORITY["UNKNOWN"])

            _debug_print("\n--- Evaluating Neighbor ---")
            _debug_print("Neighbor:", candidate_name)

            is_same_as_source = candidate_name == asset_name
            has_outgoing_edge = any(
                str(edge.get("source") or "") == asset_name and str(edge.get("target") or "") == candidate_name
                for edge in outgoing_edges
            )
            has_incoming_edge = any(
                str(edge.get("target") or "") == asset_name and str(edge.get("source") or "") == candidate_name
                for edge in incoming_edges
            )
            transition_valid = False if source_category is None else _is_valid_attack_transition(source_category, candidate_category)

            _debug_print("Check: is same as source?", is_same_as_source)
            _debug_print("Check: has outgoing edge?", has_outgoing_edge)
            _debug_print("Check: has incoming edge?", has_incoming_edge)
            _debug_print("Check: transition validity:", transition_valid)
            _debug_print(
                "Check: priority comparison:",
                {
                    "source_category": source_category,
                    "candidate_category": candidate_category,
                    "source_priority": source_priority,
                    "candidate_priority": candidate_priority,
                },
            )

            _debug_print(f"Checking neighbor: {candidate_name}")
            _debug_print("  -> Passed initial check")

            if source_category in identity_categories and candidate_category in identity_categories:
                _debug_print("IDENTITY TRANSITION ALLOWED:", source_category, "->", candidate_category)
            elif candidate_priority < source_priority:
                _debug_print("REJECTED:", candidate_name, "| Reason: candidate priority lower than source")
                _debug_print("  -> Filtered: lower priority than source")
                continue

            if source_category in identity_categories and candidate_category in identity_categories:
                pass
            elif source_category is None or not _is_valid_attack_transition(source_category, candidate_category):
                rejection_reason = "source category unavailable" if source_category is None else "invalid transition direction"
                _debug_print("REJECTED:", candidate_name, "| Reason:", rejection_reason)
                _debug_print("  -> Filtered: invalid transition direction")
                continue

            computed_score_if_available = max(_to_int(record.get("attack_path_count"), default=0), 0)
            _debug_print("  -> Score:", computed_score_if_available)

            candidate = {
                "asset_name": candidate_name,
                "asset_type": candidate_asset_type,
                "labels": labels,
                "path_length": _to_int(record.get("path_length"), default=1),
                "attack_path_count": max(_to_int(record.get("attack_path_count"), default=1), 1),
                "props": props,
            }
            if candidate["asset_name"]:
                candidates.append(candidate)
                _debug_print("ACCEPTED:", candidate_name)

    _debug_print("\n=== CANDIDATE FUNCTION END ===")
    _debug_print("Final candidates list:", candidates)

    return candidates


def build_prediction_features_for_candidate(
    source_asset: str,
    candidate: dict[str, Any],
    source_context: dict[str, int] | None = None,
) -> dict[str, Any]:
    props = candidate.get("props") or {}

    asset_type = _asset_type_from_candidate(candidate)
    labels = list(candidate.get("labels") or [])
    path_length = max(_to_int(candidate.get("path_length"), default=1), 1)
    attack_path_count = max(_to_int(candidate.get("attack_path_count"), default=1), 1)

    profile_key = _asset_profile_key(asset_type, labels, candidate.get("asset_name") or "")
    profile = ASSET_PROFILE_DEFAULTS.get(profile_key, ASSET_PROFILE_DEFAULTS["default"])
    intensity = _path_intensity(path_length)

    source_attack_path_count = max(_to_int((source_context or {}).get("source_attack_path_count"), default=0), 0)
    source_shortest_attack_path_length = max(
        _to_int((source_context or {}).get("source_shortest_attack_path_length"), default=0),
        0,
    )
    source_progression_signal = 1 if (source_attack_path_count > 0 or source_shortest_attack_path_length <= 3) else 0

    internet_exposed = _to_bool_int(
        props.get("internet_exposed", props.get("exposed_to_internet", props.get("exposure_level")))
    )
    public_access = _to_bool_int(props.get("public_access", props.get("exposure_weight", props.get("exposure_level"))))

    name_for_data = str(candidate.get("asset_name") or "").lower()
    asset_type_lower = asset_type.lower()
    labels_lower = {str(label).lower() for label in (candidate.get("labels") or [])}
    has_critical_data = _to_bool_int(
        props.get("has_critical_data")
        if "has_critical_data" in props
        else (
            "database" in asset_type_lower
            or "bucket" in asset_type_lower
            or "storage" in asset_type_lower
            or "database" in labels_lower
            or "bucket" in labels_lower
            or "s3" in name_for_data
        )
    )

    weak_iam = _to_bool_int(props.get("weak_iam", props.get("iam_weak", props.get("identity_weakness"))))
    if weak_iam == 0 and path_length <= 2:
        weak_iam = max(weak_iam, _to_int(profile.get("default_weak_iam"), default=1))

    lateral_movement_possible = 1 if path_length >= 1 else 0

    privilege_escalation_possible = _to_bool_int(
        props.get(
            "privilege_escalation_possible",
            props.get("privilege_escalation_potential", props.get("can_escalate_privilege")),
        )
    )
    if privilege_escalation_possible == 0:
        if path_length == 1:
            privilege_escalation_possible = max(
                _to_int(profile.get("default_privilege_escalation_possible"), default=0),
                source_progression_signal,
            )
        elif path_length == 2 and profile_key in {"vm", "iam"}:
            privilege_escalation_possible = max(
                _to_int(profile.get("default_privilege_escalation_possible"), default=0),
                source_progression_signal,
            )

    open_port_count = max(_to_int(props.get("open_port_count", props.get("open_ports")), default=0), 0)
    vulnerability_count = max(_to_int(props.get("vulnerability_count"), default=0), 0)
    critical_vulnerability_count = max(_to_int(props.get("critical_vulnerability_count"), default=0), 0)
    misconfiguration_count = max(_to_int(props.get("misconfiguration_count"), default=0), 0)

    open_port_floor = _to_int(_scaled_floor(float(profile.get("min_open_port_count", 0)), intensity), default=0)
    vuln_floor = _to_int(_scaled_floor(float(profile.get("min_vulnerability_count", 0)), intensity), default=0)
    critical_vuln_floor = _to_int(
        _scaled_floor(float(profile.get("min_critical_vulnerability_count", 0)), intensity),
        default=0,
    )
    misconfig_floor = _to_int(_scaled_floor(float(profile.get("min_misconfiguration_count", 0)), intensity), default=0)

    if path_length <= 2:
        open_port_count = max(open_port_count, open_port_floor)
        vulnerability_count = max(vulnerability_count, vuln_floor)
        critical_vulnerability_count = max(critical_vulnerability_count, critical_vuln_floor)
        misconfiguration_count = max(misconfiguration_count, misconfig_floor)
    else:
        open_port_count = max(open_port_count, max(open_port_floor - 1, 0))
        vulnerability_count = max(vulnerability_count, max(vuln_floor - 1, 1))
        critical_vulnerability_count = max(critical_vulnerability_count, max(critical_vuln_floor - 1, 0))
        misconfiguration_count = max(misconfiguration_count, max(misconfig_floor - 1, 0))

    if has_critical_data == 0:
        has_critical_data = max(has_critical_data, _to_int(profile.get("default_has_critical_data"), default=0))

    progression_pressure = 7.0 if source_progression_signal else 0.0
    path_pressure = max(0.0, 4.0 - float(path_length)) * 6.0
    vulnerability_pressure = min(vulnerability_count, 12) * 1.3 + min(critical_vulnerability_count, 5) * 5.0
    identity_pressure = 18.0 * weak_iam + 14.0 * privilege_escalation_possible

    exposure_score = _clamp(
        40.0 * internet_exposed
        + 30.0 * public_access
        + min(open_port_count, 20) * 1.5
        + min(vulnerability_count, 20)
        + min(misconfiguration_count, 6) * 2.5
        + path_pressure * 0.45,
        0.0,
        100.0,
    )
    identity_risk_score = _clamp(
        55.0 * weak_iam
        + 45.0 * privilege_escalation_possible
        + min(attack_path_count, 10) * 2.0
        + progression_pressure,
        0.0,
        100.0,
    )
    network_risk_score = _clamp(
        35.0 * internet_exposed
        + 25.0 * public_access
        + min(open_port_count, 30) * 1.5
        + min(misconfiguration_count, 8) * 2.0
        + vulnerability_pressure * 0.35
        + identity_pressure * 0.2
        + min(attack_path_count, 10) * 2.0
        + max(0, 4 - path_length) * 5.0,
        0.0,
        100.0,
    )

    # Reachable candidates should inherit realistic minimum posture by depth and type.
    if path_length <= 2:
        exposure_score = max(exposure_score, _scaled_floor(float(profile.get("min_exposure_score", 0.0)), intensity))
        identity_risk_score = max(
            identity_risk_score,
            _scaled_floor(float(profile.get("min_identity_risk_score", 0.0)), intensity),
        )
        network_risk_score = max(
            network_risk_score,
            _scaled_floor(float(profile.get("min_network_risk_score", 0.0)), intensity),
        )
    elif path_length >= 3:
        exposure_score = max(exposure_score, _scaled_floor(float(profile.get("min_exposure_score", 0.0)), 0.45))
        identity_risk_score = max(
            identity_risk_score,
            _scaled_floor(float(profile.get("min_identity_risk_score", 0.0)), 0.45),
        )
        network_risk_score = max(network_risk_score, _scaled_floor(float(profile.get("min_network_risk_score", 0.0)), 0.45))

    return {
        "asset_type": asset_type,
        "internet_exposed": internet_exposed,
        "public_access": public_access,
        "has_critical_data": has_critical_data,
        "weak_iam": weak_iam,
        "lateral_movement_possible": lateral_movement_possible,
        "privilege_escalation_possible": privilege_escalation_possible,
        "open_port_count": open_port_count,
        "vulnerability_count": vulnerability_count,
        "critical_vulnerability_count": critical_vulnerability_count,
        "misconfiguration_count": misconfiguration_count,
        "attack_path_count": attack_path_count,
        "shortest_path_length": path_length,
        "exposure_score": round(exposure_score, 2),
        "identity_risk_score": round(identity_risk_score, 2),
        "network_risk_score": round(network_risk_score, 2),
    }


def compute_reachability_score(path_length: int) -> float:
    if path_length <= 1:
        return 1.0
    if path_length == 2:
        return 0.75
    if path_length == 3:
        return 0.5
    return 0.25


def compute_combined_score(risk_score: float, ml_confidence: float, reachability_score: float) -> float:
    normalized_risk = _clamp(_to_float(risk_score) / 100.0, 0.0, 1.0)
    combined_score = (0.35 * normalized_risk) + (0.45 * _clamp(_to_float(ml_confidence), 0.0, 1.0)) + (0.20 * _clamp(_to_float(reachability_score), 0.0, 1.0))
    return round(_clamp(combined_score, 0.0, 1.0), 4)


def adjust_score_with_security_context(score: float, features: dict[str, Any], risk_level: str | None) -> float:
    adjusted_score = _clamp(_to_float(score), 0.0, 1.0)
    normalized_risk_level = str(risk_level or "").strip().upper()

    if normalized_risk_level in {"HIGH", "CRITICAL"}:
        adjusted_score += 0.15
    elif normalized_risk_level == "MEDIUM":
        adjusted_score += 0.05
    else:
        adjusted_score -= 0.05

    if _to_int((features or {}).get("has_critical_data"), default=0) == 1:
        adjusted_score += 0.10

    if _to_int((features or {}).get("privilege_escalation_possible"), default=0) == 1:
        adjusted_score += 0.10

    if _to_int((features or {}).get("internet_exposed"), default=0) == 1:
        adjusted_score += 0.05

    shortest_path_length = max(_to_int((features or {}).get("shortest_path_length"), default=3), 1)
    if shortest_path_length == 1:
        adjusted_score += 0.10
    elif shortest_path_length == 2:
        adjusted_score += 0.05

    if normalized_risk_level == "LOW":
        adjusted_score -= 0.10

    return round(_clamp(adjusted_score, 0.0, 1.0), 4)


def build_prediction_reason(features: dict[str, Any]) -> str:
    if _to_int((features or {}).get("has_critical_data"), default=0) == 1:
        return "High impact target with critical data exposure risk"

    if _to_int((features or {}).get("privilege_escalation_possible"), default=0) == 1:
        return "High privilege escalation potential"

    if _to_int((features or {}).get("internet_exposed"), default=0) == 1:
        return "Exposed through internet-facing attack surface"

    if max(_to_int((features or {}).get("shortest_path_length"), default=3), 1) == 1:
        return "Directly reachable in attack path"

    return "Predicted based on overall system risk"


def select_best_next_target(candidates: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not candidates:
        return None
    return max(candidates, key=lambda candidate: _to_float(candidate.get("combined_score"), 0.0))


def _safe_prediction_summary(prediction: dict[str, Any]) -> dict[str, Any]:
    predicted_label = str(prediction.get("predicted_label") or "UNKNOWN")
    confidence = _clamp(_to_float(prediction.get("confidence"), 0.0), 0.0, 1.0)

    raw_probabilities = prediction.get("probabilities")
    probabilities: dict[str, float]
    if isinstance(raw_probabilities, dict):
        probabilities = {
            str(label): round(_clamp(_to_float(prob), 0.0, 1.0), 4)
            for label, prob in raw_probabilities.items()
        }
    else:
        probabilities = {}

    return {
        "predicted_label": predicted_label,
        "confidence": round(confidence, 4),
        "probabilities": probabilities,
    }


def compute_compromise_likelihood(probabilities: dict[str, float] | None) -> float:
    if not isinstance(probabilities, dict):
        return 0.0

    high_probability = _clamp(_to_float(probabilities.get("HIGH"), 0.0), 0.0, 1.0)
    medium_probability = _clamp(_to_float(probabilities.get("MEDIUM"), 0.0), 0.0, 1.0)
    compromise_likelihood = high_probability + (0.6 * medium_probability)
    return round(_clamp(compromise_likelihood, 0.0, 1.0), 4)


def get_integrated_asset_analysis(asset_name: str) -> dict[str, Any]:
    normalized_asset_name = str(asset_name).strip()
    if not normalized_asset_name or not asset_exists(normalized_asset_name):
        raise LookupError(f"Asset '{asset_name}' not found")

    _debug_print("\n=== ANALYSIS START ===")
    _debug_print("Asset:", normalized_asset_name)

    graph_context = _get_asset_graph_context(normalized_asset_name)
    outgoing_edges = list(graph_context.get("outgoing_edges") or [])
    incoming_edges = list(graph_context.get("incoming_edges") or [])
    neighbors = list(graph_context.get("neighbors") or [])

    _debug_print("\n--- GRAPH SUMMARY ---")
    _debug_print("Total nodes:", graph_context.get("total_nodes", 0))
    _debug_print("Total edges:", graph_context.get("total_edges", 0))

    _debug_print("\n--- OUTGOING EDGES ---")
    if outgoing_edges:
        for edge in outgoing_edges:
            _debug_print(edge)
    else:
        _debug_print("None")

    _debug_print("\n--- INCOMING EDGES ---")
    if incoming_edges:
        for edge in incoming_edges:
            _debug_print(edge)
    else:
        _debug_print("None")

    _debug_print("\n--- ALL NEIGHBORS ---")
    if neighbors:
        for neighbor in neighbors:
            _debug_print(neighbor)
    else:
        _debug_print("None")

    _debug_print("\n--- EDGE TYPES FOR THIS ASSET ---")
    edge_types = outgoing_edges + incoming_edges
    if edge_types:
        for edge in edge_types:
            _debug_print("Type:", edge.get("label") or edge.get("type"))
    else:
        _debug_print("Type: None")

    _debug_print("\n--- CANDIDATE BUILD TRACE ---")
    if neighbors:
        for neighbor in neighbors:
            _debug_print(f"Checking neighbor: {neighbor}")
            _debug_print("  -> Passed initial check")
            _debug_print("  -> Score:", "N/A")
    else:
        _debug_print("No neighbors discovered for candidate evaluation")

    current_risk = get_asset_risk_summary(normalized_asset_name)
    source_context = _build_source_progression_context(normalized_asset_name)
    candidates = get_candidate_next_hops(normalized_asset_name)

    _debug_print("\n=== POST CANDIDATE SUMMARY ===")
    _debug_print("Candidates returned:", candidates)

    enriched_candidates: list[dict[str, Any]] = []
    best_feature_importance: list[dict[str, Any]] = []
    candidate_feature_map: dict[str, dict[str, Any]] = {}

    for candidate in candidates:
        path_length = max(_to_int(candidate.get("path_length"), default=1), 1)
        reachability_score = compute_reachability_score(path_length)

        try:
            features = build_prediction_features_for_candidate(
                normalized_asset_name,
                candidate,
                source_context=source_context,
            )
            candidate_feature_map[str(candidate.get("asset_name") or "")] = features
            prediction = predict_compromise(features)
            prediction_summary = _safe_prediction_summary(prediction)
            compromise_likelihood = compute_compromise_likelihood(prediction_summary.get("probabilities"))
            combined_score = compute_combined_score(
                risk_score=_to_float(current_risk.get("risk_score"), 0.0),
                ml_confidence=compromise_likelihood,
                reachability_score=reachability_score,
            )
            combined_score = adjust_score_with_security_context(
                combined_score,
                features,
                current_risk.get("risk_level"),
            )
        except Exception:
            candidate_feature_map[str(candidate.get("asset_name") or "")] = {}
            prediction_summary = {
                "predicted_label": "UNKNOWN",
                "confidence": 0.0,
                "probabilities": {},
            }
            combined_score = compute_combined_score(
                risk_score=_to_float(current_risk.get("risk_score"), 0.0),
                ml_confidence=0.0,
                reachability_score=reachability_score,
            )
            combined_score = adjust_score_with_security_context(
                combined_score,
                {},
                current_risk.get("risk_level"),
            )
            prediction = {}

        enriched_candidate = {
            "asset_name": candidate.get("asset_name"),
            "asset_type": _asset_type_from_candidate(candidate),
            "path_length": path_length,
            "reachability_score": round(reachability_score, 2),
            "prediction": prediction_summary,
            "combined_score": combined_score,
        }
        enriched_candidates.append(enriched_candidate)

        candidate["_feature_importance"] = prediction.get("feature_importance", []) if isinstance(prediction, dict) else []

    enriched_candidates = sorted(
        enriched_candidates,
        key=lambda candidate: (-_to_float(candidate.get("combined_score"), 0.0), str(candidate.get("asset_name") or "")),
    )[:3]

    candidate_next_hops = enriched_candidates

    _debug_print("\n--- FINAL CANDIDATES ---")
    if candidate_next_hops:
        for candidate in candidate_next_hops:
            _debug_print(candidate)
    else:
        _debug_print("No candidates generated")

    top_candidate = candidate_next_hops[0] if candidate_next_hops else None
    predicted_next_target: dict[str, Any] | None = None

    is_database_terminal = _asset_profile_key("", [], normalized_asset_name) == "database"

    if candidate_next_hops and not is_database_terminal and top_candidate:
        candidate_confidence = _clamp(_to_float(top_candidate.get("combined_score"), 0.0), 0.0, 1.0)
        predicted_next_target = {
            "asset_name": top_candidate.get("asset_name"),
            "asset_type": top_candidate.get("asset_type"),
            "predicted_label": top_candidate.get("prediction", {}).get("predicted_label", "UNKNOWN"),
            "confidence": candidate_confidence,
            "combined_score": _to_float(top_candidate.get("combined_score"), 0.0),
            "reason": "Top ranked attack path candidate",
        }

        best_features = candidate_feature_map.get(str(top_candidate.get("asset_name") or ""), {})
        impact_hint: str | None = None
        if best_features:
            if _to_int(best_features.get("has_critical_data"), default=0) == 1:
                impact_hint = "Critical data risk"
            elif _to_int(best_features.get("privilege_escalation_possible"), default=0) == 1:
                impact_hint = "Privilege escalation path"
            elif _to_int(best_features.get("internet_exposed"), default=0) == 1:
                impact_hint = "High impact target"
            elif max(_to_int(best_features.get("shortest_path_length"), default=3), 1) == 1:
                impact_hint = "Attack path bridge"

        if impact_hint:
            predicted_next_target["impact_hint"] = impact_hint

        for candidate in candidates:
            if candidate.get("asset_name") == top_candidate.get("asset_name"):
                raw_importance = candidate.get("_feature_importance") or []
                if isinstance(raw_importance, list):
                    best_feature_importance = raw_importance
                break

    _debug_print("\n--- PREDICTION ---")
    _debug_print("Prediction object:", predicted_next_target)

    mitigation_context: dict[str, Any] = {
        "risk_level": current_risk.get("risk_level"),
    }
    if top_candidate:
        best_candidate_name = str(top_candidate.get("asset_name") or "")
        mitigation_context.update(candidate_feature_map.get(best_candidate_name, {}))

    mitigations = generate_mitigations(mitigation_context)

    return {
        "asset_name": normalized_asset_name,
        "current_risk": current_risk,
        "candidate_next_hops": enriched_candidates,
        "predicted_next_target": predicted_next_target,
        "feature_importance": best_feature_importance,
        "mitigations": mitigations,
    }
