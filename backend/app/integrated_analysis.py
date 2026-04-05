from __future__ import annotations

from typing import Any

from app.ml_engine import predict_compromise
from app.neo4j_config import driver
from app.services.risk_service import get_single_asset_risk_data


MAX_CANDIDATE_PATH_DEPTH = 3
MAX_CANDIDATES = 25


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


def get_candidate_next_hops(asset_name: str) -> list[dict[str, Any]]:
    query = f"""
        MATCH (source {{name: $asset_name}})
    MATCH p = (source)-[*1..{MAX_CANDIDATE_PATH_DEPTH}]->(candidate)
    WHERE candidate.name IS NOT NULL
      AND candidate.name <> $asset_name
    WITH candidate,
         min(length(p)) AS shortest_path_length,
         count(DISTINCT p) AS attack_path_count
    RETURN
      candidate.name AS asset_name,
      labels(candidate) AS labels,
      properties(candidate) AS props,
      shortest_path_length AS path_length,
      attack_path_count
    ORDER BY path_length ASC, attack_path_count DESC, asset_name ASC
    LIMIT $limit
    """

    candidates: list[dict[str, Any]] = []
    with driver.session() as session:
        results = session.run(
            query,
            asset_name=asset_name,
            limit=MAX_CANDIDATES,
        )
        for record in results:
            props = dict(record.get("props") or {})
            labels = list(record.get("labels") or [])
            candidate = {
                "asset_name": str(record.get("asset_name") or ""),
                "asset_type": str(props.get("asset_type") or ""),
                "labels": labels,
                "path_length": _to_int(record.get("path_length"), default=1),
                "attack_path_count": max(_to_int(record.get("attack_path_count"), default=1), 1),
                "props": props,
            }
            if candidate["asset_name"]:
                candidates.append(candidate)

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

    current_risk = get_asset_risk_summary(normalized_asset_name)
    source_context = _build_source_progression_context(normalized_asset_name)
    candidates = get_candidate_next_hops(normalized_asset_name)

    enriched_candidates: list[dict[str, Any]] = []
    best_feature_importance: list[dict[str, Any]] = []

    for candidate in candidates:
        path_length = max(_to_int(candidate.get("path_length"), default=1), 1)
        reachability_score = compute_reachability_score(path_length)

        try:
            features = build_prediction_features_for_candidate(
                normalized_asset_name,
                candidate,
                source_context=source_context,
            )
            prediction = predict_compromise(features)
            prediction_summary = _safe_prediction_summary(prediction)
            compromise_likelihood = compute_compromise_likelihood(prediction_summary.get("probabilities"))
            combined_score = compute_combined_score(
                risk_score=_to_float(current_risk.get("risk_score"), 0.0),
                ml_confidence=compromise_likelihood,
                reachability_score=reachability_score,
            )
        except Exception:
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

    best_candidate = select_best_next_target(enriched_candidates)
    predicted_next_target: dict[str, Any] | None = None

    if best_candidate:
        predicted_next_target = {
            "asset_name": best_candidate.get("asset_name"),
            "asset_type": best_candidate.get("asset_type"),
            "predicted_label": best_candidate.get("prediction", {}).get("predicted_label", "UNKNOWN"),
            "confidence": _to_float(best_candidate.get("prediction", {}).get("confidence"), 0.0),
            "combined_score": _to_float(best_candidate.get("combined_score"), 0.0),
            "reason": (
                "Selected for shortest-path reachability and strongest combined compromise likelihood."
            ),
        }

        for candidate in candidates:
            if candidate.get("asset_name") == best_candidate.get("asset_name"):
                raw_importance = candidate.get("_feature_importance") or []
                if isinstance(raw_importance, list):
                    best_feature_importance = raw_importance
                break

    return {
        "asset_name": normalized_asset_name,
        "current_risk": current_risk,
        "candidate_next_hops": enriched_candidates,
        "predicted_next_target": predicted_next_target,
        "feature_importance": best_feature_importance,
    }