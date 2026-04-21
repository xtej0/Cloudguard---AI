from __future__ import annotations

from fastapi.testclient import TestClient

import app.integrated_analysis as integrated_analysis
from app.integrated_analysis import (
    build_prediction_features_for_candidate,
    compute_compromise_likelihood,
    compute_combined_score,
    select_best_next_target,
)
from app.main import app


client = TestClient(app)


def _sample_response() -> dict:
    return {
        "asset_name": "Web Server VM",
        "current_risk": {
            "risk_score": 72.4,
            "risk_level": "HIGH",
            "explanation": "Internet exposure and weak IAM increase risk.",
        },
        "candidate_next_hops": [
            {
                "asset_name": "Application Server VM",
                "asset_type": "VM",
                "path_length": 1,
                "reachability_score": 1.0,
                "prediction": {
                    "predicted_label": "HIGH",
                    "confidence": 0.78,
                    "probabilities": {
                        "HIGH": 0.78,
                        "MEDIUM": 0.18,
                        "LOW": 0.04,
                    },
                },
                "combined_score": 0.81,
            }
        ],
        "predicted_next_target": {
            "asset_name": "Application Server VM",
            "asset_type": "VM",
            "predicted_label": "HIGH",
            "confidence": 0.78,
            "combined_score": 0.81,
            "reason": "Selected as the highest-scoring reachable compromise candidate.",
        },
        "feature_importance": [
            {
                "feature": "exposure_score",
                "impact": 0.31,
                "direction": "increase",
            }
        ],
        "mitigations": [],
    }


def test_integrated_analysis_success_response(monkeypatch):
    monkeypatch.setattr("app.routes.integrated_analysis.get_integrated_asset_analysis", lambda _asset_name: _sample_response())

    response = client.get("/asset-analysis/Web Server VM")

    assert response.status_code == 200
    payload = response.json()
    assert "asset_name" in payload
    assert "current_risk" in payload
    assert "candidate_next_hops" in payload
    assert "predicted_next_target" in payload
    assert "feature_importance" in payload
    assert "mitigations" in payload
    assert isinstance(payload["mitigations"], list)


def test_candidate_annotation_structure(monkeypatch):
    monkeypatch.setattr("app.routes.integrated_analysis.get_integrated_asset_analysis", lambda _asset_name: _sample_response())

    response = client.get("/asset-analysis/Web Server VM")

    assert response.status_code == 200
    payload = response.json()
    assert payload["candidate_next_hops"]

    candidate = payload["candidate_next_hops"][0]
    required = {
        "asset_name",
        "asset_type",
        "path_length",
        "reachability_score",
        "prediction",
        "combined_score",
    }
    assert required.issubset(set(candidate.keys()))


def test_combined_score_range():
    assert 0.0 <= compute_combined_score(risk_score=72.4, ml_confidence=0.78, reachability_score=1.0) <= 1.0
    assert 0.0 <= compute_combined_score(risk_score=0.0, ml_confidence=0.0, reachability_score=0.25) <= 1.0
    assert 0.0 <= compute_combined_score(risk_score=100.0, ml_confidence=1.0, reachability_score=1.0) <= 1.0


def test_no_candidate_scenario(monkeypatch):
    def _no_candidates(_asset_name: str) -> dict:
        response = _sample_response()
        response["candidate_next_hops"] = []
        response["predicted_next_target"] = None
        response["feature_importance"] = []
        return response

    monkeypatch.setattr("app.routes.integrated_analysis.get_integrated_asset_analysis", _no_candidates)

    response = client.get("/asset-analysis/Isolated Asset")

    assert response.status_code == 200
    payload = response.json()
    assert payload["candidate_next_hops"] == []
    assert payload["predicted_next_target"] is None
    assert payload["feature_importance"] == []


def test_best_target_selection():
    candidates = [
        {"asset_name": "a1", "combined_score": 0.62},
        {"asset_name": "a2", "combined_score": 0.91},
        {"asset_name": "a3", "combined_score": 0.45},
    ]

    best = select_best_next_target(candidates)
    assert best is not None
    assert best["asset_name"] == "a2"


def test_invalid_asset_returns_404(monkeypatch):
    def _raise_not_found(_asset_name: str):
        raise LookupError("Asset 'Missing Asset' not found")

    monkeypatch.setattr("app.routes.integrated_analysis.get_integrated_asset_analysis", _raise_not_found)

    response = client.get("/asset-analysis/Missing Asset")

    assert response.status_code == 404
    payload = response.json()
    assert "detail" in payload


def test_frontend_friendly_response_shape(monkeypatch):
    monkeypatch.setattr("app.routes.integrated_analysis.get_integrated_asset_analysis", lambda _asset_name: _sample_response())

    response = client.get("/asset-analysis/Web Server VM")

    assert response.status_code == 200
    payload = response.json()

    assert isinstance(payload.get("asset_name"), str)
    assert isinstance(payload.get("current_risk"), dict)
    assert isinstance(payload.get("candidate_next_hops"), list)
    assert payload.get("predicted_next_target") is None or isinstance(payload.get("predicted_next_target"), dict)
    assert isinstance(payload.get("feature_importance"), list)
    assert isinstance(payload.get("mitigations"), list)


def test_direct_reachable_internal_candidate_has_nonzero_compromise_posture():
    candidate = {
        "asset_name": "Application Server VM",
        "asset_type": "VM",
        "labels": ["Asset", "VM"],
        "path_length": 1,
        "attack_path_count": 1,
        "props": {
            "internet_exposed": False,
            "public_access": False,
            "open_port_count": 0,
            "vulnerability_count": 0,
            "critical_vulnerability_count": 0,
            "misconfiguration_count": 0,
        },
    }

    features = build_prediction_features_for_candidate(
        "Web Server VM",
        candidate,
        source_context={"source_attack_path_count": 2, "source_shortest_attack_path_length": 2},
    )

    assert features["lateral_movement_possible"] == 1
    assert features["weak_iam"] == 1
    assert features["vulnerability_count"] >= 1
    assert features["misconfiguration_count"] >= 1
    assert features["identity_risk_score"] > 0
    assert features["network_risk_score"] > 0


def test_database_candidate_defaults_to_critical_data_signal():
    candidate = {
        "asset_name": "Database Server",
        "asset_type": "Database",
        "labels": ["Asset", "Database"],
        "path_length": 1,
        "attack_path_count": 1,
        "props": {
            "internet_exposed": False,
            "public_access": False,
        },
    }

    features = build_prediction_features_for_candidate(
        "Application Server VM",
        candidate,
        source_context={"source_attack_path_count": 1, "source_shortest_attack_path_length": 2},
    )

    assert features["has_critical_data"] == 1


def test_path_length_one_candidate_has_stronger_progression_features_than_deeper_path():
    near_candidate = {
        "asset_name": "Application Server VM",
        "asset_type": "VM",
        "labels": ["Asset", "VM"],
        "path_length": 1,
        "attack_path_count": 1,
        "props": {},
    }
    far_candidate = {
        "asset_name": "Auxiliary VM",
        "asset_type": "VM",
        "labels": ["Asset", "VM"],
        "path_length": 3,
        "attack_path_count": 1,
        "props": {},
    }

    source_context = {"source_attack_path_count": 2, "source_shortest_attack_path_length": 2}
    near_features = build_prediction_features_for_candidate("Web Server VM", near_candidate, source_context=source_context)
    far_features = build_prediction_features_for_candidate("Web Server VM", far_candidate, source_context=source_context)

    assert near_features["identity_risk_score"] >= far_features["identity_risk_score"]
    assert near_features["network_risk_score"] >= far_features["network_risk_score"]
    assert near_features["vulnerability_count"] >= far_features["vulnerability_count"]


def test_candidate_feature_generation_is_deterministic():
    candidate = {
        "asset_name": "IAM Admin Role",
        "asset_type": "IAM Role",
        "labels": ["Asset", "IAM"],
        "path_length": 2,
        "attack_path_count": 2,
        "props": {},
    }
    source_context = {"source_attack_path_count": 2, "source_shortest_attack_path_length": 1}

    first = build_prediction_features_for_candidate("Application Server VM", candidate, source_context=source_context)
    second = build_prediction_features_for_candidate("Application Server VM", candidate, source_context=source_context)

    assert first == second


def test_candidate_feature_schema_remains_exact_training_shape():
    candidate = {
        "asset_name": "Storage Bucket",
        "asset_type": "Bucket",
        "labels": ["Asset", "Bucket"],
        "path_length": 2,
        "attack_path_count": 1,
        "props": {},
    }

    features = build_prediction_features_for_candidate(
        "Database Server",
        candidate,
        source_context={"source_attack_path_count": 3, "source_shortest_attack_path_length": 2},
    )

    assert set(features.keys()) == {
        "asset_type",
        "internet_exposed",
        "public_access",
        "has_critical_data",
        "weak_iam",
        "lateral_movement_possible",
        "privilege_escalation_possible",
        "open_port_count",
        "vulnerability_count",
        "critical_vulnerability_count",
        "misconfiguration_count",
        "attack_path_count",
        "shortest_path_length",
        "exposure_score",
        "identity_risk_score",
        "network_risk_score",
    }


def test_compromise_likelihood_uses_high_and_medium_probabilities_only():
    probabilities = {"HIGH": 0.3786, "MEDIUM": 0.4904, "LOW": 0.131}

    score = compute_compromise_likelihood(probabilities)

    assert score == 0.6728


def test_web_server_prefers_application_server_over_low_confidence_storage_bucket(monkeypatch):
    candidates = [
        {
            "asset_name": "Application Server VM",
            "asset_type": "VM",
            "labels": ["Asset", "VM"],
            "path_length": 1,
            "attack_path_count": 1,
            "props": {},
        },
        {
            "asset_name": "Storage Bucket",
            "asset_type": "Bucket",
            "labels": ["Asset", "Bucket"],
            "path_length": 1,
            "attack_path_count": 1,
            "props": {},
        },
    ]

    predictions = {
        "Application Server VM": {
            "predicted_label": "MEDIUM",
            "confidence": 0.4904,
            "probabilities": {"HIGH": 0.3786, "MEDIUM": 0.4904, "LOW": 0.131},
        },
        "Storage Bucket": {
            "predicted_label": "LOW",
            "confidence": 0.9515,
            "probabilities": {"HIGH": 0.024, "MEDIUM": 0.0245, "LOW": 0.9515},
        },
    }

    monkeypatch.setattr(integrated_analysis, "asset_exists", lambda _asset_name: True)
    monkeypatch.setattr(integrated_analysis, "get_asset_risk_summary", lambda _asset_name: {"risk_score": 72.4, "risk_level": "HIGH", "explanation": "stub"})
    monkeypatch.setattr(
        integrated_analysis,
        "_build_source_progression_context",
        lambda _asset_name: {"source_attack_path_count": 2, "source_shortest_attack_path_length": 2},
    )
    monkeypatch.setattr(integrated_analysis, "get_candidate_next_hops", lambda _asset_name: candidates)
    monkeypatch.setattr(
        integrated_analysis,
        "predict_compromise",
        lambda features: predictions["Application Server VM"]
        if features["asset_type"] == "VM"
        else predictions["Storage Bucket"],
    )

    result = integrated_analysis.get_integrated_asset_analysis("Web Server VM")

    assert result["predicted_next_target"]["asset_name"] == "Application Server VM"
    app_candidate = next(item for item in result["candidate_next_hops"] if item["asset_name"] == "Application Server VM")
    bucket_candidate = next(item for item in result["candidate_next_hops"] if item["asset_name"] == "Storage Bucket")
    assert app_candidate["combined_score"] > bucket_candidate["combined_score"]


def test_application_server_still_prefers_database_server(monkeypatch):
    candidates = [
        {
            "asset_name": "Database Server",
            "asset_type": "Database",
            "labels": ["Asset", "Database"],
            "path_length": 1,
            "attack_path_count": 1,
            "props": {},
        },
        {
            "asset_name": "Storage Bucket",
            "asset_type": "Bucket",
            "labels": ["Asset", "Bucket"],
            "path_length": 1,
            "attack_path_count": 1,
            "props": {},
        },
    ]

    predictions = {
        "Database Server": {
            "predicted_label": "MEDIUM",
            "confidence": 0.7,
            "probabilities": {"HIGH": 0.42, "MEDIUM": 0.33, "LOW": 0.25},
        },
        "Storage Bucket": {
            "predicted_label": "LOW",
            "confidence": 0.89,
            "probabilities": {"HIGH": 0.08, "MEDIUM": 0.12, "LOW": 0.8},
        },
    }

    monkeypatch.setattr(integrated_analysis, "asset_exists", lambda _asset_name: True)
    monkeypatch.setattr(integrated_analysis, "get_asset_risk_summary", lambda _asset_name: {"risk_score": 68.0, "risk_level": "HIGH", "explanation": "stub"})
    monkeypatch.setattr(
        integrated_analysis,
        "_build_source_progression_context",
        lambda _asset_name: {"source_attack_path_count": 1, "source_shortest_attack_path_length": 2},
    )
    monkeypatch.setattr(integrated_analysis, "get_candidate_next_hops", lambda _asset_name: candidates)
    monkeypatch.setattr(
        integrated_analysis,
        "predict_compromise",
        lambda features: predictions["Database Server"]
        if features["asset_type"] == "Database"
        else predictions["Storage Bucket"],
    )

    result = integrated_analysis.get_integrated_asset_analysis("Application Server VM")

    assert result["predicted_next_target"]["asset_name"] == "Database Server"


def test_integrated_analysis_includes_mitigations_for_best_candidate(monkeypatch):
    candidates = [
        {
            "asset_name": "Application Server VM",
            "asset_type": "VM",
            "labels": ["Asset", "VM"],
            "path_length": 1,
            "attack_path_count": 1,
            "props": {
                "internet_exposed": 1,
                "public_access": 1,
                "has_critical_data": 1,
            },
        }
    ]

    prediction = {
        "predicted_label": "HIGH",
        "confidence": 0.82,
        "probabilities": {"HIGH": 0.6, "MEDIUM": 0.3, "LOW": 0.1},
    }

    monkeypatch.setattr(integrated_analysis, "asset_exists", lambda _asset_name: True)
    monkeypatch.setattr(
        integrated_analysis,
        "get_asset_risk_summary",
        lambda _asset_name: {"risk_score": 80.0, "risk_level": "CRITICAL", "explanation": "stub"},
    )
    monkeypatch.setattr(
        integrated_analysis,
        "_build_source_progression_context",
        lambda _asset_name: {"source_attack_path_count": 2, "source_shortest_attack_path_length": 1},
    )
    monkeypatch.setattr(integrated_analysis, "get_candidate_next_hops", lambda _asset_name: candidates)
    monkeypatch.setattr(integrated_analysis, "predict_compromise", lambda _features: prediction)

    result = integrated_analysis.get_integrated_asset_analysis("Web Server VM")

    assert "mitigations" in result
    assert isinstance(result["mitigations"], list)
    assert result["mitigations"]
    titles = {item["title"] for item in result["mitigations"]}
    assert "Restrict Internet Exposure" in titles


def test_integrated_analysis_limits_candidates_to_top_three(monkeypatch):
    candidates = [
        {
            "asset_name": "Candidate 1",
            "asset_type": "VM",
            "labels": ["Asset", "VM"],
            "path_length": 1,
            "attack_path_count": 1,
            "props": {"internet_exposed": 1, "public_access": 1},
        },
        {
            "asset_name": "Candidate 2",
            "asset_type": "VM",
            "labels": ["Asset", "VM"],
            "path_length": 2,
            "attack_path_count": 1,
            "props": {"internet_exposed": 1},
        },
        {
            "asset_name": "Candidate 3",
            "asset_type": "VM",
            "labels": ["Asset", "VM"],
            "path_length": 3,
            "attack_path_count": 1,
            "props": {},
        },
        {
            "asset_name": "Candidate 4",
            "asset_type": "VM",
            "labels": ["Asset", "VM"],
            "path_length": 4,
            "attack_path_count": 1,
            "props": {},
        },
    ]

    prediction = {
        "predicted_label": "HIGH",
        "confidence": 0.75,
        "probabilities": {"HIGH": 0.7, "MEDIUM": 0.2, "LOW": 0.1},
    }

    monkeypatch.setattr(integrated_analysis, "asset_exists", lambda _asset_name: True)
    monkeypatch.setattr(
        integrated_analysis,
        "get_asset_risk_summary",
        lambda _asset_name: {"risk_score": 70.0, "risk_level": "HIGH", "explanation": "stub"},
    )
    monkeypatch.setattr(
        integrated_analysis,
        "_build_source_progression_context",
        lambda _asset_name: {"source_attack_path_count": 2, "source_shortest_attack_path_length": 2},
    )
    monkeypatch.setattr(integrated_analysis, "get_candidate_next_hops", lambda _asset_name: candidates)
    monkeypatch.setattr(integrated_analysis, "predict_compromise", lambda _features: prediction)

    result = integrated_analysis.get_integrated_asset_analysis("Web Server VM")

    assert len(result["candidate_next_hops"]) == 3
    assert [item["asset_name"] for item in result["candidate_next_hops"]] == ["Candidate 1", "Candidate 2", "Candidate 3"]


def test_integrated_analysis_is_deterministic_for_same_input(monkeypatch):
    candidates = [
        {
            "asset_name": "Candidate A",
            "asset_type": "VM",
            "labels": ["Asset", "VM"],
            "path_length": 1,
            "attack_path_count": 1,
            "props": {"internet_exposed": 1, "has_critical_data": 1},
        },
        {
            "asset_name": "Candidate B",
            "asset_type": "Database",
            "labels": ["Asset", "Database"],
            "path_length": 2,
            "attack_path_count": 1,
            "props": {"public_access": 1},
        },
    ]

    prediction = {
        "predicted_label": "MEDIUM",
        "confidence": 0.64,
        "probabilities": {"HIGH": 0.3, "MEDIUM": 0.5, "LOW": 0.2},
    }

    monkeypatch.setattr(integrated_analysis, "asset_exists", lambda _asset_name: True)
    monkeypatch.setattr(
        integrated_analysis,
        "get_asset_risk_summary",
        lambda _asset_name: {"risk_score": 66.0, "risk_level": "HIGH", "explanation": "stub"},
    )
    monkeypatch.setattr(
        integrated_analysis,
        "_build_source_progression_context",
        lambda _asset_name: {"source_attack_path_count": 1, "source_shortest_attack_path_length": 2},
    )
    monkeypatch.setattr(integrated_analysis, "get_candidate_next_hops", lambda _asset_name: candidates)
    monkeypatch.setattr(integrated_analysis, "predict_compromise", lambda _features: prediction)

    first = integrated_analysis.get_integrated_asset_analysis("Application Server VM")
    second = integrated_analysis.get_integrated_asset_analysis("Application Server VM")

    assert first == second
