from __future__ import annotations

import pytest

from app import ml_engine


def _valid_input_payload() -> dict:
    return {
        "asset_type": "VM",
        "internet_exposed": 1,
        "public_access": 1,
        "has_critical_data": 1,
        "weak_iam": 1,
        "lateral_movement_possible": 1,
        "privilege_escalation_possible": 1,
        "open_port_count": 8,
        "vulnerability_count": 10,
        "critical_vulnerability_count": 4,
        "misconfiguration_count": 3,
        "attack_path_count": 6,
        "shortest_path_length": 2,
        "exposure_score": 78.5,
        "identity_risk_score": 71.2,
        "network_risk_score": 69.3,
    }


def test_model_loads_successfully():
    ml_engine.load_model_artifacts()

    assert ml_engine.MODEL is not None
    assert ml_engine.TARGET_ENCODER is not None
    assert isinstance(ml_engine.FEATURE_COLUMNS, list)
    assert ml_engine.FEATURE_COLUMNS


def test_prepare_features_returns_single_row_with_exact_columns():
    features_df = ml_engine.prepare_features(_valid_input_payload())

    assert list(features_df.columns) == ml_engine.FEATURE_COLUMNS
    assert len(features_df) == 1
    assert set(ml_engine.FEATURE_COLUMNS).issubset(set(features_df.columns))


def test_predict_compromise_returns_expected_structure():
    output = ml_engine.predict_compromise(_valid_input_payload())

    assert "predicted_label" in output
    assert "confidence" in output
    assert "probabilities" in output
    assert isinstance(output["predicted_label"], str)
    assert isinstance(output["confidence"], float)
    assert isinstance(output["probabilities"], dict)


def test_probabilities_sum_to_one_within_tolerance():
    features_df = ml_engine.prepare_features(_valid_input_payload())
    probabilities = ml_engine.predict_probabilities(features_df)
    total = sum(probabilities.values())

    assert pytest.approx(1.0, abs=1e-3) == total


def test_prepare_features_handles_missing_none_and_empty_values():
    payload = {
        "asset_type": "",
        "internet_exposed": None,
        "public_access": "",
        "identity_risk_score": None,
    }

    features_df = ml_engine.prepare_features(payload)

    assert len(features_df) == 1
    assert list(features_df.columns) == ml_engine.FEATURE_COLUMNS
    assert features_df.isna().sum().sum() == 0


def test_interpret_prediction_maps_encoded_label_to_string():
    classes = list(ml_engine.TARGET_ENCODER.classes_)
    encoded_index = classes.index("HIGH")

    label = ml_engine.interpret_prediction(encoded_index)
    assert label == "HIGH"
