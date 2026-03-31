from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def _valid_payload() -> dict:
    return {
        "asset_type": "Database Server",
        "internet_exposed": 1,
        "public_access": 1,
        "has_critical_data": 1,
        "weak_iam": 1,
        "lateral_movement_possible": 1,
        "privilege_escalation_possible": 1,
        "open_port_count": 14,
        "vulnerability_count": 22,
        "critical_vulnerability_count": 6,
        "misconfiguration_count": 9,
        "attack_path_count": 4,
        "shortest_path_length": 2,
        "exposure_score": 0.82,
        "identity_risk_score": 0.73,
        "network_risk_score": 0.69,
    }


def test_prediction_endpoint_success():
    response = client.post("/predict-compromise", json=_valid_payload())

    assert response.status_code == 200
    data = response.json()
    assert "predicted_label" in data
    assert "confidence" in data
    assert "probabilities" in data


def test_prediction_validation_error():
    response = client.post("/predict-compromise", json={})

    assert response.status_code == 422


def test_prediction_output_types():
    response = client.post("/predict-compromise", json=_valid_payload())

    assert response.status_code == 200
    data = response.json()

    assert isinstance(data["confidence"], float)
    assert isinstance(data["probabilities"], dict)
    assert isinstance(data["predicted_label"], str)


def test_feature_importance_structure():
    response = client.post("/predict-compromise", json=_valid_payload())

    assert response.status_code == 200
    data = response.json()

    assert "feature_importance" in data
    assert isinstance(data["feature_importance"], list)

    if data["feature_importance"]:
        first_item = data["feature_importance"][0]

        assert "feature" in first_item
        assert "impact" in first_item
        assert "direction" in first_item

        assert isinstance(first_item["feature"], str)
        assert isinstance(first_item["impact"], float)
        assert first_item["direction"] in {"increase", "decrease"}
