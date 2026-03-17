from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_attack_risk_summary_success():
    response = client.get(
        "/attack-risk-summary",
        params={
            "start": "Internet",
            "target": "Database Server"
        }
    )

    assert response.status_code == 200

    data = response.json()

    # Core structure checks
    assert "attack_path" in data
    assert "risk_analysis" in data

    # Attack path checks
    assert "nodes" in data["attack_path"]
    assert isinstance(data["attack_path"]["nodes"], list)
    assert len(data["attack_path"]["nodes"]) > 0

    # Risk checks
    assert "risk_score" in data["risk_analysis"]
    assert "risk_level" in data["risk_analysis"]


def test_attack_risk_summary_no_path():
    response = client.get(
        "/attack-risk-summary",
        params={
            "start": "InvalidNode",
            "target": "Database Server"
        }
    )

    data = response.json()

    assert "error" in data


def test_attack_risk_summary_missing_params():
    response = client.get("/attack-risk-summary")

    # FastAPI will return validation error (422)
    assert response.status_code == 422