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
    assert "version" in data
    assert "graph" in data
    assert "risk" in data
    assert "summary" in data
    assert "prediction" in data
    assert "mitigations" in data

    # Graph checks
    assert "nodes" in data["graph"]
    assert isinstance(data["graph"]["nodes"], list)
    assert len(data["graph"]["nodes"]) > 0
    assert "edges" in data["graph"]

    # Risk checks
    assert "top_assets" in data["risk"]

    # Summary checks
    assert "generated_at" in data["summary"]
    assert "overall_risk_level" in data["summary"]
    assert "highest_risk" in data["summary"]


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