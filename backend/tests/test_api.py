from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_get_root_returns_200_and_message_exists():
	response = client.get("/")

	assert response.status_code == 200
	data = response.json()
	assert "message" in data


def test_get_risk_score_returns_expected_top_assets_shape():
	response = client.get("/risk-score")

	assert response.status_code == 200
	data = response.json()

	assert "top_assets" in data
	assert isinstance(data["top_assets"], list)
	assert data["top_assets"]

	required_keys = {
		"asset_name",
		"risk_score",
		"risk_level",
		"explanation",
		"contributing_factors",
		"attack_path_details",
	}

	for item in data["top_assets"]:
		assert required_keys.issubset(item.keys())


def test_get_risk_score_results_sorted_by_descending_risk_score():
	response = client.get("/risk-score")

	assert response.status_code == 200
	data = response.json()
	top_assets = data["top_assets"]

	risk_scores = [item["risk_score"] for item in top_assets]
	assert risk_scores == sorted(risk_scores, reverse=True)


def test_get_risk_score_for_database_server_returns_expected_fields():
	response = client.get("/risk-score/Database Server")

	assert response.status_code == 200
	data = response.json()

	assert "asset_name" in data
	assert "risk_score" in data
	assert "risk_level" in data
	assert "attack_path_details" in data
