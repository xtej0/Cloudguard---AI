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

	assert "risk" in data
	assert "top_assets" in data["risk"]
	assert isinstance(data["risk"]["top_assets"], list)
	assert data["risk"]["top_assets"]

	required_keys = {
		"asset_name",
		"risk_score",
		"risk_level",
		"explanation",
		"contributing_factors",
		"attack_path_details",
	}

	for item in data["risk"]["top_assets"]:
		assert required_keys.issubset(item.keys())


def test_get_risk_score_results_sorted_by_descending_risk_score():
	response = client.get("/risk-score")

	assert response.status_code == 200
	data = response.json()
	top_assets = data["risk"]["top_assets"]

	risk_scores = [item["risk_score"] for item in top_assets]
	assert risk_scores == sorted(risk_scores, reverse=True)


def test_get_risk_score_for_database_server_returns_expected_fields():
	response = client.get("/risk-score/Database Server")

	assert response.status_code == 200
	data = response.json()

	assert "risk" in data
	assert "top_assets" in data["risk"]
	assert len(data["risk"]["top_assets"]) > 0

	asset_data = data["risk"]["top_assets"][0]
	assert "asset_name" in asset_data
	assert "risk_score" in asset_data
	assert "risk_level" in asset_data
	assert "attack_path_details" in asset_data

	assert "summary" in data
	assert "target_asset" in data["summary"]
	assert "overall_risk_level" in data["summary"]
	assert "generated_at" in data["summary"]
