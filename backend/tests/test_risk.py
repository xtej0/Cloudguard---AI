from app.services.risk_service import compute_risk_score


def test_compute_risk_score_smoke() -> None:
	result = compute_risk_score("Database Server")
	assert "risk_score" in result
	assert "risk_level" in result
