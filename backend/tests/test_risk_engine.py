from __future__ import annotations

import sys
import types

fake_neo4j_config = types.ModuleType("app.neo4j_config")
fake_neo4j_config.driver = object()
sys.modules.setdefault("app.neo4j_config", fake_neo4j_config)

import risk_engine


def test_compute_risk_score_is_clamped_between_0_and_100(monkeypatch):
	monkeypatch.setattr(
		risk_engine,
		"fetch_asset_properties",
		lambda _: {
			"vulnerability_severity": "critical",
			"exposure_weight": "public",
			"privilege_escalation_potential": "very_high",
			"asset_criticality": "critical",
			"labels": ["Server"],
		},
	)
	monkeypatch.setattr(risk_engine, "fetch_attack_paths", lambda _: 1000)
	monkeypatch.setattr(risk_engine, "fetch_shortest_attack_path_length", lambda _: -10)

	high = risk_engine.compute_risk_score("high-asset")
	assert 0.0 <= high["risk_score"] <= 100.0

	monkeypatch.setattr(
		risk_engine,
		"fetch_asset_properties",
		lambda _: {
			"vulnerability_severity": "none",
			"exposure_weight": "none",
			"privilege_escalation_potential": "none",
			"asset_criticality": "low",
			"labels": ["Server"],
		},
	)
	monkeypatch.setattr(risk_engine, "fetch_attack_paths", lambda _: 0)
	monkeypatch.setattr(risk_engine, "fetch_shortest_attack_path_length", lambda _: None)

	low = risk_engine.compute_risk_score("low-asset")
	assert 0.0 <= low["risk_score"] <= 100.0


def test_score_and_rank_query_results_returns_highest_risk_first():
	records = [
		{
			"asset_name": "db-server",
			"labels": ["Server"],
			"props": {
				"vulnerability_severity": "critical",
				"exposure_weight": "public",
				"privilege_escalation_potential": "very_high",
				"asset_criticality": "critical",
			},
			"attack_path_count": 10,
			"shortest_attack_path_length": 1,
			"relationships": [],
		},
		{
			"asset_name": "dev-laptop",
			"labels": ["Workstation"],
			"props": {
				"vulnerability_severity": "low",
				"exposure_weight": "private",
				"privilege_escalation_potential": "low",
				"asset_criticality": "low",
			},
			"attack_path_count": 0,
			"shortest_attack_path_length": 6,
			"relationships": [],
		},
	]

	ranked = risk_engine.score_and_rank_query_results(records, top_n=2)

	assert ranked[0]["asset_name"] == "db-server"
	assert ranked[0]["risk_score"] >= ranked[1]["risk_score"]


def test_rank_assets_respects_top_n_count(monkeypatch):
	monkeypatch.setattr(
		risk_engine,
		"compute_risk_score",
		lambda name: {
			"asset_name": name,
			"node_type": "Server",
			"risk_score": float(name.split("-")[-1]),
			"risk_level": "LOW",
			"factor_scores": {},
		},
	)
	monkeypatch.setattr(risk_engine, "fetch_asset_relationships", lambda _: [])

	assets = ["asset-10", "asset-50", "asset-30", "asset-70", "asset-20"]
	top = risk_engine.rank_assets(asset_names=assets, top_n=3)

	assert len(top) == 3
	assert [item["asset_name"] for item in top] == ["asset-70", "asset-50", "asset-30"]
