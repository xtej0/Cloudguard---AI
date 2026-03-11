"""Risk scoring engine backed by Neo4j data for CloudGuard AI."""

from __future__ import annotations

from typing import Any, Dict

from app.neo4j_config import driver


WEIGHTS: Dict[str, float] = {
	"vulnerability_severity": 0.25,
	"exposure_weight": 0.20,
	"privilege_escalation_potential": 0.15,
	"asset_criticality": 0.15,
	"attack_paths": 0.15,
	"shortest_attack_path_length": 0.10,
}


def _normalize_0_to_1(value: Any, mapping: Dict[str, float], default: float = 0.0) -> float:
	"""Normalize string/number factor values into a 0..1 score."""
	if value is None:
		return default

	if isinstance(value, bool):
		return 1.0 if value else 0.0

	if isinstance(value, (int, float)):
		# Accept either 0..1 or 0..10 style input.
		if value <= 1:
			return max(0.0, min(float(value), 1.0))
		return max(0.0, min(float(value) / 10.0, 1.0))

	key = str(value).strip().lower()
	return mapping.get(key, default)


def fetch_attack_paths(asset_name: str) -> int:
	"""Return the number of graph attack paths that lead to an asset."""
	query = """
	MATCH p = (start)-[*1..6]->(asset {name: $asset_name})
	WHERE start:Internet OR start:User
	RETURN count(DISTINCT p) AS path_count
	"""

	with driver.session() as session:
		result = session.run(query, asset_name=asset_name)
		record = result.single()

	if not record:
		return 0

	return int(record.get("path_count", 0) or 0)


def fetch_shortest_attack_path_length(asset_name: str) -> int | None:
	"""Return shortest path length from any EntryPoint to the asset, if found."""
	query = """
	MATCH p = (start)-[*1..6]->(asset {name: $asset_name})
	WHERE start:Internet OR start:User
	RETURN min(length(p)) AS shortest_length
	"""

	with driver.session() as session:
		result = session.run(query, asset_name=asset_name)
		record = result.single()

	if not record:
		return None

	shortest_length = record.get("shortest_length")
	if shortest_length is None:
		return None

	return int(shortest_length)


def fetch_asset_properties(asset_name: str) -> Dict[str, Any]:
	"""Fetch a single asset node's properties from Neo4j by name."""
	query = """
	MATCH (asset {name: $asset_name})
	RETURN properties(asset) AS props, labels(asset) AS labels
	LIMIT 1
	"""

	with driver.session() as session:
		result = session.run(query, asset_name=asset_name)
		record = result.single()

	if not record:
		return {}

	props = dict(record.get("props") or {})
	props["labels"] = record.get("labels") or []
	return props


def fetch_all_asset_names() -> list[str]:
	"""Return names of all named asset nodes in the graph."""
	query = """
	MATCH (asset)
	WHERE asset.name IS NOT NULL
	RETURN DISTINCT asset.name AS name
	"""

	with driver.session() as session:
		result = session.run(query)
		return [str(record["name"]) for record in result if record["name"]]


def fetch_asset_relationships(asset_name: str) -> list[Dict[str, Any]]:
	"""Return relationships connected to an asset node (up to 50)."""
	query = """
	MATCH (asset {name: $asset_name})-[r]-(neighbor)
	RETURN type(r) AS rel_type,
	       neighbor.name AS neighbor_name,
	       labels(neighbor) AS neighbor_labels,
	       CASE WHEN startNode(r) = asset THEN 'outgoing' ELSE 'incoming' END AS direction
	LIMIT 50
	"""

	with driver.session() as session:
		result = session.run(query, asset_name=asset_name)
		return [
			{
				"type": record["rel_type"],
				"direction": record["direction"],
				"neighbor": record["neighbor_name"],
				"neighbor_labels": list(record["neighbor_labels"] or []),
			}
			for record in result
		]


def compute_risk_score(asset_name: str) -> Dict[str, Any]:
	"""Compute and return weighted risk score details for an asset."""
	asset_props = fetch_asset_properties(asset_name)
	attack_path_count = fetch_attack_paths(asset_name)
	shortest_attack_path_length = fetch_shortest_attack_path_length(asset_name)

	vulnerability_factor = _normalize_0_to_1(
		asset_props.get("vulnerability_severity", asset_props.get("severity")),
		{
			"critical": 1.0,
			"high": 0.8,
			"medium": 0.5,
			"low": 0.2,
			"none": 0.0,
		},
		default=0.0,
	)

	exposure_raw = asset_props.get(
		"exposure_weight",
		asset_props.get("exposure_level", asset_props.get("internet_exposed", False)),
	)
	exposure_factor = _normalize_0_to_1(
		exposure_raw,
		{
			"internet_exposed": 1.0,
			"public": 1.0,
			"external": 0.8,
			"internal": 0.3,
			"private": 0.1,
			"none": 0.0,
			"true": 1.0,
			"false": 0.0,
		},
		default=0.0,
	)

	privilege_escalation_factor = _normalize_0_to_1(
		asset_props.get("privilege_escalation_potential", asset_props.get("privilege_level")),
		{
			"very_high": 1.0,
			"high": 0.8,
			"medium": 0.5,
			"low": 0.2,
			"none": 0.0,
			"root": 1.0,
			"admin": 0.9,
			"write": 0.7,
			"read": 0.3,
		},
		default=0.0,
	)

	criticality_factor = _normalize_0_to_1(
		asset_props.get("asset_criticality", asset_props.get("criticality")),
		{
			"critical": 1.0,
			"high": 0.8,
			"medium": 0.5,
			"low": 0.2,
			"noncritical": 0.1,
		},
		default=0.3,
	)

	# Cap attack-path impact to avoid unbounded growth dominating the score.
	attack_paths_factor = min(attack_path_count / 10.0, 1.0)

	# Shorter attack paths imply easier exploitation; no path means no contribution.
	if shortest_attack_path_length is None:
		shortest_path_factor = 0.0
	else:
		max_hops = 6.0
		shortest_path_factor = max(0.0, min((max_hops - float(shortest_attack_path_length) + 1.0) / max_hops, 1.0))

	weighted_score = (
		vulnerability_factor * WEIGHTS["vulnerability_severity"]
		+ exposure_factor * WEIGHTS["exposure_weight"]
		+ privilege_escalation_factor * WEIGHTS["privilege_escalation_potential"]
		+ criticality_factor * WEIGHTS["asset_criticality"]
		+ attack_paths_factor * WEIGHTS["attack_paths"]
		+ shortest_path_factor * WEIGHTS["shortest_attack_path_length"]
	)

	# Clamp to [0, 100]; the multiplication by 100 is exact so no float can exceed 100.
	risk_score = round(max(0.0, min(weighted_score, 1.0)) * 100.0, 2)

	labels = asset_props.get("labels") or []
	_GENERIC = {"Asset", "Node", "Resource"}
	node_type = next((lbl for lbl in labels if lbl not in _GENERIC), labels[0] if labels else "Unknown")

	return {
		"asset_name": asset_name,
		"node_type": node_type,
		"risk_score": risk_score,
		"risk_level": (
			"CRITICAL"
			if risk_score >= 80
			else "HIGH"
			if risk_score >= 60
			else "MEDIUM"
			if risk_score >= 35
			else "LOW"
		),
		"weights": dict(WEIGHTS),
		"factor_scores": {
			"vulnerability_severity": round(vulnerability_factor, 3),
			"exposure_weight": round(exposure_factor, 3),
			"privilege_escalation_potential": round(privilege_escalation_factor, 3),
			"asset_criticality": round(criticality_factor, 3),
			"attack_paths": round(attack_paths_factor, 3),
			"shortest_attack_path_length": round(shortest_path_factor, 3),
		},
		"raw_inputs": {
			"attack_path_count": attack_path_count,
			"shortest_attack_path_length": shortest_attack_path_length,
			"asset_properties": asset_props,
		},
	}


def rank_assets(
	asset_names: list[str] | None = None,
	top_n: int = 10,
) -> list[Dict[str, Any]]:
	"""Score and rank assets by risk score, returning the top_n highest-risk assets.

	Args:
		asset_names: Explicit list of asset names to evaluate. When ``None`` all
			named nodes in the graph are discovered automatically.
		top_n: Maximum number of assets to return, sorted by risk_score descending.

	Returns:
		List of dicts, each containing asset_name, node_type, risk_score,
		risk_level, relationships, and factor_scores.
	"""
	if asset_names is None:
		asset_names = fetch_all_asset_names()

	scored: list[Dict[str, Any]] = []
	for name in asset_names:
		result = compute_risk_score(name)
		relationships = fetch_asset_relationships(name)
		scored.append(
			{
				"asset_name": result["asset_name"],
				"node_type": result["node_type"],
				"risk_score": result["risk_score"],
				"risk_level": result["risk_level"],
				"relationships": relationships,
				"factor_scores": result["factor_scores"],
			}
		)

	scored.sort(key=lambda x: x["risk_score"], reverse=True)
	return scored[:top_n]


# ---------------------------------------------------------------------------
# Offline ranking — works on already-fetched Neo4j records
# ---------------------------------------------------------------------------

def score_and_rank_query_results(
	records: list[Dict[str, Any]],
	top_n: int = 10,
) -> list[Dict[str, Any]]:
	"""Score, normalize, and rank a list of pre-fetched Neo4j asset records.

	Accepts the raw row structure returned by queries such as::

		MATCH (a)
		WHERE a.name IS NOT NULL
		OPTIONAL MATCH (a)-[r]-(n)
		RETURN
		    a.name            AS asset_name,
		    labels(a)         AS labels,
		    properties(a)     AS props,
		    collect({
		        type:      type(r),
		        neighbor:  n.name,
		        neighbor_labels: labels(n),
		        direction: CASE WHEN startNode(r) = a THEN 'outgoing' ELSE 'incoming' END
		    }) AS relationships,
		    // pre-aggregated attack-path counts can be included as optional fields:
		    a.attack_path_count         AS attack_path_count,
		    a.shortest_attack_path_length AS shortest_attack_path_length

	Each element of *records* must be a plain ``dict``; Neo4j ``Record``
	objects are also accepted because they support ``[]`` access.

	Args:
		records: Iterable of dicts/Records from a Neo4j query result.
		top_n:   Maximum number of assets to return, highest risk first.

	Returns:
		List of dicts sorted by ``risk_score`` descending, each containing:
		``asset_name``, ``node_type``, ``risk_score``, ``risk_level``,
		``relationships``, and ``factor_scores``.
	"""
	_GENERIC = {"Asset", "Node", "Resource"}
	scored: list[Dict[str, Any]] = []

	for rec in records:
		props: Dict[str, Any] = dict(rec.get("props") or {})
		labels: list[str] = list(rec.get("labels") or [])
		asset_name: str = str(rec.get("asset_name") or props.get("name", ""))

		# ── factor scores ────────────────────────────────────────────────────
		vulnerability_factor = _normalize_0_to_1(
			props.get("vulnerability_severity", props.get("severity")),
			{"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "none": 0.0},
			default=0.0,
		)

		exposure_raw = props.get(
			"exposure_weight",
			props.get("exposure_level", props.get("internet_exposed", False)),
		)
		exposure_factor = _normalize_0_to_1(
			exposure_raw,
			{
				"internet_exposed": 1.0, "public": 1.0, "external": 0.8,
				"internal": 0.3, "private": 0.1, "none": 0.0,
				"true": 1.0, "false": 0.0,
			},
			default=0.0,
		)

		privilege_escalation_factor = _normalize_0_to_1(
			props.get("privilege_escalation_potential", props.get("privilege_level")),
			{
				"very_high": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "none": 0.0,
				"root": 1.0, "admin": 0.9, "write": 0.7, "read": 0.3,
			},
			default=0.0,
		)

		criticality_factor = _normalize_0_to_1(
			props.get("asset_criticality", props.get("criticality")),
			{"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "noncritical": 0.1},
			default=0.3,
		)

		_apc = rec.get("attack_path_count")
		if _apc is None:
			_apc = props.get("attack_path_count")
		attack_path_count = int(_apc or 0)
		attack_paths_factor = min(attack_path_count / 10.0, 1.0)

		raw_shortest = rec.get("shortest_attack_path_length")
		if raw_shortest is None:
			raw_shortest = props.get("shortest_attack_path_length")
		if raw_shortest is None:
			shortest_path_factor = 0.0
		else:
			max_hops = 6.0
			shortest_path_factor = max(
				0.0,
				min((max_hops - float(raw_shortest) + 1.0) / max_hops, 1.0),
			)

		# ── weighted sum → 0-100 score ────────────────────────────────────────
		weighted_score = (
			vulnerability_factor          * WEIGHTS["vulnerability_severity"]
			+ exposure_factor             * WEIGHTS["exposure_weight"]
			+ privilege_escalation_factor * WEIGHTS["privilege_escalation_potential"]
			+ criticality_factor          * WEIGHTS["asset_criticality"]
			+ attack_paths_factor         * WEIGHTS["attack_paths"]
			+ shortest_path_factor        * WEIGHTS["shortest_attack_path_length"]
		)
		risk_score = round(max(0.0, min(weighted_score, 1.0)) * 100.0, 2)

		risk_level = (
			"CRITICAL" if risk_score >= 80
			else "HIGH"   if risk_score >= 60
			else "MEDIUM" if risk_score >= 35
			else "LOW"
		)

		node_type = next(
			(lbl for lbl in labels if lbl not in _GENERIC),
			labels[0] if labels else "Unknown",
		)

		# ── normalise relationship records  ──────────────────────────────────
		raw_rels = rec.get("relationships") or []
		relationships = [
			{
				"type":            str(r.get("type", "")),
				"direction":       str(r.get("direction", "")),
				"neighbor":        r.get("neighbor"),
				"neighbor_labels": list(r.get("neighbor_labels") or []),
			}
			for r in raw_rels
			if r and r.get("type")  # skip null placeholders from OPTIONAL MATCH
		]

		scored.append(
			{
				"asset_name":   asset_name,
				"node_type":    node_type,
				"risk_score":   risk_score,
				"risk_level":   risk_level,
				"relationships": relationships,
				"factor_scores": {
					"vulnerability_severity":        round(vulnerability_factor, 3),
					"exposure_weight":               round(exposure_factor, 3),
					"privilege_escalation_potential": round(privilege_escalation_factor, 3),
					"asset_criticality":             round(criticality_factor, 3),
					"attack_paths":                  round(attack_paths_factor, 3),
					"shortest_attack_path_length":   round(shortest_path_factor, 3),
				},
			}
		)

	scored.sort(key=lambda x: x["risk_score"], reverse=True)
	return scored[:top_n]
