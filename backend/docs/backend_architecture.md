# CloudGuard AI Backend Architecture

## Overview

CloudGuard AI is a FastAPI backend for cloud attack-path analysis, risk scoring, next-target prediction, and mitigation guidance over a Neo4j asset graph.

The runtime entrypoint is `app/main.py`. It creates the FastAPI app, enables CORS, adds request timing logs, and mounts these routers:

- `app/routes/attack_paths.py`: `/attack-path`, `/all-paths`, `/attack-risk-summary`, `/risk-score`, `/risk-score/{asset_name}`
- `app/routes/prediction.py`: `/predict-compromise`
- `app/routes/integrated_analysis.py`: `/asset-analysis/{asset_name}`

All main analysis endpoints return a unified response envelope typed by `app/schemas/__init__.py` and built by `app/builders/response_builder.py`:

```json
{
  "version": "v1",
  "graph": { "nodes": [], "edges": [] },
  "risk": { "top_assets": [] },
  "prediction": { "next_targets": [] },
  "summary": {},
  "mitigations": []
}
```

## Module Map

| File | Responsibility |
|---|---|
| `app/main.py` | FastAPI app setup, CORS, request timing, router registration, `/`, `/health` |
| `app/neo4j_config.py` | Shared Neo4j driver configured by `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD` |
| `app/routes/attack_paths.py` | Validates asset names, calls path/risk services, maps failures to HTTP errors or unified responses |
| `app/routes/prediction.py` | Validates prediction requests and returns ranked next-target candidates |
| `app/routes/integrated_analysis.py` | Exposes one-asset analysis with risk, candidates, prediction summary, and mitigations |
| `app/services/attack_graph_service.py` | Neo4j path queries and in-memory graph traversal helpers |
| `app/services/attack_risk_service.py` | Combines shortest path and target risk analysis |
| `app/services/risk_service.py` | Fetches asset properties and computes weighted risk scores |
| `app/services/prediction_service.py` | Ranks next targets using graph reachability, risk context, and model-informed fallback context |
| `app/services/mitigation_service.py` | Builds structured mitigation recommendations through `app/mitigation_engine.py` |
| `app/ml_engine.py` | Loads the trained model and runs compromise prediction |
| `app/integrated_analysis.py` | Builds candidate features, ranks reachable compromise candidates, and produces integrated analysis |
| `app/builders/response_builder.py` | Converts service output into the unified API response |
| `app/utils/graph_formatter.py` | Converts path node/relationship lists into Cytoscape node/edge objects |
| `app/schemas/__init__.py` | Pydantic schemas for unified API responses |
| `app/schemas/prediction.py` | Pydantic schemas for prediction requests/responses |
| `app/schemas/integrated_analysis.py` | Pydantic schemas for integrated analysis responses |

## Graph Model

Seeded local data includes assets such as `Internet`, `Web Server VM`, `Application Server VM`, `Database Server`, `Storage Bucket`, `IAM Role`, and `User`.

Seeded relationship labels include:

- `EXPOSED_TO`: `Internet` -> `Web Server VM`
- `CONNECTS_TO`: `Web Server VM` -> `Application Server VM` -> `Database Server`
- `HAS_ACCESS`: `User` -> `IAM Role`
- `STORES_DATA_IN`: `Database Server` -> `Storage Bucket`

The path queries preserve Neo4j relationship types. Response builders pass those labels through to Cytoscape edges. `UNKNOWN` is only a formatter fallback when a caller supplies fewer relationship labels than path edges.

## Endpoint Behavior

### `/attack-path`

`app/routes/attack_paths.py` validates `start` and `target`, checks asset existence with `get_asset_existence()`, then calls `get_shortest_attack_path(start, target)`.

The service runs a Neo4j shortest-path query and returns:

```json
{
  "nodes": ["Internet", "Web Server VM", "Application Server VM", "Database Server"],
  "relationships": ["EXPOSED_TO", "CONNECTS_TO", "CONNECTS_TO"],
  "path_length": 4
}
```

The route builds the final envelope with `build_attack_path_response()`. If Neo4j returns no path, the route returns an empty graph through the same builder and uses asset-existence flags to produce an accurate summary message.

### `/all-paths`

`/all-paths` validates assets, checks existence, then calls `get_all_attack_paths(start, target)`.

The response builder aggregates unique nodes and relationship-preserving edges from every returned path and sets `summary.total_paths`.

### `/attack-risk-summary`

`/attack-risk-summary` calls `get_attack_risk_summary(start, target)`, which combines:

- shortest-path data from `get_shortest_attack_path()`
- target risk from `calculate_risk_score()`

`build_attack_risk_response()` preserves the shortest-path relationship labels in `graph.edges`, includes the target risk item in `risk.top_assets`, returns next-target predictions, and returns structured mitigation objects.

No-path domain errors stay inside the unified envelope under `summary.error`; unexpected database/runtime errors become HTTP 500 responses.

### `/risk-score` and `/risk-score/{asset_name}`

`/risk-score` ranks important assets by weighted risk score. `/risk-score/{asset_name}` returns one asset's risk details. Both endpoints include contextual predictions and structured mitigations when enough risk context is available.

### `/predict-compromise`

The prediction endpoint uses `app/services/prediction_service.py`. Ranking combines graph reachability from seeded/requested nodes, risk signals, and model-informed fallback context. Results are sorted by probability and capped to the top candidates.

### `/asset-analysis/{asset_name}`

Integrated analysis builds candidate features for reachable assets, calls `predict_compromise()`, combines model confidence with graph/risk scores, and returns:

- selected asset risk context
- candidate target rankings
- primary predicted next target
- structured mitigations from `generate_mitigations()`

Debug trace printing is disabled by default. Set `CLOUDGUARD_DEBUG=true` to enable integrated-analysis debug logs.

## Risk Scoring

`app/services/risk_service.py` computes deterministic weighted risk from:

- vulnerability severity
- exposure
- privilege escalation potential
- asset criticality
- attack path count
- shortest attack path length

Scores are normalized to `0..100` and mapped to `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.

## Response Construction

`app/builders/response_builder.py` is the source of truth for unified response shape. It:

- converts graph data to Cytoscape-compatible `{ data: ... }` objects
- preserves relationship labels supplied by graph services
- includes predictions under `prediction.next_targets`
- includes structured mitigation objects with `title`, `recommendation`, `severity`, `priority`, and `reason`
- keeps error payloads schema-compatible through `summary.error`

## Tests

Tests under `backend/tests/` cover API response shape, route/service behavior, risk scoring, prediction output, integrated analysis, mitigation generation, graph traversal, seed integrity, and Neo4j connection smoke checks.
