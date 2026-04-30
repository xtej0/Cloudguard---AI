# CloudGuard AI – Backend Architecture Documentation

## 1. Overview
CloudGuard AI backend is a FastAPI service that models cloud-attack movement and risk scoring over a Neo4j graph. The API provides three major capabilities implemented in code: (1) attack-path retrieval, (2) attack-risk summary for a source/target pair, and (3) per-asset and portfolio-level risk scoring.

The runtime entrypoint is `app/main.py`, which mounts a single router (`app/routes/attack_paths.py`) and exposes five security-focused GET endpoints plus a root health message endpoint. Neo4j connectivity is configured through `app/neo4j_config.py` using environment variables (`NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD`).

All route handlers return a unified response envelope (version, graph, risk, prediction, summary, mitigations), implemented by builder functions in `app/builders/response_builder.py` and typed by `app/schemas.py`.

## 2. Backend Module Layout and Responsibilities

| File | Responsibility | Key Interactions |
|---|---|---|
| `app/main.py` | FastAPI app initialization and router registration | Imports `router` from `app/routes/attack_paths.py` |
| `app/neo4j_config.py` | Creates shared Neo4j `driver`; provides `test_connection()` | Used by services for all Cypher execution |
| `app/routes/attack_paths.py` | Defines API endpoints: `/attack-path`, `/all-paths`, `/attack-risk-summary`, `/risk-score`, `/risk-score/{asset_name}` | Calls services and response builders |
| `app/services/attack_graph_service.py` | Graph queries (`shortestPath`, all paths, asset existence) + in-memory BFS helpers (`find_attack_paths`, `shortest_attack_path`) | Used by routes and attack-risk service |
| `app/services/risk_service.py` | Risk scoring engine (input collection, normalization, weighted scoring, ranking) | Called by routes and attack-risk service |
| `app/services/attack_risk_service.py` | Orchestrates shortest-path + target risk calculation into one summary payload | Uses `get_shortest_attack_path` and `calculate_risk_score` |
| `app/services/summary_service.py` | Builds user-facing summary messages and UTC timestamp | Used by response builders |
| `app/services/prediction_service.py` | Ranks graph-derived next targets using reachability, asset risk, and optional model context | Used by prediction and unified response builders |
| `app/services/mitigation_service.py` | Converts risk payloads into contextual mitigation-engine inputs | Uses `app/mitigation_engine.py` |
| `app/builders/response_builder.py` | Constructs unified response payloads for each endpoint use case | Uses summary/prediction/mitigation services and graph formatter |
| `app/utils/graph_formatter.py` | Converts path data to Cytoscape-style nodes/edges | Used by response builder graph sections |
| `app/schemas.py` | Pydantic response schema (`FinalResponse` and nested models) | Bound as `response_model` on route handlers |
| `app/models/graph_schema.py` | In-memory graph dataclasses/enums for algorithmic tests/utilities | Used by `attack_graph_service.py` BFS functions and tests |
| `seed_graph.py` | Seeds Neo4j with demo cloud assets and relationships | Supports local/dev graph state and integration tests |
| `tests/test_api.py` | API integration checks for root and risk endpoints | Uses FastAPI `TestClient` |
| `tests/test_attack_graph.py` | Unit tests for in-memory graph traversal logic | Validates BFS path discovery behavior |
| `tests/test_attack_risk.py` | API tests for `/attack-risk-summary` success, error, validation | Validates response envelope on summary endpoint |
| `tests/test_graph_seed.py` | Neo4j graph integrity checks after seeding | Verifies minimum node/relationship counts |
| `tests/test_neo4j.py` | Neo4j connection smoke test | Calls `test_connection()` |
| `tests/test_risk.py` | Risk scoring smoke test | Calls `compute_risk_score("Database Server")` |
| `tests/test_risk_engine.py` | Unit tests for score clamping, ranking order, top-N behavior | Monkeypatches data fetchers in risk service |

## 3. Neo4j Graph Schema
### 3.1 Node Labels in Seeded Graph (`seed_graph.py`)
- `Internet`
- `VM` (two instances: `Web Server VM`, `Application Server VM`)
- `Database` (`Database Server`)
- `Bucket` (`Storage Bucket`)
- `User`
- `IAMRole`

### 3.2 Relationship Types in Seeded Graph
- `EXPOSED_TO` (`Internet` → `Web Server VM`)
- `CONNECTS_TO` (`Web Server VM` → `Application Server VM` → `Database Server`)
- `HAS_ACCESS` (`User` → `IAM Role`)
- `STORES_DATA_IN` (`Database Server` → `Storage Bucket`)

### 3.3 Relationship/Type Vocabulary Also Present in Code
- `app/models/graph_schema.py` enum also includes `CAN_ASSUME_ROLE` (used by in-memory traversal tests, not seeded by `seed_graph.py`).
- Path queries in services use variable-length relationship patterns (`-[*]->`, `-[*1..6]->`) and therefore traverse any relationship type that exists in Neo4j.

### 3.4 Asset Properties (Observed in Seed + Risk Queries)
`seed_graph.py` assigns security-relevant properties per node, including:
- `name`
- `criticality`
- `vulnerability_severity`
- `exposure_level`
- `privilege_level`
- additional context fields by node type (for example `layer`, `engine`, `sensitivity`, `contains`)

`risk_service.py` reads and normalizes these fields (including aliases) during scoring:
- Vulnerability: `vulnerability_severity` or `severity`
- Exposure: `exposure_weight` or `exposure_level` or `internet_exposed`
- Privilege escalation: `privilege_escalation_potential` or `privilege_level`
- Criticality: `asset_criticality` or `criticality`
- Attack path metrics from Cypher path queries (`path_count`, `shortest_length`)

## 4. Attack Path Flow
### 4.1 `/attack-path` (shortest path)
1. Route handler `get_attack_path(start, target)` in `app/routes/attack_paths.py` receives query parameters.
2. Calls `get_shortest_attack_path(start, target)` in `app/services/attack_graph_service.py`:
   - Cypher: `MATCH p = shortestPath((a {name:$start})-[*]->(b {name:$target}))`
   - Returns ordered `nodes` (by `name`) and relationship type list.
3. Calls `get_asset_existence(start, target)` to distinguish invalid assets from no-path scenarios.
4. Builds envelope through `build_attack_path_response`:
   - `graph`: Cytoscape-style nodes/edges from path
   - `summary`: start/target/path length/status message/generated timestamp
   - `risk`: empty top-assets list for this endpoint

### 4.2 `/all-paths` (all directed paths)
1. Route handler `get_all_paths(start, target)`.
2. Calls `get_all_attack_paths(start, target)`:
   - Cypher: `MATCH p = (a {name:$start})-[*]->(b {name:$target})`
   - Returns every matched path with ordered nodes + relationship labels.
3. Calls `get_asset_existence(start, target)`.
4. `build_all_paths_response` aggregates unique nodes and edges from all path results and returns unified envelope with `summary.total_paths`.

### 4.3 `/attack-risk-summary` (path + risk)
1. Route handler `attack_risk_summary(start, target)`.
2. Calls `get_attack_risk_summary(start, target)` in `app/services/attack_risk_service.py`.
3. Service sequence:
   - Validate non-empty start/target.
   - Compute shortest path via `get_shortest_attack_path`.
   - Compute target risk via `calculate_risk_score(target)`.
   - Return combined payload: `attack_path` + `risk_analysis`.
4. Builder `build_attack_risk_response` transforms output into unified response envelope.
5. If no path or processing issue, service returns `{ "error": "No attack path found between given nodes" }` (or another explicit message); builder wraps it under `summary.error` while preserving standard top-level structure.

## 5. Risk Scoring Flow
### 5.1 Inputs Used
For each asset, `compute_risk_score(asset_name)` gathers:
- Asset properties from Neo4j (`fetch_asset_properties`)
- Number of attack paths from entrypoints (`fetch_attack_paths`):
  - Entry points constrained to nodes with label `Internet` or `User`
  - Path length constrained to 1..6 hops
- Shortest attack path length (`fetch_shortest_attack_path_length`)

### 5.2 Factor Normalization Logic
All factors are normalized to 0..1 using `_normalize_0_to_1`:
- `None` → default
- `bool` → `1.0`/`0.0`
- numeric `<=1` → clamped directly; numeric `>1` → divided by 10 and clamped
- string values mapped via factor-specific dictionaries

Derived factors:
- `vulnerability_factor` from severity map (`critical`=1.0, `high`=0.8, `medium`=0.5, `low`=0.2, `none`=0.0)
- `exposure_factor` from exposure/public/internal/private map
- `privilege_escalation_factor` from privilege map (`root`, `admin`, `write`, etc.)
- `criticality_factor` from criticality map
- `attack_paths_factor = min(path_count / 10.0, 1.0)`
- `shortest_path_factor = ((6 - shortest_length + 1) / 6)` clamped to 0..1 (or `0.0` if no path)

### 5.3 Weighted Score Calculation
`WEIGHTS` in `risk_service.py`:
- vulnerability severity: `0.25`
- exposure: `0.20`
- privilege escalation potential: `0.15`
- asset criticality: `0.15`
- attack paths: `0.15`
- shortest attack path length: `0.10`

Formula:
- `weighted_score = Σ(normalized_factor × weight)`
- `risk_score = round(clamp(weighted_score, 0, 1) * 100, 2)`

### 5.4 Risk Level Assignment
`_risk_level_from_score` thresholds:
- `CRITICAL` if score `>= 80`
- `HIGH` if score `>= 60`
- `MEDIUM` if score `>= 35`
- `LOW` otherwise

### 5.5 Ranking Flow
- `/risk-score` calls `get_top_asset_risk_scores()` → `get_all_asset_risk_scores()`.
- Assets are selected by `fetch_important_asset_names()` (excludes `Internet` and `User`, and filters by criticality/severity/exposure/connectivity; falls back to all named assets if needed).
- Results are sorted by descending `risk_score` before response.

## 6. API Endpoints

| Method | Route | Purpose | Parameters |
|---|---|---|---|
| `GET` | `/` | Health-style root message | None |
| `GET` | `/attack-path` | Shortest directed path between two named assets | Query: `start` (str), `target` (str) |
| `GET` | `/all-paths` | All directed paths between two named assets | Query: `start` (str), `target` (str) |
| `GET` | `/attack-risk-summary` | Combined shortest-path context and target risk analysis | Query: `start` (str), `target` (str) |
| `GET` | `/risk-score` | Risk-ranked list of important assets | None |
| `GET` | `/risk-score/{asset_name}` | Risk details for a single asset | Path: `asset_name` (str) |

### 6.1 Example Responses (Derived from Response Builders and Tests)

#### `GET /`
```json
{
  "message": "CloudGuard AI backend running"
}
```

#### `GET /attack-path?start=Internet&target=Database Server`
```json
{
  "version": "v1",
  "graph": {
    "nodes": [
      { "data": { "id": "Internet", "label": "Internet", "type": "asset" } },
      { "data": { "id": "Web Server VM", "label": "Web Server VM", "type": "asset" } },
      { "data": { "id": "Application Server VM", "label": "Application Server VM", "type": "asset" } },
      { "data": { "id": "Database Server", "label": "Database Server", "type": "asset" } }
    ],
    "edges": [
      { "data": { "source": "Internet", "target": "Web Server VM", "label": "EXPOSED_TO" } },
      { "data": { "source": "Web Server VM", "target": "Application Server VM", "label": "CONNECTS_TO" } },
      { "data": { "source": "Application Server VM", "target": "Database Server", "label": "CONNECTS_TO" } }
    ]
  },
  "risk": { "top_assets": [] },
  "prediction": { "next_targets": [] },
  "summary": {
    "start_asset": "Internet",
    "target_asset": "Database Server",
    "path_length": 4,
    "overall_risk_level": "UNKNOWN",
    "highest_risk": null,
    "message": "Attack path successfully found",
    "generated_at": "2026-03-23T12:00:00+00:00"
  },
  "mitigations": []
}
```

#### `GET /all-paths?start=Internet&target=Database Server`
```json
{
  "version": "v1",
  "graph": {
    "nodes": [
      { "data": { "id": "Internet", "label": "Internet", "type": "asset" } },
      { "data": { "id": "Web Server VM", "label": "Web Server VM", "type": "asset" } },
      { "data": { "id": "Application Server VM", "label": "Application Server VM", "type": "asset" } },
      { "data": { "id": "Database Server", "label": "Database Server", "type": "asset" } }
    ],
    "edges": [
      { "data": { "source": "Internet", "target": "Web Server VM", "label": "EXPOSED_TO" } },
      { "data": { "source": "Web Server VM", "target": "Application Server VM", "label": "CONNECTS_TO" } },
      { "data": { "source": "Application Server VM", "target": "Database Server", "label": "CONNECTS_TO" } }
    ]
  },
  "risk": { "top_assets": [] },
  "prediction": { "next_targets": [] },
  "summary": {
    "start_asset": "Internet",
    "target_asset": "Database Server",
    "total_paths": 1,
    "path_length": 4,
    "overall_risk_level": "UNKNOWN",
    "highest_risk": null,
    "message": "Attack path successfully found",
    "generated_at": "2026-03-23T12:00:00+00:00"
  },
  "mitigations": []
}
```

#### `GET /attack-risk-summary?start=Internet&target=Database Server`
```json
{
  "version": "v1",
  "graph": {
    "nodes": [
      { "data": { "id": "Internet", "label": "Internet", "type": "asset" } },
      { "data": { "id": "Web Server VM", "label": "Web Server VM", "type": "asset" } },
      { "data": { "id": "Application Server VM", "label": "Application Server VM", "type": "asset" } },
      { "data": { "id": "Database Server", "label": "Database Server", "type": "asset" } }
    ],
    "edges": [
      { "data": { "source": "Internet", "target": "Web Server VM", "label": "UNKNOWN" } },
      { "data": { "source": "Web Server VM", "target": "Application Server VM", "label": "UNKNOWN" } },
      { "data": { "source": "Application Server VM", "target": "Database Server", "label": "UNKNOWN" } }
    ]
  },
  "risk": {
    "top_assets": [
      {
        "asset_name": "Database Server",
        "risk_score": 0,
        "risk_level": "LOW",
        "explanation": "Database Server is assessed as LOW risk (0/100).",
        "contributing_factors": []
      }
    ]
  },
  "prediction": { "next_targets": [] },
  "summary": {
    "start_asset": "Internet",
    "target_asset": "Database Server",
    "path_length": 4,
    "overall_risk_level": "LOW",
    "highest_risk": "Database Server",
    "message": "Attack path successfully found",
    "generated_at": "2026-03-23T12:00:00+00:00"
  },
  "mitigations": []
}
```

#### `GET /attack-risk-summary?start=InvalidNode&target=Database Server` (no path/error case)
```json
{
  "version": "v1",
  "graph": { "nodes": [], "edges": [] },
  "risk": { "top_assets": [] },
  "prediction": { "next_targets": [] },
  "summary": {
    "error": "No attack path found between given nodes",
    "generated_at": "2026-03-23T12:00:00+00:00",
    "start_asset": "InvalidNode",
    "target_asset": "Database Server"
  },
  "mitigations": []
}
```

#### `GET /risk-score`
```json
{
  "version": "v1",
  "graph": { "nodes": [], "edges": [] },
  "risk": {
    "top_assets": [
      {
        "asset_name": "IAM Role",
        "risk_score": 63.0,
        "risk_level": "HIGH",
        "explanation": "IAM Role is assessed as HIGH risk (63.0/100). Key drivers: High vulnerability severity on this asset; Strong privilege-escalation potential; 1 distinct attack path(s) from likely entry points.",
        "contributing_factors": [
          "High vulnerability severity on this asset",
          "Strong privilege-escalation potential",
          "1 distinct attack path(s) from likely entry points",
          "Very short attack path (1 hops)"
        ],
        "attack_path_details": {
          "attack_path_count": 1,
          "shortest_attack_path_length": 1,
          "relationship_count": 1,
          "entrypoint_reachability": "reachable"
        }
      }
    ]
  },
  "prediction": { "next_targets": [] },
  "summary": {
    "highest_risk": "IAM Role",
    "overall_risk_level": "HIGH",
    "total_assets": 5,
    "generated_at": "2026-03-23T12:00:00+00:00"
  },
  "mitigations": []
}
```

#### `GET /risk-score/Database Server`
```json
{
  "version": "v1",
  "graph": { "nodes": [], "edges": [] },
  "risk": {
    "top_assets": [
      {
        "asset_name": "Database Server",
        "risk_score": 62.67,
        "risk_level": "HIGH",
        "attack_path_details": {
          "attack_path_count": 1,
          "shortest_attack_path_length": 3
        }
      }
    ]
  },
  "prediction": { "next_targets": [] },
  "summary": {
    "target_asset": "Database Server",
    "overall_risk_level": "HIGH",
    "generated_at": "2026-03-23T12:00:00+00:00"
  },
  "mitigations": []
}
```

## 7. Architecture Diagrams
### 7.1 Backend Request-Handling Flow
```text
Client
  |
  v
FastAPI (app/main.py)
  |
  v
Router (app/routes/attack_paths.py)
  |
  +--> Attack graph services (path queries)
  +--> Risk service (scoring + ranking)
  +--> Attack-risk service (orchestration)
           |
           v
       Neo4j driver/session (app/neo4j_config.py)
  |
  v
Response builders (app/builders/response_builder.py)
  |
  v
Unified API payload (version, graph, risk, prediction, summary, mitigations)
```

### 7.2 Attack Path Flow (`/attack-path` and `/all-paths`)
```text
GET /attack-path or /all-paths
  |
  v
Route handler reads query params: start, target
  |
  v
attack_graph_service query:
  - shortestPath query or all directed paths query
  - get_asset_existence(start, target)
  |
  v
response_builder builds:
  - graph nodes/edges (Cytoscape format)
  - summary message + metadata
  |
  v
FinalResponse JSON
```

### 7.3 Risk Scoring Flow (`/risk-score`)
```text
GET /risk-score
  |
  v
risk_service.get_all_asset_risk_scores()
  |
  +--> fetch_important_asset_names()
  +--> for each asset: compute_risk_score()
          |
          +--> fetch_asset_properties()
          +--> fetch_attack_paths()
          +--> fetch_shortest_attack_path_length()
          +--> normalize factors to 0..1
          +--> weighted score -> 0..100
          +--> assign risk level (LOW/MEDIUM/HIGH/CRITICAL)
  |
  v
Sort descending by risk_score
  |
  v
response_builder.build_risk_score_response()
  |
  v
FinalResponse JSON
```

## 8. Testing Strategy
The project includes both API-level and unit-level tests under `tests/`:

- **API integration tests (`test_api.py`, `test_attack_risk.py`)**
  - Validate status codes and response envelope for `/`, `/risk-score`, `/risk-score/{asset_name}`, `/attack-risk-summary`.
  - Confirm required fields exist (for example `risk.top_assets`, `summary.generated_at`).
  - Confirm `/risk-score` output is sorted descending by `risk_score`.
  - Confirm `/attack-risk-summary` handles missing params (`422`) and no-path conditions (`summary.error`).

- **Graph traversal unit tests (`test_attack_graph.py`)**
  - Test in-memory BFS helpers (`find_attack_paths`, `shortest_attack_path`) against a fixture graph.
  - Cover positive path discovery and edge cases (missing start node, empty critical-type set).

- **Risk engine tests (`test_risk.py`, `test_risk_engine.py`)**
  - Smoke-test risk computation result shape.
  - Verify score clamping in valid range `0..100` using monkeypatched extreme inputs.
  - Verify ranking order and top-N truncation logic.

- **Neo4j/seed integrity tests (`test_neo4j.py`, `test_graph_seed.py`)**
  - Validate Neo4j connectivity message.
  - Validate seeded graph has at least expected counts (`>=7` nodes, `>=5` relationships).

## 9. Current Limitations
Based on current implementation:

1. **Next-target ranking is hybrid intelligence**
   - `/predict-compromise` uses the trained ML model for risk-level prediction.
   - `predict_next_targets()` ranks likely next targets from graph reachability, ranked asset risk, and model context. It is not a separate per-target ML classifier.

2. **Risk scoring is deterministic rule-based logic**
   - `/risk-score` uses fixed weighted graph/security factors in `risk_service.py`.
   - The ML model predicts `risk_level` from synthetic posture features; it does not replace deterministic graph risk scoring.

3. **Seeded graph is a compact demo topology**
   - `seed_graph.py` inserts a small static environment (Internet/VM/Database/Bucket/User/IAMRole).

4. **Path query breadth can grow quickly**
   - `/all-paths` uses variable-length directed path matching without explicit hop cap in that endpoint query.

5. **Error semantics are envelope-based**
   - Service-level errors for attack-risk summary are represented in `summary.error` instead of HTTP 4xx for domain errors like no-path.

6. **Runtime depends on external Neo4j environment variables**
   - Missing Neo4j configuration prevents successful DB-backed endpoint behavior.

## 10. Conclusion
The current CloudGuard AI backend is a well-structured FastAPI + Neo4j service for graph-based attack-path analysis and deterministic risk scoring. Core API routes, response standardization, and scoring/ranking logic are implemented and test-covered at unit and integration levels.

The architecture is suitable for iterative expansion: the response envelope already reserves extension points (`prediction`, `mitigations`), and the service separation supports incremental upgrades (for example, richer schema, capped path search policies, and ML-assisted prediction) without changing the API contract.
