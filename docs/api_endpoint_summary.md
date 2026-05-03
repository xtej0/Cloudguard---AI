# CloudGuard AI API Endpoint Summary

Base URL for local development:

```text
http://localhost:8000
```

## Endpoint Table

| Method | Endpoint | Input | Response Model | Purpose |
|---|---|---|---|---|
| `GET` | `/` | none | `RootResponse` | Confirms the backend is reachable. |
| `GET` | `/health` | none | `HealthResponse` | Health/readiness check. |
| `GET` | `/attack-path` | query: `start`, `target` | `FinalResponse` | Returns the shortest Neo4j attack path between two assets. |
| `GET` | `/all-paths` | query: `start`, `target` | `FinalResponse` | Returns all directed Neo4j paths between two assets, aggregated into Cytoscape graph format. |
| `GET` | `/attack-risk-summary` | query: `start`, `target` | `FinalResponse` | Combines shortest path, target risk, predictions, and mitigations. |
| `GET` | `/risk-score` | none | `FinalResponse` | Returns important assets ranked by risk score. |
| `GET` | `/risk-score/{asset_name}` | path: `asset_name` | `FinalResponse` | Returns risk details for one asset. |
| `POST` | `/predict-compromise` | JSON posture features | `PredictionResponse` | Runs ML risk-level prediction and adds next-target ranking. |
| `GET` | `/asset-analysis/{asset_name}` | path: `asset_name` | `IntegratedAnalysisResponse` | Returns integrated risk, candidate next hops, predicted target, feature importance, and mitigations. |

## Unified Response Endpoints

These endpoints use the same top-level envelope:

- `/attack-path`
- `/all-paths`
- `/attack-risk-summary`
- `/risk-score`
- `/risk-score/{asset_name}`

Envelope:

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

## Example Requests

Shortest attack path:

```powershell
Invoke-RestMethod "http://localhost:8000/attack-path?start=Internet&target=Database%20Server"
```

All attack paths:

```powershell
Invoke-RestMethod "http://localhost:8000/all-paths?start=Internet&target=Database%20Server"
```

Attack-risk summary:

```powershell
Invoke-RestMethod "http://localhost:8000/attack-risk-summary?start=Internet&target=Database%20Server"
```

Risk ranking:

```powershell
Invoke-RestMethod "http://localhost:8000/risk-score"
```

Single asset:

```powershell
Invoke-RestMethod "http://localhost:8000/risk-score/Database%20Server"
```

Integrated analysis:

```powershell
Invoke-RestMethod "http://localhost:8000/asset-analysis/Web%20Server%20VM"
```

ML prediction:

```powershell
$body = @{
  asset_type = "Database"
  internet_exposed = 1
  public_access = 1
  has_critical_data = 1
  weak_iam = 1
  lateral_movement_possible = 1
  privilege_escalation_possible = 1
  open_port_count = 14
  vulnerability_count = 22
  critical_vulnerability_count = 6
  misconfiguration_count = 9
  attack_path_count = 4
  shortest_path_length = 2
  exposure_score = 82
  identity_risk_score = 73
  network_risk_score = 69
} | ConvertTo-Json

Invoke-RestMethod "http://localhost:8000/predict-compromise" -Method Post -ContentType "application/json" -Body $body
```

## Error Semantics

- Invalid asset-name characters return HTTP 400.
- Missing required query parameters return HTTP 422.
- Neo4j connection failures return HTTP 500.
- No-path domain cases are represented inside the unified response with `summary.error` or a no-path summary message, depending on endpoint.

## Relationship Labels

Path endpoints preserve Neo4j relationship labels in `graph.edges[*].data.label`, for example:

- `EXPOSED_TO`
- `CONNECTS_TO`
- `HAS_ACCESS`
- `STORES_DATA_IN`

`UNKNOWN` is only a defensive formatter fallback when path nodes are supplied without a matching relationship list.
