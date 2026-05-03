# CloudGuard AI Unified Response Structure

## Contract

The main backend analysis endpoints return the same top-level JSON envelope:

```json
{
  "version": "v1",
  "graph": {
    "nodes": [],
    "edges": []
  },
  "risk": {
    "top_assets": []
  },
  "prediction": {
    "next_targets": []
  },
  "summary": {},
  "mitigations": []
}
```

The envelope is typed by `app/schemas/__init__.py` as `FinalResponse`.

## Endpoints

| Method | Route | Notes |
|---|---|---|
| `GET` | `/attack-path` | Shortest directed path between `start` and `target` assets |
| `GET` | `/all-paths` | All directed paths between `start` and `target`, aggregated into one graph |
| `GET` | `/attack-risk-summary` | Shortest path plus target risk, predictions, and mitigations |
| `GET` | `/risk-score` | Risk-ranked important assets |
| `GET` | `/risk-score/{asset_name}` | Risk details for one asset |

`/predict-compromise` and `/asset-analysis/{asset_name}` use endpoint-specific schemas in `app/schemas/prediction.py` and `app/schemas/integrated_analysis.py`.

## `graph`

`graph.nodes` and `graph.edges` are Cytoscape-compatible objects.

Node format:

```json
{
  "data": {
    "id": "Internet",
    "label": "Internet",
    "type": "asset"
  }
}
```

Edge format:

```json
{
  "data": {
    "source": "Internet",
    "target": "Web Server VM",
    "label": "EXPOSED_TO"
  }
}
```

Path endpoints preserve Neo4j relationship labels such as `EXPOSED_TO`, `CONNECTS_TO`, `HAS_ACCESS`, and `STORES_DATA_IN`. Edges are directional: `source` -> `target`.

## `risk`

`risk.top_assets` is a list of asset risk records. Records can include:

```json
{
  "asset_name": "Database Server",
  "risk_score": 72.5,
  "risk_level": "HIGH",
  "explanation": "Database Server is assessed as HIGH risk (72.5/100).",
  "contributing_factors": [
    "High vulnerability severity on this asset",
    "Very short attack path (3 hops)"
  ],
  "attack_path_details": {
    "attack_path_count": 1,
    "shortest_attack_path_length": 3,
    "relationship_count": 3,
    "entrypoint_reachability": "reachable"
  }
}
```

Risk levels are `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.

## `prediction`

`prediction.next_targets` contains ranked next-target candidates when a builder has enough graph or risk context. The prediction service combines graph reachability, risk data, and model-informed fallback context.

Example:

```json
{
  "prediction": {
    "next_targets": [
      {
        "node": "Database Server",
        "probability": 0.73,
        "label": "HIGH",
        "reasons": [
          "Reachable within 2 hops",
          "Ranked using asset risk and model context"
        ]
      }
    ]
  }
}
```

The array can be empty when no suitable candidates are available.

## `summary`

`summary` contains endpoint-specific metadata.

For `/attack-path`:

```json
{
  "summary": {
    "start_asset": "Internet",
    "target_asset": "Database Server",
    "path_length": 4,
    "overall_risk_level": "UNKNOWN",
    "highest_risk": null,
    "message": "Attack path successfully found",
    "generated_at": "2026-04-10T12:00:00+00:00"
  }
}
```

For `/all-paths`, `summary.total_paths` is included.

For `/risk-score`, `summary.highest_risk`, `summary.overall_risk_level`, and `summary.total_assets` describe the ranking.

For no-path domain errors, the API still returns the unified envelope and places the error under `summary.error`.

## `mitigations`

`mitigations` is a list of structured recommendation objects. It can be empty when no risk context is available.

```json
{
  "mitigations": [
    {
      "title": "Restrict Public Exposure",
      "recommendation": "Limit public ingress to required services only.",
      "severity": "HIGH",
      "priority": "P1",
      "reason": "Internet exposure increases exploitability."
    }
  ]
}
```

## Complete Example

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
  "risk": {
    "top_assets": [
      {
        "asset_name": "Database Server",
        "risk_score": 72.5,
        "risk_level": "HIGH",
        "explanation": "Database Server is assessed as HIGH risk (72.5/100).",
        "contributing_factors": ["High vulnerability severity on this asset"]
      }
    ]
  },
  "prediction": {
    "next_targets": [
      {
        "node": "Storage Bucket",
        "probability": 0.64,
        "label": "MEDIUM",
        "reasons": ["Reachable from current path context"]
      }
    ]
  },
  "summary": {
    "start_asset": "Internet",
    "target_asset": "Database Server",
    "path_length": 4,
    "overall_risk_level": "HIGH",
    "highest_risk": "Database Server",
    "message": "Attack path successfully found",
    "generated_at": "2026-04-10T12:00:00+00:00"
  },
  "mitigations": [
    {
      "title": "Patch Critical Vulnerabilities",
      "recommendation": "Prioritize remediation for critical and high findings on the target asset.",
      "severity": "HIGH",
      "priority": "P1",
      "reason": "Known vulnerabilities increase compromise likelihood."
    }
  ]
}
```

## Validation Checklist

- [ ] `graph.nodes` and `graph.edges` are arrays
- [ ] each node has `data.id`, `data.label`, and `data.type`
- [ ] each edge has `data.source`, `data.target`, and `data.label`
- [ ] path endpoint edge labels preserve Neo4j relationship types
- [ ] `risk.top_assets` is an array
- [ ] `prediction.next_targets` is an array
- [ ] `summary` is an object
- [ ] `mitigations` is an array of structured recommendation objects
- [ ] errors use `summary.error` inside the unified envelope

## Quick Validation

```python
from app.schemas import FinalResponse

validated = FinalResponse(**response.json())
```

## Status

[ok] Unified envelope is current.
[ok] Graph data is Cytoscape-compatible.
[ok] Relationship labels are preserved when supplied by graph services.
[ok] Predictions and mitigations are active extension sections, not placeholder-only fields.
