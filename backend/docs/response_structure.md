# CloudGuard AI - Unified Response Schema Documentation

## Overview

All endpoints in the CloudGuard AI backend return a **unified, frontend-ready JSON response structure**. This ensures consistency across the API and simplifies frontend integration with Cytoscape visualization.

---

## All Available Endpoints

The following endpoints all return the same unified schema:

1. **`GET /attack-path`** - Get shortest attack path between two assets
   - Parameters: `start` (asset name), `target` (asset name)
   - Returns: Shortest path with nodes and edges

2. **`GET /all-paths`** - Get all possible attack paths between two assets
   - Parameters: `start` (asset name), `target` (asset name)  
   - Returns: All paths aggregated into graph format

3. **`GET /risk-score`** - Get risk scores for all top-risk assets
   - Parameters: None
   - Returns: Ranked list of high-risk assets

4. **`GET /risk-score/{asset_name}`** - Get risk score for a single asset
   - Parameters: `asset_name` (string)
   - Returns: Single asset risk details

5. **`GET /attack-risk-summary`** - Get attack risk analysis between two assets
   - Parameters: `start` (asset name), `target` (asset name)
   - Returns: Combined attack path and risk analysis

---

## Unified Response Schema

**Every endpoint returns this exact structure:**

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
  "mitigations": [
    {
      "title": "Limit Lateral Movement",
      "recommendation": "Implement network segmentation and stricter east-west access controls between assets.",
      "severity": "HIGH",
      "priority": "P1",
      "reason": "Lateral movement paths enable attackers to pivot deeper into the environment."
    }
  ]
}
```

### Error Handling Contract

Errors are returned using the same unified schema. There is no standalone top-level
`{"error": ...}` payload. Instead, error details are placed under `summary.error`.

```json
{
  "version": "v1",
  "graph": { "nodes": [], "edges": [] },
  "risk": { "top_assets": [] },
  "prediction": { "next_targets": [] },
  "mitigations": [],
  "summary": {
    "error": "No attack path found between given nodes"
  }
}
```

---

## Response Schema Sections Explained

### 1. **`graph` Section** (For Cytoscape Visualization)

Contains the attack path graph in **Cytoscape-compatible format**.

**Purpose:** Visualize network topology and attack paths in the frontend.

**Structure:**
- `nodes` (array): List of assets/nodes in the graph
  - Each node is wrapped in a `data` object
  - Contains: `id`, `label`, `type`

- `edges` (array): List of relationships between nodes
  - Each edge is wrapped in a `data` object
  - Contains: `source`, `target`, `label` (relationship type)

**Example:**
```json
{
  "graph": {
    "nodes": [
      { "data": { "id": "Internet", "label": "Internet", "type": "asset" } },
      { "data": { "id": "Web Server", "label": "Web Server", "type": "asset" } }
    ],
    "edges": [
      { "data": { "source": "Internet", "target": "Web Server", "label": "ATTACK" } }
    ]
  }
}
```

---

### 2. **`risk` Section** (Risk Rankings)

Contains risk assessment data for assets.

**Purpose:** Display which assets are at highest risk and why.

**Structure:**
- `top_assets` (array): List of high-risk assets, sorted by risk score (descending)
  - Each asset contains:
    - `asset_name` (string): Name of the asset
    - `risk_score` (float 0-100): Numerical risk score
    - `risk_level` (string): Risk category (LOW, MEDIUM, HIGH, CRITICAL)
    - `explanation` (string): Human-readable risk explanation
    - `contributing_factors` (array): Key factors influencing the score
    - `attack_path_details` (object): Attack pattern information

**Example:**
```json
{
  "risk": {
    "top_assets": [
      {
        "asset_name": "Database Server",
        "risk_score": 85.5,
        "risk_level": "CRITICAL",
        "explanation": "Database is exposed to 3 attack paths with short path length.",
        "contributing_factors": ["exposed_to_internet", "high_criticality", "multiple_attack_paths"],
        "attack_path_details": {
          "attack_path_count": 3,
          "shortest_attack_path_length": 2
        }
      }
    ]
  }
}
```

---

### 3. **`prediction` Section** (Next-Target Ranking)

Contains ranked next-compromise targets when graph and risk context is available.

**Purpose:** Surface likely next targets using graph reachability, asset risk, and model context.

- `next_targets` (array): Ranked target candidates. It can be empty when no graph context is available.

**Example:**
```json
{
  "prediction": {
    "next_targets": [
      {
        "node": "Application Server VM",
        "probability": 0.82,
        "label": "HIGH",
        "reasons": ["Directly connected to a high-risk asset"]
      }
    ]
  }
}
```

---

### 4. **`summary` Section** (Metadata)

Contains contextual information about the response.

**Purpose:** Provide metadata that helps frontend understand the data context.

**Structure varies by endpoint:**

**For `/attack-path` and `/all-paths`:**
```json
{
  "summary": {
    "start_asset": "Internet",
    "target_asset": "Database Server",
    "path_length": 3,
    "total_paths": 5
  }
}
```

**For `/risk-score`:**
```json
{
  "summary": {}
}
```

**For `/risk-score/{asset_name}`:**
```json
{
  "summary": {
    "target_asset": "Database Server",
    "risk_level": "CRITICAL",
    "generated_at": "2026-03-23T12:00:00+00:00"
  }
}
```

---

### 5. **`mitigations` Section** (Security Recommendations)

Contains contextual rule-based security recommendations.

**Purpose:** Suggest security actions to reduce exposure, identity risk, vulnerability risk, lateral movement, and data impact.

- `mitigations` (array): Recommendation objects. It can be empty when no risk context is available.

**Example:**
```json
{
  "mitigations": [
    {
      "title": "Patch Critical Vulnerabilities",
      "recommendation": "Prioritize and patch critical vulnerabilities immediately using emergency remediation timelines.",
      "severity": "HIGH",
      "priority": "P1",
      "reason": "Critical vulnerabilities present immediate exploit risk."
    }
  ]
}
```

---

## Complete Example JSON Response

**Below is a realistic response from `/all-paths` endpoint:**

```json
{
  "graph": {
    "nodes": [
      {
        "data": {
          "id": "Internet",
          "label": "Internet",
          "type": "asset"
        }
      },
      {
        "data": {
          "id": "Web Server",
          "label": "Web Server",
          "type": "asset"
        }
      },
      {
        "data": {
          "id": "Application Server",
          "label": "Application Server",
          "type": "asset"
        }
      },
      {
        "data": {
          "id": "Database Server",
          "label": "Database Server",
          "type": "asset"
        }
      }
    ],
    "edges": [
      {
        "data": {
          "source": "Internet",
          "target": "Web Server",
          "label": "ATTACK"
        }
      },
      {
        "data": {
          "source": "Web Server",
          "target": "Application Server",
          "label": "ATTACK"
        }
      },
      {
        "data": {
          "source": "Application Server",
          "target": "Database Server",
          "label": "ATTACK"
        }
      }
    ]
  },
  "risk": {
    "top_assets": [
      {
        "asset_name": "Database Server",
        "risk_score": 85.5,
        "risk_level": "CRITICAL",
        "explanation": "Database is exposed to 2 attack paths with minimal hops from Internet.",
        "contributing_factors": [
          "exposed_via_multiple_paths",
          "stores_sensitive_data",
          "limited_access_controls"
        ],
        "attack_path_details": {
          "attack_path_count": 2,
          "shortest_attack_path_length": 3
        }
      },
      {
        "asset_name": "Application Server",
        "risk_score": 72.3,
        "risk_level": "HIGH",
        "explanation": "Gateway to backend systems with 3 incoming attack paths.",
        "contributing_factors": [
          "direct_internet_exposure",
          "executes_user_code",
          "memory_vulnerabilities"
        ],
        "attack_path_details": {
          "attack_path_count": 3,
          "shortest_attack_path_length": 2
        }
      }
    ]
  },
  "prediction": {
    "next_targets": []
  },
  "summary": {
    "start_asset": "Internet",
    "target_asset": "Database Server",
    "total_paths": 1
  },
  "mitigations": []
}
```

---

## Cytoscape Compatibility

The `graph.nodes` and `graph.edges` sections are **fully compatible with Cytoscape.js** visualization library.

### Node Format (Cytoscape Compatible)

**Required structure:**
```json
{
  "data": {
    "id": "unique_identifier",
    "label": "Display Name",
    "type": "asset_type"
  }
}
```

**Rules:**
- `id` must be unique across all nodes
- `label` is what displays in visualization
- `type` can be: `asset`, `service`, `user`, `internet`, etc.

**Frontend Usage (Cytoscape.js):**
```javascript
const elements = response.graph.nodes.map(node => ({
  data: node.data
}));

cyInstance.add(elements);
```

---

### Edge Format (Cytoscape Compatible)

**Required structure:**
```json
{
  "data": {
    "source": "source_node_id",
    "target": "target_node_id",
    "label": "Relationship Type"
  }
}
```

**Rules:**
- `source` and `target` must reference existing node IDs
- `label` describes the relationship (e.g., "ATTACK", "EXECUTES", "CONNECTS_TO")
- Edges are directional (source → target)

**Frontend Usage (Cytoscape.js):**
```javascript
const edges = response.graph.edges.map(edge => ({
  data: edge.data
}));

cyInstance.add(edges);
```

---

## Response Validation Checklist

**Every endpoint response must satisfy these requirements:**

- [ ] **`graph` section exists**
  - [ ] `graph.nodes` is an array
  - [ ] `graph.edges` is an array
  - [ ] Each node has `{ data: { id, label, type } }`
  - [ ] Each edge has `{ data: { source, target, label } }`

- [ ] **`risk` section exists**
  - [ ] `risk.top_assets` is an array
  - [ ] Each asset has required fields:
    - [ ] `asset_name` (string)
    - [ ] `risk_score` (number 0-100)
    - [ ] `risk_level` (string: LOW/MEDIUM/HIGH/CRITICAL)

- [ ] **`prediction` section exists**
  - [ ] `prediction.next_targets` is an array (can be empty)

- [ ] **`summary` section exists**
  - [ ] `summary` is an object (can be empty `{}`)

- [ ] **`mitigations` section exists**
  - [ ] `mitigations` is an array (can be empty `[]`)
  - [ ] Each non-empty mitigation has `title`, `recommendation`, `severity`, `priority`, and `reason`

- [ ] **No field naming inconsistencies**
  - [ ] All responses use same key names across endpoints
  - [ ] No alternate names like `nodes` vs `graph_nodes`
  - [ ] No extra fields not in the unified schema

---

## Testing the Response Structure

### Using curl to test endpoints:

```bash
# Test /attack-path endpoint
curl "http://localhost:8000/attack-path?start=Internet&target=Database Server"

# Test /risk-score endpoint
curl "http://localhost:8000/risk-score"

# Test /risk-score/{asset_name} endpoint
curl "http://localhost:8000/risk-score/Database Server"
```

### Expected Response Code
- **200**: Success - response contains valid unified schema
- **400**: Bad request - invalid parameters
- **500**: Server error - check Neo4j connection

### Schema Validation
All responses should pass this validation:
```python
from app.schemas import FinalResponse
response_data = response.json()
validated = FinalResponse(**response_data)  # Should not raise exception
```

---

## Frontend Integration Guide

### 1. Parse Response
```javascript
const response = await fetch('/risk-score');
const data = await response.json();
```

### 2. Render Graph
```javascript
const cy = cytoscape({
  container: document.getElementById('cy'),
  elements: [
    ...data.graph.nodes,
    ...data.graph.edges
  ],
  style: [...]
});
```

### 3. Display Risk Rankings
```javascript
data.risk.top_assets.forEach(asset => {
  console.log(`${asset.asset_name}: ${asset.risk_level} (${asset.risk_score}/100)`);
});
```

### 4. Show Summary Info
```javascript
if (data.summary && Object.keys(data.summary).length > 0) {
  console.log('Path details:', data.summary);
}
```

---

## Summary

- ✅ All endpoints return the **same unified schema**
- ✅ Graph data is **Cytoscape-compatible**
- ✅ Response is **frontend-ready**
- ✅ Includes next-target predictions and contextual mitigations
- ✅ Consistent field naming across all endpoints
- ✅ Validated with Pydantic schemas

**Status:** Ready for frontend integration! 🚀
