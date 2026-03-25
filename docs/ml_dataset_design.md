# CloudGuard AI — Day 15: Synthetic Attack Dataset Design for ML

## 1) ML Problem Definition

**Task type:** Binary classification

**Objective:** Predict whether an asset will be compromised (`1`) or not compromised (`0`) based on graph-derived and security posture features.

This dataset is fully synthetic and generated from attack-graph structure, asset exposure patterns, privilege relationships, and backend risk logic.

**Prediction target:** `compromised`

---

## 2) Feature Set (Exact Columns)

The dataset uses exactly these feature columns:

- `exposed_port`
- `internet_exposed`
- `privilege_level`
- `vulnerability_score`
- `network_depth`
- `attack_path_count`
- `shortest_attack_path`
- `asset_criticality`
- `lateral_movement_options`

No additional model input features are included in this Day 15 dataset design.

---

## 3) Data Dictionary

| Feature | Data Type | Description | Valid Range | Why It Matters for Security Risk |
|---|---|---|---|---|
| `exposed_port` | Integer | Count of externally reachable open ports on the asset. | 0-10 | More exposed services increase attack surface and exploit opportunities. |
| `internet_exposed` | Integer (binary) | Whether the asset is directly reachable from the internet. | 0 or 1 | Internet-facing assets are easier to discover and attack, often serving as initial access points. |
| `privilege_level` | Integer (ordinal) | Effective privilege available on or through the asset. | 1-5 (1=low, 5=admin/root) | Higher privilege enables stronger attacker control and easier pivoting to sensitive assets. |
| `vulnerability_score` | Float | Aggregated vulnerability severity score (CVSS-like) for the asset. | 0.0-10.0 | High severity weaknesses are primary compromise drivers. |
| `network_depth` | Integer | Number of hops from internet edge/entry point to the asset in the attack graph. | 1-10 | Lower depth means easier reachability; deeper assets are usually harder to access directly. |
| `attack_path_count` | Integer | Number of distinct attack paths leading to the asset. | 0-25 | Multiple paths increase attacker optionality and resilience if one path is blocked. |
| `shortest_attack_path` | Integer | Minimum hop length among all feasible attack paths to the asset. | 1-10 (or 99 when no path) | Short paths indicate faster, lower-effort compromise chains. |
| `asset_criticality` | Integer (ordinal) | Business/security criticality rating of the asset. | 1-5 (1=low, 5=mission-critical) | Critical assets are typically high-value targets and receive focused attacker effort. |
| `lateral_movement_options` | Integer | Number of immediate pivot opportunities from current foothold toward this asset (credential trust, reachable neighbors, role paths). | 0-15 | More lateral options increase probability of successful progression across the environment. |

**Note on `shortest_attack_path`:** A value of `99` represents no reachable attack path. This sentinel value is allowed only when `attack_path_count = 0`.

---

## 4) Label Definition

**Label column:** `compromised`

- `0` = asset not compromised
- `1` = asset compromised

### Label Generation Logic (Exact)

`compromised = 1 if:`

- `vulnerability_score > 7`
- `AND (internet_exposed == 1 OR attack_path_count > 0)`
- `AND shortest_attack_path <= 3`

Otherwise, `compromised = 0`.

### Practical Modeling Note

For Day 15, the label is intentionally deterministic to create a controlled baseline dataset; future dataset versions may add controlled probabilistic variation/noise to better reflect real-world uncertainty.

---

## 5) Dataset Size and Class Balance

**Target dataset size:** 5000 samples

Two dataset variants will be produced:

1. **Balanced dataset (50/50)**
   - `compromised = 1`: 2500 samples
   - `compromised = 0`: 2500 samples

2. **Imbalanced dataset (20/80)**
   - `compromised = 1`: 1000 samples
   - `compromised = 0`: 4000 samples

This supports model development under both controlled training balance and realistic low-prevalence compromise scenarios.

---

## 6) Synthetic Data Generation Rules

### A. Realistic Distributions

- `internet_exposed`: Bernoulli distribution with lower prevalence than internal-only assets (e.g., minority internet-facing population).
- `vulnerability_score`: Right-skewed toward medium values, with fewer extreme high values.
- `exposed_port`: Low-count heavy distribution (most assets expose few ports, few assets expose many).
- `network_depth`: Mid-depth concentration with fewer assets at extreme edge or deep-core positions.
- `attack_path_count`: Zero-inflated distribution (many assets with 0-2 paths, fewer with large path counts).
- `privilege_level` and `asset_criticality`: Ordinal distributions with more mid-tier values than extremes.
- `lateral_movement_options`: Correlated count distribution, usually small-to-moderate with occasional high-mobility assets.

### B. Relationship Rules Between Features

To keep synthetic data consistent with cloud attack graph logic:

- If `internet_exposed = 1`, `network_depth` tends to be lower (edge-accessible assets should not systematically appear deep in network layers).
- If `attack_path_count = 0`, set `shortest_attack_path = 99` (no valid route sentinel).
- If `attack_path_count > 0`, constrain `shortest_attack_path` to 1-10.
- Higher `attack_path_count` generally co-occurs with higher `lateral_movement_options`.
- Higher `privilege_level` increases expected `lateral_movement_options` due to greater pivot capability.
- Higher `vulnerability_score` should increase probability of `compromised = 1` only when reachability conditions (internet/path) are also present.

### C. Hard Constraints

- Enforce valid ranges from the Data Dictionary for every generated sample.
- Enforce label rule exactly as defined (do not use probabilistic overrides for labeling).
- Preserve internal consistency:
  - `attack_path_count = 0` -> `shortest_attack_path = 99`
  - `shortest_attack_path <= 3` can only occur when `attack_path_count > 0` or exposure enables feasible direct access context.
- Avoid contradictory combinations at scale (for example, very deep assets with persistent direct internet exposure should be rare).

---

## 7) Generation Strategy

Data will be created programmatically using a staged synthetic pipeline (no manual row authoring):

1. **Schema-first initialization**
   - Create an empty dataset with exactly the nine feature columns plus `compromised`.

2. **Base sampling by feature type**
   - Sample each feature from its defined distribution family (binary, ordinal, continuous, count).

3. **Dependency adjustment pass**
   - Apply relationship rules to enforce graph realism (e.g., internet exposure vs. depth, path count vs. shortest path, privilege vs. lateral movement).

4. **Constraint validation pass**
   - Clip/fix out-of-range values and resolve invalid tuples.

5. **Deterministic labeling pass**
   - Compute `compromised` strictly from the exact rule:
     - `vulnerability_score > 7`
     - `AND (internet_exposed == 1 OR attack_path_count > 0)`
     - `AND shortest_attack_path <= 3`

6. **Class-balance curation**
   - Produce two outputs from the same generation framework:
     - Balanced 5000-sample set (50/50)
     - Imbalanced 5000-sample set (20/80)

7. **Quality checks and export**
   - Verify class counts, range conformance, and dependency consistency.
   - Export as tabular dataset files for ML training/validation workflows.

---

## 8) Feature Coverage Review (Redundancy/Missing)

### Redundancy Check

- Potential overlap exists between `attack_path_count`, `shortest_attack_path`, and `lateral_movement_options` because all capture graph reachability in different ways.
- This is acceptable for Day 15 because each captures a distinct security perspective:
  - path multiplicity (`attack_path_count`),
  - minimum attacker effort (`shortest_attack_path`),
  - local pivot flexibility (`lateral_movement_options`).
- Recommendation: keep all three for now; evaluate feature importance after initial model training.

### Missing Signal Check (Future Improvements, Not Added to Current Schema)

Current schema is valid and sufficient for initial binary compromise prediction, but future versions may benefit from adding:

- Patch recency / remediation status
- Identity exposure (e.g., stale privileged credentials)
- External exploit availability / threat intelligence indicator
- Segmentation strength or policy enforcement score

These are not included in this Day 15 dataset because the feature list is fixed by design.

---

## 9) Intended Initial ML Models

- **Logistic Regression**: Strong baseline for binary classification with interpretable feature influence, useful for validating signal direction in security features.
- **Random Forest**: Handles nonlinear interactions in attack-graph-derived tabular data and is robust to mixed feature scales and noisy relationships.
- **XGBoost / Gradient Boosting**: Typically high-performing on structured/tabular cybersecurity datasets by modeling complex feature interactions and decision boundaries.

These models are well-suited to this tabular compromise-likelihood task and provide a practical progression from interpretable baseline to higher-capacity ensemble methods.
