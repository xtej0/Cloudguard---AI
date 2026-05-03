# ML Flow and Mitigation Logic

## ML Objective

CloudGuard AI uses supervised multiclass classification to predict an asset's risk level from cloud posture and attack-path features.

- Target: `risk_level`
- Classes: `LOW`, `MEDIUM`, `HIGH`
- Training data: `datasets/synthetic_attack_dataset.csv`
- Training script: `ml/train_model.py`
- Inference module: `backend/app/ml_engine.py`
- API route: `POST /predict-compromise`

The endpoint name is retained for continuity, but the model predicts a risk class rather than a binary compromised/not-compromised value.

## Feature Set

The inference engine uses the exact training feature order:

| Feature | Meaning |
|---|---|
| `asset_type` | Asset category such as VM, Database, Bucket, IAM Role, Container, or Load Balancer |
| `internet_exposed` | Whether the asset is directly internet exposed |
| `public_access` | Whether public access is enabled |
| `has_critical_data` | Whether the asset stores sensitive or critical data |
| `weak_iam` | Whether IAM controls are weak |
| `lateral_movement_possible` | Whether the asset enables lateral movement |
| `privilege_escalation_possible` | Whether privilege escalation is plausible |
| `open_port_count` | Number of open ports |
| `vulnerability_count` | Total vulnerability count |
| `critical_vulnerability_count` | Critical vulnerability count |
| `misconfiguration_count` | Security misconfiguration count |
| `attack_path_count` | Number of attack paths involving the asset |
| `shortest_path_length` | Shortest graph path length to the asset |
| `exposure_score` | Composite exposure score |
| `identity_risk_score` | Composite identity risk score |
| `network_risk_score` | Composite network risk score |

## Training Pipeline

`ml/train_model.py` performs the following workflow:

1. Load `datasets/synthetic_attack_dataset.csv`.
2. Reject a `risk_score` column if present, preventing target leakage.
3. Drop `scenario_id`.
4. Split features from `risk_level`.
5. Encode categorical feature columns with `LabelEncoder`.
6. Encode target labels with a separate target encoder.
7. Train a tuned `RandomForestClassifier`.
8. Benchmark against `GradientBoostingClassifier`.
9. Print accuracy, classification report, confusion matrix, and feature importance.
10. Save artifacts under `models/`.

Saved artifacts:

```text
models/risk_model.pkl
models/feature_encoders.pkl
models/target_encoder.pkl
```

## Model Selection

The selected model is a tuned Random Forest classifier:

- `n_estimators=300`
- `max_depth=12`
- `min_samples_split=5`
- `min_samples_leaf=2`
- `class_weight="balanced"`
- `random_state=42`

The Day 18 evaluation recorded approximately 81 percent Random Forest accuracy and approximately 80 percent Gradient Boosting accuracy on the synthetic test split.

## Inference Flow

`backend/app/ml_engine.py` loads model artifacts at import time and caches them globally.

For each prediction request:

1. Raw JSON is normalized.
2. Categorical values are encoded using training-time encoders.
3. Missing or invalid numeric values are coerced to `0.0`.
4. A one-row pandas `DataFrame` is built in the exact training feature order.
5. The model predicts an encoded class.
6. The target encoder converts the prediction back to `LOW`, `MEDIUM`, or `HIGH`.
7. Class probabilities are returned when the model supports `predict_proba`.
8. Optional SHAP-based feature importance is returned when SHAP is available and compatible.

Prediction response fields:

```json
{
  "predicted_label": "HIGH",
  "confidence": 0.87,
  "probabilities": {
    "HIGH": 0.87,
    "MEDIUM": 0.10,
    "LOW": 0.03
  },
  "feature_importance": [],
  "next_targets": []
}
```

## Next-Target Ranking

`backend/app/services/prediction_service.py` ranks likely next targets by combining:

- graph reachability from high-risk or requested seed assets
- risk score and risk level context
- model prediction confidence and label context

The probability calculation uses weighted components:

- risk component: 45 percent
- graph-distance component: 30 percent
- model context component: 25 percent

The ranking excludes non-attackable node types such as `Internet` and `User`, keeps likely cloud assets such as servers, databases, buckets, storage, IAM roles, and VMs, sorts by probability, and returns the top candidates.

## Integrated Analysis Flow

`backend/app/integrated_analysis.py` powers `GET /asset-analysis/{asset_name}`.

The flow is:

1. Load current risk details for the selected asset.
2. Query reachable candidate next-hop assets from Neo4j.
3. Build model feature rows for each candidate.
4. Run `predict_compromise()` for candidates.
5. Compute graph reachability, compromise likelihood, and combined scores.
6. Select the highest-scoring predicted next target.
7. Generate mitigations from the selected candidate context.

Debug trace printing is disabled by default. Set `CLOUDGUARD_DEBUG=true` to enable additional integrated-analysis debug logs.

## Mitigation Engine

Mitigation logic is split across:

- `backend/app/services/mitigation_service.py`
- `backend/app/mitigation_engine.py`

The service translates existing risk API payloads into normalized mitigation-engine signals. The engine then emits structured recommendations.

Recommendation schema:

```json
{
  "title": "Restrict Internet Exposure",
  "recommendation": "Restrict inbound traffic and remove unnecessary public network exposure.",
  "severity": "HIGH",
  "priority": "P1",
  "reason": "Asset is internet-exposed, increasing direct attack surface."
}
```

## Mitigation Rules

| Signal | Recommendation |
|---|---|
| `internet_exposed=1` | Restrict Internet Exposure |
| `public_access=1` | Remove Public Access |
| `weak_iam=1` | Strengthen IAM Controls |
| `privilege_escalation_possible=1` | Block Privilege Escalation Paths |
| `critical_vulnerability_count>0` | Patch Critical Vulnerabilities |
| `vulnerability_count>=5` with no critical count | Review Vulnerability Management |
| `misconfiguration_count>0` | Harden Security Configuration |
| `lateral_movement_possible=1` | Limit Lateral Movement |
| `has_critical_data=1` | Protect Critical Data |
| two or more high-risk flags | Immediate Containment and Security Review |

If a risk payload exists but no rule fires, the service returns a fallback recommendation titled `Review Asset Risk Controls`.

## Academic Interpretation

The ML component should be presented as a synthetic-data classifier suitable for demonstrating a security analytics workflow. The strongest academic value is the integration pattern:

- graph context from Neo4j
- deterministic risk scoring for explainability
- model inference for risk classification
- rule-based mitigations for actionability
- dashboard visualization for analyst usability
