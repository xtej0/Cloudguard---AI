# CloudGuard AI - Day 15 Synthetic Attack Dataset Design

## 1. ML Problem Definition

CloudGuard AI uses a supervised multiclass classification model to predict an asset's compromise risk level from synthetic cloud posture and graph-derived features.

- Task type: multiclass classification
- Prediction target: `risk_level`
- Classes: `LOW`, `MEDIUM`, `HIGH`
- Dataset file: `datasets/synthetic_attack_dataset.csv`
- Generation script: `datasets/generate_dataset.py`
- Training script: `ml/train_model.py`
- Saved artifacts:
  - `models/risk_model.pkl`
  - `models/feature_encoders.pkl`
  - `models/target_encoder.pkl`

The model does not predict a binary `compromised` flag. It predicts a risk class that is consumed by the backend prediction API and dashboard.

## 2. Dataset Shape

The generator currently creates 10,000 synthetic rows using a fixed random seed (`42`) for reproducibility.

Each row represents one cloud asset scenario with correlated exposure, identity, vulnerability, network, and attack-path signals.

## 3. Actual Columns

| Column | Role | Type | Description |
|---|---|---|---|
| `scenario_id` | metadata | string | Stable scenario identifier such as `SCN-00001`. Dropped before training. |
| `asset_type` | feature | categorical | Asset category: `VM`, `Database`, `Bucket`, `IAM Role`, `Container`, or `Load Balancer`. |
| `internet_exposed` | feature | binary int | Whether the asset is directly internet-exposed. |
| `public_access` | feature | binary int | Whether broad/public access is enabled. |
| `has_critical_data` | feature | binary int | Whether the asset stores sensitive or business-critical data. |
| `weak_iam` | feature | binary int | Whether weak IAM controls are associated with the asset. |
| `lateral_movement_possible` | feature | binary int | Whether the asset enables lateral movement. |
| `privilege_escalation_possible` | feature | binary int | Whether privilege escalation paths are plausible. |
| `open_port_count` | feature | integer | Number of open network ports. |
| `vulnerability_count` | feature | integer | Total known vulnerability count. |
| `critical_vulnerability_count` | feature | integer | Count of critical vulnerabilities. |
| `misconfiguration_count` | feature | integer | Count of security misconfigurations. |
| `attack_path_count` | feature | integer | Estimated number of attack paths involving the asset. |
| `shortest_path_length` | feature | integer | Shortest attack-path length. `0` means no valid path exists. |
| `exposure_score` | feature | float | Composite exposure score in the 0-100 range. |
| `identity_risk_score` | feature | float | Composite identity-risk score in the 0-100 range. |
| `network_risk_score` | feature | float | Composite network-risk score in the 0-100 range. |
| `risk_level` | target | categorical | Final class label: `LOW`, `MEDIUM`, or `HIGH`. |

## 4. Generation Logic

`datasets/generate_dataset.py` builds scenarios with asset-specific probability profiles.

Examples:

- VMs and load balancers are more likely to be internet-facing.
- Databases are more likely to contain critical data.
- Buckets are more likely to have public-access risk.
- IAM roles are more likely to contain weak IAM and privilege-escalation signals.

The generator derives:

- `attack_path_count` from vulnerability, exposure, IAM, movement, and misconfiguration signals.
- `shortest_path_length` from attack-path count, exposure, and movement flags.
- `exposure_score`, `identity_risk_score`, and `network_risk_score` from weighted signal groups.
- `risk_level` from an internal risk score with deterministic LOW/HIGH boundaries and controlled uncertainty in the MEDIUM/HIGH boundary.

## 5. Label Assignment

`risk_level` is assigned from an internal score:

- `LOW` if score is below 35.
- `HIGH` if score is above 70.
- `MEDIUM` or `HIGH` probabilistically in the middle region, weighted toward `MEDIUM`.

This hybrid approach keeps low and high classes clear while preserving realistic uncertainty for borderline scenarios.

## 6. Training Pipeline

`ml/train_model.py` performs the following steps:

1. Load `datasets/synthetic_attack_dataset.csv`.
2. Reject a `risk_score` column if present to avoid leakage.
3. Drop `scenario_id`.
4. Split features from target:
   - `X = dataset.drop(columns=["risk_level"])`
   - `y = dataset["risk_level"]`
5. Label-encode categorical features such as `asset_type`.
6. Label-encode the target classes.
7. Train a tuned `RandomForestClassifier`.
8. Compare against `GradientBoostingClassifier`.
9. Print accuracy, classification report, confusion matrix, and feature importance.
10. Save model and encoders into `models/`.

## 7. Model Selection

The selected model is a tuned Random Forest classifier because it performed slightly better than Gradient Boosting during Day 18 evaluation and provides useful feature-importance signals for explanations.

See `docs/model_evaluation_day18.md` for the recorded evaluation summary.

## 8. API Integration

`backend/app/ml_engine.py` loads:

- `models/risk_model.pkl`
- `models/feature_encoders.pkl`
- `models/target_encoder.pkl`

The `/predict-compromise` endpoint accepts the same feature fields used during training, returns:

- `predicted_label`
- `confidence`
- `probabilities`
- `feature_importance`
- graph/risk-derived `next_targets`

The endpoint name remains `/predict-compromise` for continuity, but the model output is a risk-level classification rather than a binary compromise decision.

## 9. Limitations

- The dataset is synthetic and should be described as simulated training data.
- `risk_level` labels are generated from engineered rules, so metrics may overstate real-world performance.
- The model predicts asset risk class, while next-target ranking also uses graph and risk context.
- Future work could add real cloud telemetry, time-series behavior, remediation status, and threat-intelligence signals.
