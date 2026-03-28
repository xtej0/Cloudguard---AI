"""Train a risk level classifier for CloudGuard AI."""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder


# -----------------------------
# Reproducibility configuration
# -----------------------------
RANDOM_SEED = 42
np.random.seed(RANDOM_SEED)


# -----------------------------
# Paths
# -----------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATASET_PATH = PROJECT_ROOT / "datasets" / "synthetic_attack_dataset.csv"
MODELS_DIR = PROJECT_ROOT / "models"

MODEL_PATH = MODELS_DIR / "risk_model.pkl"
FEATURE_ENCODERS_PATH = MODELS_DIR / "feature_encoders.pkl"
TARGET_ENCODER_PATH = MODELS_DIR / "target_encoder.pkl"


def main() -> None:
    """Train and persist a Random Forest classifier for risk_level prediction."""

    # -----------------------------
    # 1. Load dataset
    # -----------------------------
    dataset = pd.read_csv(DATASET_PATH)
    print(f"Dataset shape: {dataset.shape}")
    print("Columns:")
    print(dataset.columns.tolist())

    # -----------------------------
    # 2. Remove non-useful/leakage columns
    # -----------------------------
    if "risk_score" in dataset.columns:
        raise ValueError("risk_score column detected. Remove it to avoid ML data leakage.")

    dataset = dataset.drop(columns=["scenario_id"], errors="ignore")

    # -----------------------------
    # 3. Separate features and target
    # -----------------------------
    X = dataset.drop(columns=["risk_level"])
    y = dataset["risk_level"]

    # -----------------------------
    # 4. Encode categorical feature columns
    # -----------------------------
    feature_encoders: dict[str, LabelEncoder] = {}
    categorical_columns = X.select_dtypes(include=["object", "category", "string"]).columns.tolist()

    for column in categorical_columns:
        encoder = LabelEncoder()
        X[column] = encoder.fit_transform(X[column].astype(str))
        feature_encoders[column] = encoder

    # -----------------------------
    # 5. Encode target
    # -----------------------------
    target_encoder = LabelEncoder()
    y_encoded = target_encoder.fit_transform(y)
    print(f"Target classes: {list(target_encoder.classes_)}")

    # -----------------------------
    # 6. Train-test split
    # -----------------------------
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y_encoded,
        test_size=0.2,
        random_state=RANDOM_SEED,
        stratify=y_encoded,
    )

    # -----------------------------
    # 7. Train Random Forest model (tuned)
    # -----------------------------
    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=12,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=RANDOM_SEED,
    )
    model.fit(X_train, y_train)

    # -----------------------------
    # 8. Evaluate models
    # -----------------------------
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    print("\n======== RANDOM FOREST RESULTS ========")
    print(f"Accuracy: {accuracy:.4f}")
    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            y_pred,
            target_names=target_encoder.classes_,
            zero_division=0,
        )
    )

    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    gb_model = GradientBoostingClassifier(random_state=RANDOM_SEED)
    gb_model.fit(X_train, y_train)
    gb_pred = gb_model.predict(X_test)
    gb_accuracy = accuracy_score(y_test, gb_pred)

    print("\n======== GRADIENT BOOSTING RESULTS ========")
    print(f"Accuracy: {gb_accuracy:.4f}")
    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            gb_pred,
            target_names=target_encoder.classes_,
            zero_division=0,
        )
    )

    # -----------------------------
    # 9. Feature importance
    # -----------------------------
    feature_importance_df = (
        pd.DataFrame({"feature": X.columns, "importance": model.feature_importances_})
        .sort_values("importance", ascending=False)
        .head(10)
    )

    print("\nTop 10 Feature Importances:")
    print(feature_importance_df.to_string(index=False))

    # -----------------------------
    # 10. Save model and encoders
    # -----------------------------
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    joblib.dump(feature_encoders, FEATURE_ENCODERS_PATH)
    joblib.dump(target_encoder, TARGET_ENCODER_PATH)

    print("\nSaved artifacts:")
    print(f"- {MODEL_PATH}")
    print(f"- {FEATURE_ENCODERS_PATH}")
    print(f"- {TARGET_ENCODER_PATH}")


if __name__ == "__main__":
    main()
