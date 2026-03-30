from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODELS_DIR = PROJECT_ROOT / "models"

MODEL_PATH = MODELS_DIR / "risk_model.pkl"
FEATURE_ENCODERS_PATH = MODELS_DIR / "feature_encoders.pkl"
TARGET_ENCODER_PATH = MODELS_DIR / "target_encoder.pkl"

# Exact feature order from training (after removing scenario_id and target).
TRAINING_FEATURE_COLUMNS = [
    "asset_type",
    "internet_exposed",
    "public_access",
    "has_critical_data",
    "weak_iam",
    "lateral_movement_possible",
    "privilege_escalation_possible",
    "open_port_count",
    "vulnerability_count",
    "critical_vulnerability_count",
    "misconfiguration_count",
    "attack_path_count",
    "shortest_path_length",
    "exposure_score",
    "identity_risk_score",
    "network_risk_score",
]

MODEL: Any | None = None
FEATURE_ENCODERS: dict[str, Any] = {}
TARGET_ENCODER: Any | None = None
FEATURE_COLUMNS: list[str] = TRAINING_FEATURE_COLUMNS.copy()
MODEL_LOAD_ERROR: str | None = None


def load_model_artifacts() -> None:
    """Load model + encoders once and cache globally for inference calls."""

    global MODEL, FEATURE_ENCODERS, TARGET_ENCODER, FEATURE_COLUMNS, MODEL_LOAD_ERROR

    try:
        if not MODEL_PATH.exists():
            raise FileNotFoundError(f"Model file not found at {MODEL_PATH}")
        if not FEATURE_ENCODERS_PATH.exists():
            raise FileNotFoundError(f"Feature encoder file not found at {FEATURE_ENCODERS_PATH}")
        if not TARGET_ENCODER_PATH.exists():
            raise FileNotFoundError(f"Target encoder file not found at {TARGET_ENCODER_PATH}")

        MODEL = joblib.load(MODEL_PATH)
        FEATURE_ENCODERS = joblib.load(FEATURE_ENCODERS_PATH)
        TARGET_ENCODER = joblib.load(TARGET_ENCODER_PATH)

        if hasattr(MODEL, "feature_names_in_"):
            FEATURE_COLUMNS = list(MODEL.feature_names_in_)
        else:
            FEATURE_COLUMNS = TRAINING_FEATURE_COLUMNS.copy()

        MODEL_LOAD_ERROR = None
    except Exception as exc:  # pragma: no cover - exercised via fallback tests
        MODEL_LOAD_ERROR = str(exc)
        MODEL = None
        FEATURE_ENCODERS = {}
        TARGET_ENCODER = None
        FEATURE_COLUMNS = TRAINING_FEATURE_COLUMNS.copy()


def _normalize_input_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, str) and value.strip() == "":
        return None
    return value


def _encode_categorical(column: str, value: Any) -> int:
    """Encode a categorical value using training-time LabelEncoder rules."""

    encoder = FEATURE_ENCODERS.get(column)
    if encoder is None:
        return 0

    classes = list(getattr(encoder, "classes_", []))
    if not classes:
        return 0

    safe_value = "UNKNOWN" if value is None else str(value).strip()
    if not safe_value:
        safe_value = "UNKNOWN"

    if safe_value not in classes:
        safe_value = classes[0]

    return int(encoder.transform([safe_value])[0])


def _coerce_numeric(value: Any) -> float:
    if value is None:
        return 0.0
    if isinstance(value, bool):
        return float(int(value))
    if isinstance(value, (int, float, np.integer, np.floating)):
        return float(value)

    try:
        parsed = float(str(value).strip())
    except (TypeError, ValueError):
        return 0.0

    if np.isnan(parsed) or np.isinf(parsed):
        return 0.0
    return float(parsed)


def prepare_features(raw_input: dict[str, Any]) -> pd.DataFrame:
    """Convert flexible raw input into a single-row model-ready DataFrame."""

    if not isinstance(raw_input, dict):
        raw_input = {}

    record: dict[str, Any] = {}
    for column in FEATURE_COLUMNS:
        raw_value = _normalize_input_value(raw_input.get(column))

        if column in FEATURE_ENCODERS:
            record[column] = _encode_categorical(column, raw_value)
        else:
            record[column] = _coerce_numeric(raw_value)

    return pd.DataFrame([record], columns=FEATURE_COLUMNS)


def interpret_prediction(prediction: Any) -> str:
    """Map model prediction output to LOW/MEDIUM/HIGH label."""

    if TARGET_ENCODER is None:
        return str(prediction)

    try:
        encoded_value = int(np.asarray(prediction).reshape(-1)[0])
        label = TARGET_ENCODER.inverse_transform([encoded_value])[0]
        return str(label)
    except Exception:
        return str(prediction)


def predict_probabilities(raw_input: dict[str, Any]) -> dict[str, float]:
    """Return class probabilities by label, or a safe fallback when unavailable."""

    if MODEL is None:
        raise RuntimeError(MODEL_LOAD_ERROR or "Model is not loaded")

    features = prepare_features(raw_input)
    class_labels = [str(label) for label in getattr(TARGET_ENCODER, "classes_", ["LOW", "MEDIUM", "HIGH"])]

    if hasattr(MODEL, "predict_proba"):
        proba = MODEL.predict_proba(features)[0]
        return {
            class_labels[idx]: round(float(prob), 4)
            for idx, prob in enumerate(proba)
        }

    prediction = MODEL.predict(features)[0]
    predicted_label = interpret_prediction(prediction)
    fallback = {label: 0.0 for label in class_labels}
    fallback[predicted_label] = 1.0
    return fallback


def predict_compromise(raw_input: dict[str, Any]) -> dict[str, Any]:
    """Run end-to-end inference and return JSON-safe prediction payload."""

    if MODEL is None:
        return {
            "predicted_label": "UNKNOWN",
            "confidence": 0.0,
            "probabilities": {},
            "error": MODEL_LOAD_ERROR or "Model is not loaded",
        }

    try:
        features = prepare_features(raw_input)
        raw_prediction = MODEL.predict(features)[0]
        predicted_label = interpret_prediction(raw_prediction)
        probabilities = predict_probabilities(raw_input)

        confidence = float(probabilities.get(predicted_label, 0.0))

        return {
            "predicted_label": str(predicted_label),
            "confidence": round(confidence, 4),
            "probabilities": {k: round(float(v), 4) for k, v in probabilities.items()},
        }
    except Exception as exc:
        return {
            "predicted_label": "UNKNOWN",
            "confidence": 0.0,
            "probabilities": {},
            "error": str(exc),
        }


# Load artifacts at import-time for reuse across API calls.
load_model_artifacts()
