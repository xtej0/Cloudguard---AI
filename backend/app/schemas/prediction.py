from typing import Any, Dict, List

from pydantic import BaseModel, Field


class PredictionRequest(BaseModel):
    asset_type: str = Field(
        ...,
        description="Type/category of the asset being evaluated.",
        json_schema_extra={"example": "Database Server"},
    )
    internet_exposed: int = Field(
        ...,
        description="Whether the asset is directly exposed to the internet (0 or 1).",
        json_schema_extra={"example": 1},
    )
    public_access: int = Field(
        ...,
        description="Whether the asset allows public access (0 or 1).",
        json_schema_extra={"example": 1},
    )
    has_critical_data: int = Field(
        ...,
        description="Whether the asset stores business-critical or sensitive data (0 or 1).",
        json_schema_extra={"example": 1},
    )
    weak_iam: int = Field(
        ...,
        description="Presence of weak IAM controls associated with this asset (0 or 1).",
        json_schema_extra={"example": 1},
    )
    lateral_movement_possible: int = Field(
        ...,
        description="Whether lateral movement from this asset is possible (0 or 1).",
        json_schema_extra={"example": 1},
    )
    privilege_escalation_possible: int = Field(
        ...,
        description="Whether privilege escalation paths exist from this asset (0 or 1).",
        json_schema_extra={"example": 1},
    )
    open_port_count: int = Field(
        ...,
        description="Number of open network ports detected on the asset.",
        json_schema_extra={"example": 14},
    )
    vulnerability_count: int = Field(
        ...,
        description="Total known vulnerabilities associated with the asset.",
        json_schema_extra={"example": 22},
    )
    critical_vulnerability_count: int = Field(
        ...,
        description="Count of critical severity vulnerabilities for the asset.",
        json_schema_extra={"example": 6},
    )
    misconfiguration_count: int = Field(
        ...,
        description="Count of detected security misconfigurations.",
        json_schema_extra={"example": 9},
    )
    attack_path_count: int = Field(
        ...,
        description="Number of attack paths that include this asset.",
        json_schema_extra={"example": 4},
    )
    shortest_path_length: int = Field(
        ...,
        description="Length of the shortest known attack path to this asset.",
        json_schema_extra={"example": 2},
    )
    exposure_score: float = Field(
        ...,
        description="Composite exposure score derived from external attack surface signals.",
        json_schema_extra={"example": 0.82},
    )
    identity_risk_score: float = Field(
        ...,
        description="Composite identity-related risk score for the asset.",
        json_schema_extra={"example": 0.73},
    )
    network_risk_score: float = Field(
        ...,
        description="Composite network risk score for the asset.",
        json_schema_extra={"example": 0.69},
    )


class PredictionResponse(BaseModel):
    predicted_label: str = Field(
        ...,
        description="Predicted compromise risk class label.",
        json_schema_extra={"example": "HIGH"},
    )
    confidence: float = Field(
        ...,
        description="Model confidence score for the predicted label.",
        json_schema_extra={"example": 0.5996},
    )
    probabilities: Dict[str, float] = Field(
        ...,
        description="Per-class probability map returned by the model.",
        json_schema_extra={"example": {"HIGH": 0.5996, "LOW": 0.0904, "MEDIUM": 0.31}},
    )
    feature_importance: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Top SHAP feature contributions for the predicted class.",
        json_schema_extra={
            "example": [
                {"feature": "vulnerability_count", "impact": 0.23, "direction": "increase"}
            ]
        },
    )
