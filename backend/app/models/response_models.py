from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class GraphNodeData(BaseModel):
    id: str
    label: str
    type: str


class GraphEdgeData(BaseModel):
    source: str
    target: str
    label: str


class GraphNode(BaseModel):
    data: GraphNodeData


class GraphEdge(BaseModel):
    data: GraphEdgeData


class GraphSection(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class RiskSection(BaseModel):
    top_assets: list[dict[str, Any]]


class PredictionSection(BaseModel):
    next_targets: list[dict[str, Any]]


class SummarySection(BaseModel):
    model_config = {"extra": "allow"}


class AttackRiskSummaryResponse(BaseModel):
    version: str = "v1"
    graph: GraphSection
    risk: RiskSection
    prediction: PredictionSection
    mitigations: list[str]
    summary: dict[str, Any]


class ErrorResponse(BaseModel):
    error: str