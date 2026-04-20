from __future__ import annotations

from typing import Any
from collections import deque

from dataclasses import dataclass, field

from app.services.risk_service import fetch_asset_relationships, get_top_asset_risk_scores

_GENERIC_LABELS = {"Asset", "Node", "Resource"}
_NON_ATTACKABLE_NODE_TYPES = {"user", "internet"}
_ATTACKABLE_TYPE_HINTS = ("vm", "server", "database", "bucket", "storage", "iam", "role")


def _normalize_node_type(labels: list[Any] | None) -> str:
    cleaned_labels = [str(label).strip() for label in (labels or []) if str(label).strip()]
    node_type = next((label for label in cleaned_labels if label not in _GENERIC_LABELS), cleaned_labels[0] if cleaned_labels else "Unknown")
    return node_type


def _is_attackable_node_type(node_type: str) -> bool:
    normalized = str(node_type or "").strip().lower()
    if not normalized or normalized in _NON_ATTACKABLE_NODE_TYPES:
        return False
    return any(token in normalized for token in _ATTACKABLE_TYPE_HINTS)


def _prediction_reason_for_depth(distance: int, fallback: bool = False) -> str:
    if fallback:
        return "Predicted based on overall risk distribution"
    if distance <= 1:
        return "Directly connected to a high-risk asset"
    return "Reachable through attack path from high-risk asset"

@dataclass
class PredictionGraphView:
    nodes: set[str] = field(default_factory=set)
    outgoing: dict[str, list[str]] = field(default_factory=dict)
    incoming: dict[str, list[str]] = field(default_factory=dict)
    node_types: dict[str, str] = field(default_factory=dict)
    node_depths: dict[str, int] = field(default_factory=dict)

    def add_node(self, node_id: str, node_type: str | None = None, depth: int | None = None) -> None:
        normalized = str(node_id).strip()
        if not normalized:
            return
        self.nodes.add(normalized)
        self.outgoing.setdefault(normalized, [])
        self.incoming.setdefault(normalized, [])
        if node_type:
            existing_type = self.node_types.get(normalized)
            if not existing_type or existing_type == "Unknown":
                self.node_types[normalized] = str(node_type).strip()
        if depth is not None:
            existing_depth = self.node_depths.get(normalized)
            if existing_depth is None or depth < existing_depth:
                self.node_depths[normalized] = depth

    def add_edge(self, source: str, target: str) -> None:
        normalized_source = str(source).strip()
        normalized_target = str(target).strip()
        if not normalized_source or not normalized_target:
            return

        self.add_node(normalized_source)
        self.add_node(normalized_target)
        if normalized_target not in self.outgoing[normalized_source]:
            self.outgoing[normalized_source].append(normalized_target)
        if normalized_source not in self.incoming[normalized_target]:
            self.incoming[normalized_target].append(normalized_source)

    def get_node(self, node_id: str) -> str | None:
        normalized = str(node_id).strip()
        return normalized if normalized in self.nodes else None

    def get_outgoing(self, node_id: str) -> list[str]:
        return list(self.outgoing.get(str(node_id).strip(), []))

    def get_incoming(self, node_id: str) -> list[str]:
        return list(self.incoming.get(str(node_id).strip(), []))

    def get_node_type(self, node_id: str) -> str:
        normalized = str(node_id).strip()
        return self.node_types.get(normalized, "Unknown")

    def get_node_depth(self, node_id: str) -> int | None:
        normalized = str(node_id).strip()
        return self.node_depths.get(normalized)


def pseudo_random_from_id(node_id: str) -> float:
    value = str(node_id or "")
    hash_value = 0

    for character in value:
        hash_value = ord(character) + ((hash_value << 5) - hash_value)

    return abs(hash_value % 100) / 100.0


def compute_stable_probability(node_id: str) -> float:
    base = 0.6
    spread = 0.3
    variation = pseudo_random_from_id(node_id)
    return min(base + variation * spread, 0.95)


def get_risk_label(probability: float) -> str:
    if probability >= 0.80:
        return "HIGH"
    if probability >= 0.65:
        return "MEDIUM"
    return "LOW"


def get_high_risk_node_ids(risk_assets: list[dict[str, Any]] | None = None) -> list[str]:
    assets = list(risk_assets or get_top_asset_risk_scores())
    high_risk = [
        str(asset.get("asset_name") or asset.get("asset") or asset.get("name") or "").strip()
        for asset in assets
        if str(asset.get("risk_level") or "").upper() in {"HIGH", "CRITICAL"}
    ]

    high_risk = [node_id for node_id in high_risk if node_id]
    if high_risk:
        return list(dict.fromkeys(high_risk))

    fallback = [
        str(asset.get("asset_name") or asset.get("asset") or asset.get("name") or "").strip()
        for asset in assets[:3]
    ]
    return [node_id for node_id in fallback if node_id]


def build_prediction_graph(seed_node_ids: list[str]) -> PredictionGraphView:
    graph = PredictionGraphView()
    queue: deque[tuple[str, int]] = deque()
    visited_depths: dict[str, int] = {}

    for seed_node_id in seed_node_ids:
        normalized_seed = str(seed_node_id or "").strip()
        if not normalized_seed:
            continue

        graph.add_node(normalized_seed, depth=0)
        queue.append((normalized_seed, 0))
        visited_depths[normalized_seed] = 0

    while queue:
        current_node, current_depth = queue.popleft()
        if current_depth >= 2:
            continue

        relationships = fetch_asset_relationships(current_node)

        for relationship in relationships:
            neighbor = str(relationship.get("neighbor") or "").strip()
            if not neighbor:
                continue

            neighbor_type = _normalize_node_type(relationship.get("neighbor_labels"))
            graph.add_node(neighbor, node_type=neighbor_type, depth=current_depth + 1)
            direction = str(relationship.get("direction") or "").lower()
            if direction == "outgoing":
                graph.add_edge(current_node, neighbor)
            elif direction == "incoming":
                graph.add_edge(neighbor, current_node)

            next_depth = current_depth + 1
            previous_depth = visited_depths.get(neighbor)
            if previous_depth is None or next_depth < previous_depth:
                visited_depths[neighbor] = next_depth
                queue.append((neighbor, next_depth))

    return graph


def derive_next_targets(graph: PredictionGraphView, high_risk_nodes: list[str]) -> list[dict[str, Any]]:
    predictions: list[dict[str, Any]] = []
    seen_nodes: dict[str, dict[str, Any]] = {}
    high_risk_set = {str(node_id).strip() for node_id in high_risk_nodes if str(node_id).strip()}

    for target_id in sorted(graph.nodes):
        if target_id in high_risk_set:
            continue

        target_type = graph.get_node_type(target_id)
        if not _is_attackable_node_type(target_type):
            continue

        distance = graph.get_node_depth(target_id)
        if distance is None or distance <= 0:
            continue

        reason = _prediction_reason_for_depth(distance)
        probability = compute_stable_probability(target_id)
        prediction = {
            "node": target_id,
            "probability": probability,
            "label": get_risk_label(probability),
            "reasons": [reason],
        }

        existing = seen_nodes.get(target_id)
        if existing is None or float(existing.get("probability") or 0.0) < probability:
            seen_nodes[target_id] = prediction

    predictions = list(seen_nodes.values())
    predictions.sort(key=lambda item: float(item.get("probability") or 0.0), reverse=True)
    return predictions[:3]


def predict_next_targets(*_args: Any, **_kwargs: Any) -> list[dict[str, Any]]:
    """Return predicted next targets for an attack path context."""
    risk_assets = _kwargs.get("risk_assets")
    seed_node_ids = get_high_risk_node_ids(risk_assets if isinstance(risk_assets, list) else None)

    if not seed_node_ids:
        top_assets = _kwargs.get("top_assets")
        if isinstance(top_assets, list):
            for asset in top_assets:
                if isinstance(asset, dict):
                    candidate_name = str(asset.get("asset_name") or asset.get("name") or asset.get("node") or "").strip()
                    if candidate_name:
                        seed_node_ids.append(candidate_name)

    if not seed_node_ids:
        for key in ("asset_name", "target"):
            value = str(_kwargs.get(key) or "").strip()
            if value:
                seed_node_ids = [value]
                break

    if not seed_node_ids:
        nodes = _kwargs.get("nodes")
        if isinstance(nodes, list) and nodes:
            seed_node_ids = [str(nodes[-1]).strip()]

    if not seed_node_ids:
        paths = _kwargs.get("paths")
        if isinstance(paths, list):
            for path in paths:
                if isinstance(path, dict):
                    candidate_nodes = path.get("nodes") or []
                    if candidate_nodes:
                        seed_node_ids.append(str(candidate_nodes[-1]).strip())

    if not seed_node_ids:
        seed_node_ids = get_high_risk_node_ids(get_top_asset_risk_scores())

    seed_node_ids = [node_id for node_id in dict.fromkeys(seed_node_ids) if node_id]
    if not seed_node_ids:
        return derive_next_targets(PredictionGraphView(), [])

    graph = build_prediction_graph(seed_node_ids)
    predictions = derive_next_targets(graph, seed_node_ids)
    if predictions:
        return predictions

    fallback_predictions: list[dict[str, Any]] = []
    top_assets = _kwargs.get("risk_assets") if isinstance(_kwargs.get("risk_assets"), list) else get_top_asset_risk_scores()
    for asset in top_assets:
        if not isinstance(asset, dict):
            continue

        node_id = str(asset.get("asset_name") or asset.get("name") or asset.get("node") or "").strip()
        node_type = str(asset.get("node_type") or asset.get("type") or "").strip()
        if not node_id or not _is_attackable_node_type(node_type):
            continue

        probability = compute_stable_probability(node_id)
        fallback_predictions.append(
            {
                "node": node_id,
                "probability": probability,
                "label": get_risk_label(probability),
                "reasons": [_prediction_reason_for_depth(0, fallback=True)],
            }
        )

        if len(fallback_predictions) >= 3:
            break

    return fallback_predictions