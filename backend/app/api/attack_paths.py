from fastapi import APIRouter, HTTPException
import time
import logging

from app.neo4j_config import driver
from risk_engine import get_all_asset_risk_scores, compute_risk_score
from app.services.attack_risk_service import get_attack_risk_summary
from app.response_builder import (
    build_attack_path_response,
    build_all_paths_response,
    build_risk_score_response,
    build_attack_risk_response,
    build_single_asset_risk_response,
)
from app.schemas import FinalResponse

router = APIRouter()

logging.basicConfig(level=logging.INFO)


@router.get("/attack-path", response_model=FinalResponse)
def get_attack_path(start: str, target: str):

    start_time = time.time()

    query = """
    MATCH p = shortestPath((a {name:$start})-[*]->(b {name:$target}))
    RETURN nodes(p) as nodes, relationships(p) as rels
    """

    with driver.session() as session:
        result = session.run(query, start=start, target=target)
        record = result.single()

    execution_time = time.time() - start_time

    if not record:
        return build_attack_path_response([], [])

    nodes = [node["name"] for node in record["nodes"]]
    relationships = [rel.type for rel in record["rels"]]

    logging.info(f"Shortest attack path query executed in {execution_time:.4f} seconds")

    return build_attack_path_response(nodes, relationships)


@router.get("/all-paths", response_model=FinalResponse)
def get_all_paths(start: str, target: str):

    start_time = time.time()

    query = """
    MATCH p = (a {name:$start})-[*]->(b {name:$target})
    RETURN nodes(p) AS nodes, relationships(p) AS rels
    """

    with driver.session() as session:
        results = session.run(query, start=start, target=target)

        paths = []
        for record in results:
            nodes = [node["name"] for node in record["nodes"]]
            relationships = [rel.type for rel in record["rels"]]
            paths.append({"nodes": nodes, "relationships": relationships})

    execution_time = time.time() - start_time

    logging.info(f"All attack paths query executed in {execution_time:.4f} seconds")

    return build_all_paths_response(paths)


@router.get(
    "/attack-risk-summary",
    response_model=FinalResponse,
    summary="Get attack risk summary between assets",
    description="Returns a risk summary for attack paths from the start asset to the target asset.",
)
def attack_risk_summary(start: str, target: str):
    try:
        summary = get_attack_risk_summary(start=start, target=target)
        return build_attack_risk_response(summary)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to fetch attack risk summary: {str(exc)}")


@router.get(
    "/risk-score",
    response_model=FinalResponse,
    summary="Get top asset risk scores",
    description="Returns all assets ranked by risk score, including explanations, contributing factors, and attack path details.",
)
def get_top_risk_scores():
    try:
        top_assets = get_all_asset_risk_scores()
        return build_risk_score_response(top_assets)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to fetch asset risk scores: {str(exc)}")


@router.get(
    "/risk-score/{asset_name}",
    response_model=FinalResponse,
    summary="Get risk score for one asset",
    description="Returns risk score details for a single asset, including risk level and attack path details.",
)
def get_asset_risk_score(asset_name: str):
    try:
        risk_data = compute_risk_score(asset_name)
        raw_inputs = risk_data.get("raw_inputs", {})

        asset_data = {
            "asset_name": risk_data.get("asset_name", asset_name),
            "risk_score": risk_data.get("risk_score"),
            "risk_level": risk_data.get("risk_level"),
            "attack_path_details": {
                "attack_path_count": raw_inputs.get("attack_path_count"),
                "shortest_attack_path_length": raw_inputs.get("shortest_attack_path_length"),
            },
        }
        return build_single_asset_risk_response(asset_data)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to fetch risk score for asset '{asset_name}': {str(exc)}")