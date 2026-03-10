from fastapi import APIRouter
import time
import logging

from app.neo4j_config import driver

router = APIRouter()

logging.basicConfig(level=logging.INFO)


@router.get("/attack-path")
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
        return {"message": "No attack path found"}

    nodes = [node["name"] for node in record["nodes"]]
    relationships = [type(rel).__name__ for rel in record["rels"]]

    logging.info(f"Shortest attack path query executed in {execution_time:.4f} seconds")

    return {
        "start_node": start,
        "target_node": target,
        "nodes": nodes,
        "relationships": relationships,
        "path_length": len(nodes),
        "execution_time": execution_time
    }


@router.get("/all-paths")
def get_all_paths(start: str, target: str):

    start_time = time.time()

    query = """
    MATCH p = (a {name:$start})-[*]->(b {name:$target})
    RETURN nodes(p) as nodes
    """

    with driver.session() as session:
        results = session.run(query, start=start, target=target)

        paths = []
        for record in results:
            nodes = [node["name"] for node in record["nodes"]]
            paths.append(nodes)

    execution_time = time.time() - start_time

    logging.info(f"All attack paths query executed in {execution_time:.4f} seconds")

    return {
        "start_node": start,
        "target_node": target,
        "paths": paths,
        "total_paths": len(paths),
        "execution_time": execution_time
    }