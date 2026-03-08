from neo4j import GraphDatabase
import os
from dotenv import load_dotenv

load_dotenv()

URI = os.getenv("NEO4J_URI")
USER = os.getenv("NEO4J_USER")
PASSWORD = os.getenv("NEO4J_PASSWORD")

driver = GraphDatabase.driver(URI, auth=(USER, PASSWORD))


def test_nodes_exist():
    with driver.session() as session:
        result = session.run("MATCH (n) RETURN count(n) AS total")
        total = result.single()["total"]

        assert total >= 7


def test_relationships_exist():
    with driver.session() as session:
        result = session.run("MATCH ()-[r]->() RETURN count(r) AS total")
        total = result.single()["total"]

        assert total >= 5