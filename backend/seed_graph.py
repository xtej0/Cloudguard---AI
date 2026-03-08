from neo4j import GraphDatabase
import os
from dotenv import load_dotenv

load_dotenv()

URI = os.getenv("NEO4J_URI")
USER = os.getenv("NEO4J_USER")
PASSWORD = os.getenv("NEO4J_PASSWORD")

if not URI or not USER or not PASSWORD:
    raise ValueError(
        "Missing Neo4j environment variables. "
        "Please set NEO4J_URI, NEO4J_USER, and NEO4J_PASSWORD in .env."
    )

driver = GraphDatabase.driver(URI, auth=(USER, PASSWORD))


def seed_graph():

    with driver.session() as session:

        # Clear old graph
        session.run("MATCH (n) DETACH DELETE n")

        # Create nodes with security properties

        session.run("""
        CREATE (:Internet {
            name:'Internet',
            trust_level:'untrusted'
        })
        """)

        session.run("""
        CREATE (:VM {
            name:'Web Server VM',
            layer:'web',
            exposed:true,
            criticality:'medium'
        })
        """)

        session.run("""
        CREATE (:VM {
            name:'Application Server VM',
            layer:'application',
            exposed:false,
            criticality:'high'
        })
        """)

        session.run("""
        CREATE (:Database {
            name:'Database Server',
            engine:'PostgreSQL',
            sensitivity:'high'
        })
        """)

        session.run("""
        CREATE (:Bucket {
            name:'Storage Bucket',
            sensitivity:'high',
            contains:'customer_data'
        })
        """)

        session.run("""
        CREATE (:User {
            name:'User',
            privilege:'standard'
        })
        """)

        session.run("""
        CREATE (:IAMRole {
            name:'IAM Role',
            privilege_level:'admin'
        })
        """)

        # Create relationships

        session.run("""
        MATCH (i:Internet),(w:VM {name:'Web Server VM'})
        CREATE (i)-[:EXPOSED_TO]->(w)
        """)

        session.run("""
        MATCH (w:VM {name:'Web Server VM'}),(a:VM {name:'Application Server VM'})
        CREATE (w)-[:CONNECTS_TO]->(a)
        """)

        session.run("""
        MATCH (a:VM {name:'Application Server VM'}),(d:Database)
        CREATE (a)-[:CONNECTS_TO]->(d)
        """)

        session.run("""
        MATCH (u:User),(r:IAMRole)
        CREATE (u)-[:HAS_ACCESS]->(r)
        """)

        session.run("""
        MATCH (d:Database),(b:Bucket)
        CREATE (d)-[:STORES_DATA_IN]->(b)
        """)


if __name__ == "__main__":
    seed_graph()
    print("Cloud infrastructure graph inserted successfully.")
    driver.close()