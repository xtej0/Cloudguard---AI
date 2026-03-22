from app.neo4j_config import test_connection as check_connection


def test_neo4j_connection_message() -> None:
	assert check_connection() == "CloudGuard Neo4j Connected"
