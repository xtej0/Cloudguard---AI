from app.routes import attack_paths


def test_attack_path_uses_shortest_path_service(monkeypatch):
    captured = {}

    monkeypatch.setattr(attack_paths, "get_asset_existence", lambda start, target: (True, True))
    monkeypatch.setattr(
        attack_paths,
        "get_shortest_attack_path",
        lambda start, target: {
            "nodes": [start, "Gateway", target],
            "relationships": ["EXPOSED_TO", "CONNECTS_TO"],
        },
    )

    def fake_builder(nodes, relationships, **kwargs):
        captured["nodes"] = nodes
        captured["relationships"] = relationships
        captured["kwargs"] = kwargs
        return {"ok": True}

    monkeypatch.setattr(attack_paths, "build_attack_path_response", fake_builder)

    result = attack_paths.attack_path("Internet", "Database Server")

    assert result == {"ok": True}
    assert captured["nodes"] == ["Internet", "Gateway", "Database Server"]
    assert captured["relationships"] == ["EXPOSED_TO", "CONNECTS_TO"]
    assert captured["kwargs"]["start"] == "Internet"
    assert captured["kwargs"]["target"] == "Database Server"


def test_attack_path_returns_empty_path_when_service_finds_no_path(monkeypatch):
    captured = {}

    monkeypatch.setattr(attack_paths, "get_asset_existence", lambda start, target: (True, True))
    monkeypatch.setattr(attack_paths, "get_shortest_attack_path", lambda start, target: None)

    def fake_builder(nodes, relationships, **kwargs):
        captured["nodes"] = nodes
        captured["relationships"] = relationships
        captured["kwargs"] = kwargs
        return {"ok": True}

    monkeypatch.setattr(attack_paths, "build_attack_path_response", fake_builder)

    result = attack_paths.attack_path("Internet", "Storage Bucket")

    assert result == {"ok": True}
    assert captured["nodes"] == []
    assert captured["relationships"] == []
    assert captured["kwargs"]["start_exists"] is True
    assert captured["kwargs"]["target_exists"] is True


def test_all_paths_uses_all_paths_service(monkeypatch):
    paths = [
        {
            "nodes": ["Internet", "Gateway", "Database Server"],
            "relationships": ["EXPOSED_TO", "CONNECTS_TO"],
        }
    ]
    captured = {}

    monkeypatch.setattr(attack_paths, "get_asset_existence", lambda start, target: (True, True))
    monkeypatch.setattr(attack_paths, "get_all_attack_paths", lambda start, target: paths)

    def fake_builder(paths_arg, **kwargs):
        captured["paths"] = paths_arg
        captured["kwargs"] = kwargs
        return {"ok": True}

    monkeypatch.setattr(attack_paths, "build_all_paths_response", fake_builder)

    result = attack_paths.all_paths("Internet", "Database Server")

    assert result == {"ok": True}
    assert captured["paths"] == paths
    assert captured["kwargs"]["start"] == "Internet"
    assert captured["kwargs"]["target"] == "Database Server"
