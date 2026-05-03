# CloudGuard AI Operations Guide

This guide documents how to run CloudGuard AI locally for development, testing, reports, and demos.

## 1. Install Dependencies

From the project root:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
```

## 2. Configure Environment

Create `backend/.env`:

```env
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=password
BACKEND_PORT=8000
CLOUDGUARD_DEBUG=false
```

Use the actual local Neo4j password.

## 3. Start Neo4j

Start Neo4j with Bolt enabled:

```text
bolt://localhost:7687
```

The backend uses `backend/app/neo4j_config.py` to read the connection settings.

## 4. Seed Graph Data

From the project root:

```powershell
cd backend
..\.venv\Scripts\python.exe seed_graph.py
```

If the virtual environment is active:

```powershell
cd backend
python seed_graph.py
```

## 5. Start Backend

From the project root:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --app-dir backend
```

Verify:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

Expected:

```json
{ "status": "ok" }
```

## 6. Start Frontend

From the project root:

```powershell
python -m http.server 5500 -d frontend
```

Open:

```text
http://127.0.0.1:5500/
```

Alternative: use VS Code Live Server on `frontend/index.html`.

## 7. Run Tests

All backend tests:

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests
```

Focused review suite:

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests/test_attack_risk.py backend/tests/test_attack_path_routes.py backend/tests/test_mitigation_engine.py backend/tests/test_prediction_api.py
```

Notes:

- Neo4j-backed tests require Neo4j to be running.
- Some graph tests also assume the demo graph has been seeded.
- `.pytest_cache` permission warnings do not affect application behavior.

## 8. Retrain ML Model

From the project root:

```powershell
.\.venv\Scripts\python.exe ml\train_model.py
```

Artifacts are written to:

```text
models/risk_model.pkl
models/feature_encoders.pkl
models/target_encoder.pkl
```

## 9. Demo Checklist

- [ ] Neo4j running.
- [ ] Demo graph seeded.
- [ ] Backend running on port 8000.
- [ ] Frontend running on port 5500 or Live Server.
- [ ] `GET /health` returns `{"status":"ok"}`.
- [ ] Dashboard loads without external CDN dependencies.
- [ ] `/attack-path` renders graph edges with preserved relationship labels.
- [ ] `/risk-score` shows ranked assets.
- [ ] `/predict-compromise` returns a model label and probabilities.
- [ ] `/asset-analysis/{asset_name}` returns risk, candidates, prediction, and mitigations.

## 10. Useful URLs

```text
http://127.0.0.1:8000/
http://127.0.0.1:8000/health
http://127.0.0.1:8000/docs
http://127.0.0.1:5500/
```
