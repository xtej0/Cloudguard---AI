# CloudGuard AI

CloudGuard AI is a local cybersecurity demo system for cloud attack-path analysis, risk scoring, ML-assisted risk prediction, mitigation recommendations, and dashboard visualization.

## Current Stack

Frontend:

- Static HTML, CSS, and JavaScript
- Cytoscape.js for graph visualization
- Runs through VS Code Live Server or any static file server

Backend:

- Python
- FastAPI
- Neo4j official Python driver
- NetworkX-style in-memory graph utilities for tests
- Scikit-learn model inference through saved `joblib` artifacts

Database:

- Neo4j graph database

ML:

- Synthetic dataset in `datasets/synthetic_attack_dataset.csv`
- Training script in `ml/train_model.py`
- Saved model and encoders in `models/`

## Project Structure

```text
frontend/   Static dashboard UI
backend/    FastAPI backend, graph/risk/prediction services, tests
database/   Database-related project files
datasets/   Synthetic dataset and generation/inspection scripts
docs/       Architecture, response, ML, and evaluation documentation
ml/         Model training script
models/     Saved model and encoder artifacts
```

## Core Features

- Shortest attack path API
- Full infrastructure graph API
- Attack-risk summary API
- Ranked risk scoring
- Single-asset risk lookup
- ML risk-level prediction
- Graph/risk/model-informed next-target ranking
- Integrated asset analysis
- Contextual mitigation recommendations
- Interactive dashboard with graph search, presets, export, and attack simulation

## Environment Variables

Copy `.env.example` or create `backend/.env` with:

```env
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=password
BACKEND_PORT=8000
```

Update the Neo4j password to match your local database.

## Run Neo4j

Start Neo4j locally or through Neo4j Desktop. Confirm the Bolt URL is available at:

```text
bolt://localhost:7687
```

## Seed The Demo Graph

From the project root:

```powershell
cd backend
python seed_graph.py
```

If your VS Code terminal already has the project virtual environment active, use the same command from inside `backend/`.

## Run The Backend

From `backend/`:

```powershell
uvicorn app.main:app --reload
```

The backend should run at:

```text
http://127.0.0.1:8000
```

Useful checks:

```text
http://127.0.0.1:8000/
http://127.0.0.1:8000/health
http://127.0.0.1:8000/docs
```

## Run The Frontend

Recommended:

1. Open the project in VS Code.
2. Right-click `frontend/index.html`.
3. Select `Open with Live Server`.

The dashboard will call the backend at:

```text
http://localhost:8000
```

## Run Tests

From `backend/` with the virtual environment active:

```powershell
pytest
```

Or from the project root:

```powershell
pytest backend/tests
```

Some tests require Neo4j to be running and seeded.

## Main API Endpoints

```text
GET  /
GET  /health
GET  /attack-path?start=Internet&target=Database Server
GET  /all-paths?start=Internet&target=Database Server
GET  /attack-risk-summary?start=Internet&target=Database Server
GET  /risk-score
GET  /risk-score/{asset_name}
POST /predict-compromise
GET  /asset-analysis/{asset_name}
```

## Demo Flow

1. Start Neo4j.
2. Seed the graph.
3. Start the FastAPI backend.
4. Open the dashboard with Live Server.
5. Load `/attack-path`.
6. Load `/risk-score`.
7. Run `/predict-compromise`.
8. Use asset analysis presets.
9. Search graph nodes such as `Database Server`, `IAM Role`, and `Storage Bucket`.
10. Run the attack simulation for the Internet-to-Database scenario.

## Notes

- The frontend is not currently Electron/React/Tailwind. It is a static dashboard by design.
- The ML model predicts multiclass `risk_level`, not a binary compromised flag.
- Next-target ranking combines graph reachability, risk data, and model context.
- The dataset is synthetic and intended for academic/demo use.
