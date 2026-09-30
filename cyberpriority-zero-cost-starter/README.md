# CyberPriority — Intelligent Cybersecurity Incident Prioritization

A zero-cost, GitHub-ready SOC-style incident prioritization dashboard.

## What it does
- Ingests security events and incidents
- Calculates contextual risk from 0–100
- Assigns P1/P2/P3/P4 priority
- Correlates related events
- Shows an explainable decision trace
- Includes a safe attack simulation mode
- Provides simulated response actions
- Stores data locally in SQLite
- No paid API is required

## Stack
- Python + FastAPI
- SQLite
- HTML/CSS/JavaScript frontend
- Optional scikit-learn model
- No external AI/API dependency

## Run on Windows

### 1. Backend
Open CMD in `backend`:

```bat
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
py -m uvicorn app.main:app --reload
```

### 2. Open the dashboard
Open `frontend/index.html` in your browser.

For local API access, the frontend uses `http://127.0.0.1:8000`.

## Project structure

```text
cyberpriority/
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── services/
│   │   └── data/
│   └── requirements.txt
├── frontend/
│   └── index.html
├── data/
└── docs/
```

## Safety
The response buttons in this hackathon version are simulated. They do not actually isolate hosts, block IPs, or modify external systems.

## License
MIT
