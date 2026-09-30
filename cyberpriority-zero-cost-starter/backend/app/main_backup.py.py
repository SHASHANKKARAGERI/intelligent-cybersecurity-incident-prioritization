from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime, timezone
import sqlite3
import json
import os
import random

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "cyberpriority.db")

app = FastAPI(title="CyberPriority API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class IncidentIn(BaseModel):
    title: str
    category: str = "Suspicious Activity"
    host: str = "unknown-host"
    asset_type: str = "Workstation"
    user: str = "unknown"
    user_privilege: int = Field(50, ge=0, le=100)
    threat_severity: int = Field(50, ge=0, le=100)
    asset_criticality: int = Field(50, ge=0, le=100)
    attack_confidence: int = Field(50, ge=0, le=100)
    exploitability: int = Field(50, ge=0, le=100)
    business_impact: int = Field(50, ge=0, le=100)
    network_exposure: int = Field(50, ge=0, le=100)
    events: List[str] = []

WEIGHTS = {
    "threat_severity": 0.20,
    "asset_criticality": 0.20,
    "user_privilege": 0.15,
    "attack_confidence": 0.20,
    "exploitability": 0.10,
    "business_impact": 0.15,
}

def score_incident(x: IncidentIn):
    raw = sum(getattr(x, k) * w for k, w in WEIGHTS.items())
    # Exposure can increase contextual risk, but mitigation is intentionally
    # kept out of the base score for transparency.
    score = round(min(100, raw * 0.85 + x.network_exposure * 0.15))
    if score >= 90:
        priority = "P1"
        label = "CRITICAL"
    elif score >= 75:
        priority = "P2"
        label = "HIGH"
    elif score >= 50:
        priority = "P3"
        label = "MEDIUM"
    else:
        priority = "P4"
        label = "LOW"

    reasons = []
    if x.threat_severity >= 80: reasons.append("High threat severity")
    if x.asset_criticality >= 80: reasons.append("Critical asset involved")
    if x.user_privilege >= 80: reasons.append("Privileged account involved")
    if x.attack_confidence >= 80: reasons.append("High attack confidence")
    if x.exploitability >= 80: reasons.append("High exploitability")
    if x.business_impact >= 80: reasons.append("Potentially high business impact")
    if len(x.events) >= 4: reasons.append("Multiple related telemetry events")
    if not reasons: reasons.append("Risk factors are below the high-confidence thresholds")

    return score, priority, label, reasons

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    conn.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        category TEXT,
        host TEXT,
        asset_type TEXT,
        user TEXT,
        score INTEGER,
        priority TEXT,
        label TEXT,
        confidence INTEGER,
        factors TEXT,
        events TEXT,
        status TEXT DEFAULT 'Open',
        created_at TEXT
    )
    """)
    conn.commit()
    conn.close()

def row_to_dict(r):
    d = dict(r)
    d["factors"] = json.loads(d["factors"] or "[]")
    d["events"] = json.loads(d["events"] or "[]")
    return d

def insert_incident(x: IncidentIn):
    score, priority, label, reasons = score_incident(x)
    confidence = x.attack_confidence
    conn = db()
    cur = conn.execute("""
        INSERT INTO incidents
        (title, category, host, asset_type, user, score, priority, label,
         confidence, factors, events, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        x.title, x.category, x.host, x.asset_type, x.user, score, priority,
        label, confidence, json.dumps(reasons), json.dumps(x.events),
        "Open", datetime.now(timezone.utc).isoformat()
    ))
    conn.commit()
    r = conn.execute("SELECT * FROM incidents WHERE id=?", (cur.lastrowid,)).fetchone()
    conn.close()
    return row_to_dict(r)

@app.on_event("startup")
def startup():
    init_db()
    conn = db()
    count = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    conn.close()
    if count == 0:
        seed_demo_data()

def seed_demo_data():
    samples = [
        IncidentIn(
            title="Cobalt Strike Beaconing & LSASS Memory Dump",
            category="Credential Access",
            host="DC-CORP-EAST.int",
            asset_type="Domain Controller",
            user="admin",
            user_privilege=100, threat_severity=98, asset_criticality=100,
            attack_confidence=95, exploitability=92, business_impact=98,
            network_exposure=70,
            events=["Suspicious Kerberos Ticket Request", "Known C2 Beacon Pattern",
                    "LSASS Memory Read", "Privileged Process Started"]
        ),
        IncidentIn(
            title="Unusual Bulk Data Egress",
            category="Exfiltration",
            host="prod-customer-db",
            asset_type="Production Database",
            user="service-account",
            user_privilege=85, threat_severity=90, asset_criticality=100,
            attack_confidence=91, exploitability=75, business_impact=96,
            network_exposure=88,
            events=["Large Outbound Transfer", "Unknown ASN", "Database Export"]
        ),
        IncidentIn(
            title="Spear-Phishing Payload Execution & Persistence",
            category="Execution",
            host="laptop-cfo-win11",
            asset_type="Executive Workstation",
            user="executive-user",
            user_privilege=80, threat_severity=72, asset_criticality=82,
            attack_confidence=88, exploitability=70, business_impact=84,
            network_exposure=55,
            events=["Malicious Attachment Opened", "PowerShell Execution",
                    "Scheduled Task Created"]
        ),
        IncidentIn(
            title="Repeated SSH Password Spraying",
            category="Initial Access",
            host="bastion-ssh.edge.internal",
            asset_type="SSH Gateway",
            user="unknown",
            user_privilege=60, threat_severity=60, asset_criticality=70,
            attack_confidence=94, exploitability=65, business_impact=62,
            network_exposure=90,
            events=["31 Failed SSH Logins", "Multiple Source IPs"]
        ),
    ]
    for s in samples:
        insert_incident(s)

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "CyberPriority API"}

@app.get("/api/incidents")
def incidents():
    conn = db()
    rows = conn.execute("""
        SELECT * FROM incidents
        ORDER BY score DESC, id DESC
    """).fetchall()
    conn.close()
    return [row_to_dict(r) for r in rows]

@app.get("/api/incidents/{incident_id}")
def incident(incident_id: int):
    conn = db()
    r = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    conn.close()
    if not r:
        raise HTTPException(404, "Incident not found")
    return row_to_dict(r)

@app.post("/api/incidents")
def create_incident(x: IncidentIn):
    return insert_incident(x)

@app.post("/api/incidents/{incident_id}/action")
def response_action(incident_id: int, action: str):
    allowed = {"isolate": "Host isolation simulated",
               "block": "Source blocking simulated",
               "investigate": "Investigation workflow opened",
               "close": "Ticket closed"}
    if action not in allowed:
        raise HTTPException(400, "Unknown action")
    conn = db()
    if action == "close":
        conn.execute("UPDATE incidents SET status='Closed' WHERE id=?", (incident_id,))
        conn.commit()
    r = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    conn.close()
    if not r:
        raise HTTPException(404, "Incident not found")
    result = row_to_dict(r)
    result["action_result"] = allowed[action]
    return result

@app.post("/api/simulate")
def simulate():
    # Safe, synthetic attack scenario. No external systems are touched.
    host = random.choice(["dc-demo-01.internal", "finance-db-demo", "exec-laptop-demo"])
    x = IncidentIn(
        title="Simulated Account Compromise Chain",
        category="Correlated Attack",
        host=host,
        asset_type="Critical Server",
        user="admin",
        user_privilege=100,
        threat_severity=94,
        asset_criticality=96,
        attack_confidence=97,
        exploitability=90,
        business_impact=95,
        network_exposure=85,
        events=[
            "Multiple failed administrator logins",
            "Successful privileged login",
            "Suspicious PowerShell execution",
            "Privilege escalation detected",
            "Sensitive resource accessed",
            "Outbound connection to unknown destination",
        ]
    )
    return insert_incident(x)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
