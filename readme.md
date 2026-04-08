# VULNOPS — AI Pentest Orchestrator

VULNOPS is a local pentest orchestration tool that ingests scan logs, matches CVEs against a knowledgebase, runs sandboxed exploit checks, generates a consolidated report, and validates the report for evidence quality.

---

**Features**
- Ingestion of raw scan logs (JSON)
- CVE matching against a local knowledgebase
- Script generation (LLM) fallback when KB scripts are missing
- Sandboxed execution with evidence markers
- Reports + Script Results + Validator results in UI
- Validator stage that checks evidence quality and consistency
- Pagination for Reports / Script Results / Validator / Knowledgebase

---

**Tech Stack**
- Backend: FastAPI + PostgreSQL
- Frontend: Vite + React
- Sandbox: Docker (optional but recommended)

---

## 1) Prerequisites

- Python 3.11+
- Node.js 18+
- PostgreSQL 14+
- Docker Desktop (recommended)

---

## 2) Project Setup

### 2.1 Create and activate virtual environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2.2 Install Python dependencies
```powershell
pip install -r requirements.txt
```

### 2.3 Frontend dependencies
```powershell
cd frontend
npm install
cd ..
```

---

## 3) Environment Configuration

Create or update `.env`:
```env
# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=vulnerability_db
DB_USER=postgres
DB_PASSWORD=your_password

# OpenAI (optional, only if using LLM generation)
OPENAI_API_KEY=sk-...
MAX_OPENAI_ATTEMPTS=3

# Paths
KNOWLEDGEBASE_DIR=knowledgebase
REPORTS_DIR=reports
LOGS_DIR=logs
SCRIPT_RESULTS_DIR=script_result

# Optional: disable per-browser filtering
DISABLE_CLIENT_FILTER=1
```

---

## 4) Database Setup

Ensure PostgreSQL is running and database exists:
```sql
CREATE DATABASE vulnerability_db;
```

The backend auto-creates tables on startup:
- `network_vulnerabilities`
- `scan_jobs`
- `scan_events`
- `scan_results`
- `scan_reports`
- `validator_results`

---

## 5) Run the Backend (FastAPI)
```powershell
python -m uvicorn api:app --host 127.0.0.1 --port 8000
```

API base: `http://127.0.0.1:8000`

---

## 6) Run the Frontend (Vite)
```powershell
cd frontend
npm run dev
```

UI: `http://localhost:5173`

---

## 7) Basic Usage Flow

### 7.1 Ingest raw scan file
Open UI → **Ingestion** → upload `input/raw_scan.json`  
This creates a normalized file in `input/`.

### 7.2 Launch scan
Open UI → **Dashboard** → **New Scan**

Required fields:
- Target URL
- Source type (File/API/S3)
- Validation mode

### 7.3 Pipeline stages
1. Ingestion  
2. Normalize  
3. Match  
4. Knowledgebase  
5. Generate (LLM if needed)  
6. Sandbox Validate  
7. Report  
8. Validator

---

## 8) Reports + Script Results + Validator

**Reports**
- Aggregated orchestration summary from DB (`scan_reports`)

**Script Results**
- Raw stdout/stderr per CVE run (`scan_results`)

**Validator**
- Validates report evidence and consistency (`validator_results`)

---

## 9) Validator Logic (Summary)
Validator checks:
- Evidence presence and authenticity  
- Forbidden placeholder phrases  
- Payload-to-evidence correlation  
- CVSS score range per severity  
- Consistency between `exploitation_success` and severity  

Validator runs **after report stage**, and stores results in DB.

---

## 10) Optional: Docker Sandbox

Sandboxed execution uses Docker (recommended).
If Docker is not running, execution fails with sandbox errors.

---

## 11) Troubleshooting

**Problem:** Script says “Not Vulnerable” but exploit succeeded  
**Fix:** Ensure script prints evidence marker `[EXPLOIT CONFIRMED]`

**Problem:** Validator shows INVALID with 0 findings  
**Fix:** Ensure the validator is reading the CVE report JSON (stdout) or report contains `vulnerabilities`

**Problem:** Different browsers show different data  
**Fix:** Set `DISABLE_CLIENT_FILTER=1` in `.env`

---

## 12) Useful Commands

Run backend:
```powershell
python -m uvicorn api:app --host 127.0.0.1 --port 8000
```

Run frontend:
```powershell
cd frontend
npm run dev
```

Check API health:
```powershell
curl http://127.0.0.1:8000/api/health
```

---

## 13) Project Structure
```
api.py
main.py
validator/
executor/
db/
frontend/
knowledgebase/
input/
reports/
script_result/
logs/
```


