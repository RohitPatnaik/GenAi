#!/usr/bin/env python3
"""
FastAPI backend for the VULNOPS frontend.
Provides endpoints for CVE data, reports, script results, ingestion, and runs.
"""

import os
import json
import uuid
import threading
import subprocess
from datetime import datetime
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, UploadFile, File, HTTPException, Body
from fastapi.responses import FileResponse, Response
import asyncio
from fastapi.middleware.cors import CORSMiddleware

from config import REPORTS_DIR, SCRIPT_RESULTS_DIR, LOGS_DIR
from db.connection import init_db, ensure_schema
from db.models import (
    get_all_vulnerabilities,
    create_scan_job,
    update_scan_job,
    get_scan_job,
    add_scan_event,
    get_scan_events,
    get_scan_results,
    get_scan_result,
    get_scan_reports,
    get_scan_report,
)
from scanner_parser.parser import parse_raw_input, write_normalized

DISABLE_CLIENT_FILTER = os.getenv("DISABLE_CLIENT_FILTER", "0") == "1"

app = FastAPI(title="VULNOPS API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def suppress_cancelled_errors(request, call_next):
    try:
        return await call_next(request)
    except asyncio.CancelledError:
        return Response(status_code=499)

@app.on_event("startup")
def _startup():
    init_db()
    ensure_schema()


def _list_files(dir_path: str, exts: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    if not os.path.isdir(dir_path):
        return []
    entries = []
    for name in os.listdir(dir_path):
        path = os.path.join(dir_path, name)
        if not os.path.isfile(path):
            continue
        if exts and os.path.splitext(name)[1].lower() not in exts:
            continue
        stat = os.stat(path)
        entries.append({
            "name": name,
            "path": path,
            "size": stat.st_size,
            "mtime": stat.st_mtime
        })
    entries.sort(key=lambda x: x["mtime"], reverse=True)
    return entries


def _read_json_file(dir_path: str, name: str) -> Dict[str, Any]:
    path = os.path.join(dir_path, name)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="File not found")
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return json.load(f)


def _job_owned_by_client(job_id: Optional[str], client_id: str) -> bool:
    if DISABLE_CLIENT_FILTER:
        return True
    if not job_id:
        return False
    try:
        job = get_scan_job(job_id)
        return bool(job and job.get("created_by") == client_id)
    except Exception:
        return False


@app.get("/api/health")
def health():
    return {"status": "ok", "time": datetime.utcnow().isoformat() + "Z"}


@app.get("/api/vulns")
def vulns():
    rows = get_all_vulnerabilities()
    return {"items": rows}


@app.get("/api/reports")
def reports(client_id: Optional[str] = None, lite: bool = False):
    items = get_scan_reports(limit=50, lite=lite)
    if client_id and not DISABLE_CLIENT_FILTER:
        items = [r for r in items if _job_owned_by_client(r.get("job_id"), client_id)]
    if lite:
        items = [
            {
                "id": r.get("id"),
                "job_id": r.get("job_id"),
                "created_at": r.get("created_at"),
            }
            for r in items
        ]
    return {"items": items}


@app.get("/api/report/latest")
def report_latest_alias(client_id: Optional[str] = None):
    items = get_scan_reports(limit=1)
    if client_id and not DISABLE_CLIENT_FILTER:
        items = [r for r in items if _job_owned_by_client(r.get("job_id"), client_id)]
    if not items:
        raise HTTPException(status_code=404, detail="No reports found")
    return items[0].get("summary_json") or {}


@app.get("/api/report/{report_id}")
def report(report_id: int, client_id: Optional[str] = None):
    row = get_scan_report(report_id)
    if not row:
        raise HTTPException(status_code=404, detail="Report not found")
    if client_id and not DISABLE_CLIENT_FILTER and not _job_owned_by_client(row.get("job_id"), client_id):
        raise HTTPException(status_code=404, detail="Report not found")
    return row.get("summary_json") or {}


@app.get("/api/report-file/{report_id}")
def report_file(report_id: int, client_id: Optional[str] = None):
    row = get_scan_report(report_id)
    if not row:
        raise HTTPException(status_code=404, detail="Report not found")
    if client_id and not DISABLE_CLIENT_FILTER and not _job_owned_by_client(row.get("job_id"), client_id):
        raise HTTPException(status_code=404, detail="Report not found")
    return row.get("summary_json") or {}


@app.get("/api/script-results")
def script_results(client_id: Optional[str] = None, job_id: Optional[str] = None, lite: bool = False):
    items = get_scan_results(job_id=job_id, limit=200, lite=lite)
    if client_id and not DISABLE_CLIENT_FILTER:
        items = [r for r in items if _job_owned_by_client(r.get("job_id"), client_id)]
    if lite:
        items = [
            {
                "id": r.get("id"),
                "job_id": r.get("job_id"),
                "cve": r.get("cve"),
                "stage": r.get("stage"),
                "success": r.get("success"),
                "returncode": r.get("returncode"),
                "created_at": r.get("created_at"),
            }
            for r in items
        ]
    return {"items": items}


@app.get("/api/script-result/{result_id}")
def script_result(result_id: int, client_id: Optional[str] = None):
    row = get_scan_result(result_id)
    if not row:
        raise HTTPException(status_code=404, detail="Result not found")
    if client_id and not DISABLE_CLIENT_FILTER and not _job_owned_by_client(row.get("job_id"), client_id):
        raise HTTPException(status_code=404, detail="Result not found")
    return row


@app.get("/api/script-result-file/{result_id}")
def script_result_file(result_id: int, client_id: Optional[str] = None):
    return script_result(result_id, client_id=client_id)


@app.post("/api/ingest")
def ingest(file: UploadFile = File(...)):
    os.makedirs("input", exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_name = file.filename.replace("\\", "_").replace("/", "_")
    save_path = os.path.join("input", f"{ts}_{safe_name}")
    with open(save_path, "wb") as f:
        f.write(file.file.read())

    try:
        normalized = parse_raw_input(save_path)
        output_path = os.path.join("input", f"norm_{ts}.json")
        write_normalized(normalized, output_file=output_path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {"status": "ok", "input_path": save_path, "output_path": output_path, "count": len(normalized)}


@app.post("/api/scan/start")
def start_scan(payload: Dict[str, Any] = Body(...)):
    if not payload.get("target_url"):
        raise HTTPException(status_code=400, detail="target_url is required")
    job_id = str(uuid.uuid4())
    job = {
        "id": job_id,
        "job_name": payload.get("job_name"),
        "priority": payload.get("priority"),
        "source_type": payload.get("source_type"),
        "source_path": payload.get("source_path"),
        "exploit_mode": payload.get("exploit_mode"),
        "fallback_llm": payload.get("fallback_llm"),
        "validation_mode": payload.get("validation_mode"),
        "sandbox_target": payload.get("sandbox_target"),
        "target_url": payload.get("target_url"),
        "input_file": payload.get("input_file"),
        "output_file": payload.get("output_file"),
        "created_by": payload.get("client_id"),
        "status": "queued",
        "stage": "ingest"
    }
    create_scan_job(job)
    add_scan_event(job_id, "ingest", "info", "Job created")

    input_file = payload.get("input_file") or "input/norm_input_newt.json"

    def _worker():
        update_scan_job(job_id, status="running")
        cmd = [os.sys.executable, "main.py", payload.get("target_url"), input_file, job_id]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode == 0:
                update_scan_job(job_id, status="finished", stage="report")
            else:
                update_scan_job(job_id, status="failed", stage="report")
                add_scan_event(job_id, "report", "error", proc.stderr or proc.stdout)
        except Exception as e:
            update_scan_job(job_id, status="failed")
            add_scan_event(job_id, "report", "error", str(e))

    threading.Thread(target=_worker, daemon=True).start()
    return {"job_id": job_id}


@app.get("/api/scan/jobs")
def list_scan_jobs(limit: int = 50, client_id: Optional[str] = None):
    conn = None
    try:
        from db.connection import get_connection
        import psycopg2.extras
        conn = get_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        if client_id:
            cur.execute(
                "SELECT * FROM scan_jobs WHERE created_by = %s ORDER BY created_at DESC LIMIT %s",
                (client_id, limit),
            )
        else:
            cur.execute("SELECT * FROM scan_jobs ORDER BY created_at DESC LIMIT %s", (limit,))
        rows = cur.fetchall()
        cur.close()
        return {"items": rows}
    finally:
        if conn is not None:
            conn.close()


@app.get("/api/reports/latest")
def latest_report(client_id: Optional[str] = None):
    items = get_scan_reports(limit=1)
    if client_id and not DISABLE_CLIENT_FILTER:
        items = [r for r in items if _job_owned_by_client(r.get("job_id"), client_id)]
    if not items:
        raise HTTPException(status_code=404, detail="No reports found")
    return items[0].get("summary_json") or {}


@app.get("/api/scan/{job_id}")
def scan_status(job_id: str, client_id: Optional[str] = None):
    job = get_scan_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if client_id and not DISABLE_CLIENT_FILTER and job.get("created_by") and job.get("created_by") != client_id:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@app.get("/api/scan/{job_id}/events")
def scan_events(job_id: str, limit: int = 200, client_id: Optional[str] = None):
    job = get_scan_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if client_id and not DISABLE_CLIENT_FILTER and job.get("created_by") and job.get("created_by") != client_id:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"items": get_scan_events(job_id, limit=limit)}
