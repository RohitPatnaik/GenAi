#!/usr/bin/env python3
"""
Executor Module

Runs an exploit script from knowledgebase/<CVE>/<CVE>.py against a target URL.
Captures stdout/stderr, logs, and returns a result dict.
"""

import os
import sys
import subprocess
import logging
import json
import time
import ast
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import (
    KNOWLEDGEBASE_DIR,
    REPORTS_DIR,
    LOGS_DIR,
    SCRIPT_RESULTS_DIR,
    SANDBOX_DOCKER,
    SANDBOX_DOCKER_IMAGE,
    SANDBOX_DOCKER_FALLBACK,
    SANDBOX_TIMEOUT,
)
from utils.file_utils import get_cve_script_path
from db.models import get_vulnerability_by_cve, add_scan_event, add_scan_result

logger = logging.getLogger(__name__)

# Ensure directories exist
os.makedirs(KNOWLEDGEBASE_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(SCRIPT_RESULTS_DIR, exist_ok=True)

def ensure_docker_running(
    job_id: Optional[str] = None,
    stage: str = "sandbox",
    wait_seconds: int = 20,
    interval_seconds: int = 2,
) -> bool:
    """
    Hard-fail if Docker is not running (sandbox-only execution).
    """
    if SANDBOX_DOCKER != "1":
        return True
    deadline = time.time() + max(0, wait_seconds)
    while True:
        try:
            proc = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except Exception:
            proc = None

        if proc and proc.returncode == 0:
            return True

        if time.time() >= deadline:
            break
        time.sleep(max(1, interval_seconds))

    msg = "Docker not running. Start Docker Desktop to enable sandbox isolation."
    if job_id:
        add_scan_event(job_id, stage, "error", msg)
    raise RuntimeError(msg)

_IMPORT_PACKAGE_MAP = {
    "bs4": "beautifulsoup4",
    "yaml": "pyyaml",
    "Crypto": "pycryptodome",
    "PIL": "pillow",
    "cv2": "opencv-python",
}

_IGNORE_IMPORTS = {
    "os", "sys", "re", "json", "time", "datetime", "pathlib", "typing",
    "math", "random", "subprocess", "itertools", "collections", "logging",
    "urllib", "http", "socket", "ssl", "hashlib", "base64", "gzip",
    "csv", "html", "xml", "argparse", "functools", "inspect", "asyncio",
}

def _extract_imports(script_path: str) -> set:
    """
    Return top-level imported module names from a Python script.
    """
    try:
        src = Path(script_path).read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(src)
    except Exception:
        return set()

    mods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mods.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                mods.add(node.module.split(".")[0])
    return {m for m in mods if m and m not in _IGNORE_IMPORTS}

def run_exploit(
    cve: str,
    target_url: str,
    timeout: int = SANDBOX_TIMEOUT,
    job_id: str = None,
    stage: str = "execute",
) -> Dict[str, Any]:
    """
    Run the exploit script for the given CVE against target_url.

    Args:
        cve: CVE identifier (e.g., "CVE-2021-44228")
        target_url: Target URL to test
        timeout: Maximum execution time in seconds

    Returns:
        Dict with keys:
            - success (bool): whether exploit succeeded (based on return code/heuristics)
            - returncode (int)
            - stdout (str)
            - stderr (str)
            - error (str, if any)
            - script_path (str)
            - timestamp (str)
    """
    db_record = None
    try:
        db_record = get_vulnerability_by_cve(cve)
    except Exception:
        db_record = None

    if db_record and db_record.get("script_path"):
        script_path = os.path.abspath(db_record["script_path"])
        logger.info(f"Using DB script_path for {cve}: {script_path}")
    else:
        script_path = os.path.abspath(get_cve_script_path(cve))
        logger.info(f"Using default script_path for {cve}: {script_path}")
    timestamp = datetime.now().isoformat()

    result = {
        "cve": cve,
        "target": target_url,
        "timestamp": timestamp,
        "script_path": script_path,
        "success": False,
        "returncode": None,
        "stdout": "",
        "stderr": "",
        "error": None
    }

    # Check if script exists
    if not os.path.isfile(script_path):
        error_msg = f"Script not found: {script_path}"
        logger.error(error_msg)
        result["error"] = error_msg
        return result

    # Ensure script is executable? Not strictly needed if we call with python.
    # We'll run with python interpreter to be safe.
    cmd = [sys.executable, script_path, target_url]
    run_cwd = SCRIPT_RESULTS_DIR if os.path.isdir(SCRIPT_RESULTS_DIR) else None

    # Capture files created by the script in SCRIPT_RESULTS_DIR
    pre_files = set()
    if run_cwd:
        pre_files = set(p.name for p in Path(run_cwd).glob("*") if p.is_file())

    logger.info(f"Running exploit for {cve} against {target_url}")
    if job_id:
        add_scan_event(job_id, stage, "info", f"Running exploit for {cve}")
    try:
        if stage == "sandbox" and SANDBOX_DOCKER == "1":
            ensure_docker_running(job_id=job_id, stage=stage)
            proc = _run_in_docker(script_path, target_url, timeout, job_id=job_id, stage=stage)
        else:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,  # don't raise on non-zero return
                cwd=run_cwd
            )
        result["returncode"] = proc.returncode
        result["stdout"] = proc.stdout
        result["stderr"] = proc.stderr

        # Determine success: you can customize heuristics
        # By default, consider return code 0 as success
        if proc.returncode == 0:
            # Optionally, you could also check for keywords in stdout
            result["success"] = True
        else:
            result["success"] = False

        logger.info(f"Exploit completed with return code {proc.returncode}")
        if job_id:
            add_scan_event(job_id, stage, "info", f"{cve} completed (return code {proc.returncode})")

    except subprocess.TimeoutExpired as e:
        result["error"] = f"Timeout expired ({timeout}s)"
        logger.error(result["error"])
        if job_id:
            add_scan_event(job_id, stage, "error", result["error"])
    except Exception as e:
        # Hard-fail for Docker issues so the pipeline stops cleanly.
        msg = str(e)
        if isinstance(e, RuntimeError) and ("Docker not running" in msg or "Sandbox image not found" in msg):
            raise
        result["error"] = msg
        logger.exception(f"Unexpected error running exploit: {e}")
        if job_id:
            add_scan_event(job_id, stage, "error", result["error"])

    # Identify new files created by the script
    created_files = []
    if run_cwd:
        post_files = set(p.name for p in Path(run_cwd).glob("*") if p.is_file())
        new_files = sorted(post_files - pre_files)
        for name in new_files:
            p = Path(run_cwd) / name
            entry = {
                "name": name,
                "path": str(p),
                "size": p.stat().st_size
            }
            # For small text/json files, include content inline
            if p.suffix.lower() in {".json", ".txt", ".log"} and entry["size"] <= 1_000_000:
                try:
                    entry["content"] = p.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    entry["content"] = None
            created_files.append(entry)
    result["script_result_dir"] = os.path.abspath(SCRIPT_RESULTS_DIR)
    result["script_created_files"] = created_files

    # File backups disabled; results are stored in DB

    if job_id:
        try:
            add_scan_result(job_id, {**result, "stage": stage})
        except Exception:
            pass
    return result


def _run_in_docker(
    script_path: str,
    target_url: str,
    timeout: int,
    job_id: Optional[str] = None,
    stage: str = "sandbox",
) -> subprocess.CompletedProcess:
    """
    Execute the exploit script inside a Docker container for sandbox isolation.
    Requires Docker to be installed and running.
    """
    script_dir = os.path.dirname(os.path.abspath(script_path))
    script_name = os.path.basename(script_path)
    workdir = "/work"

    # Auto-install missing deps based on script imports (fallback).
    imports = _extract_imports(script_path)
    pkgs = []
    for m in sorted(imports):
        pkg = _IMPORT_PACKAGE_MAP.get(m, m)
        if pkg:
            pkgs.append(pkg)
    pkg_str = " ".join(pkgs)

    install_cmd = ""
    if pkg_str:
        install_cmd = f"python -m pip -q install --no-cache-dir {pkg_str} >/dev/null 2>&1 || true; "

    inner_cmd = f"{install_cmd}python {script_name} {target_url}"

    docker_cmd = [
        "docker", "run", "--rm",
        "-v", f"{script_dir}:{workdir}:ro",
        "-w", workdir,
        SANDBOX_DOCKER_IMAGE,
        "sh", "-c", inner_cmd
    ]

    proc = subprocess.run(
        docker_cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )

    if proc.returncode != 0:
        err = (proc.stderr or "") + (proc.stdout or "")
        low = err.lower()
        if "cannot connect to the docker daemon" in low or "is the docker daemon running" in low:
            msg = "Docker not running. Start Docker Desktop to enable sandbox isolation."
            if job_id:
                add_scan_event(job_id, stage, "error", msg)
            raise RuntimeError(msg)
        if ("pull access denied" in low) or ("manifest" in low and "not found" in low):
            msg = (
                f"Sandbox image not found: {SANDBOX_DOCKER_IMAGE}. "
                "Build it with: docker build -t vulnops-sandbox:latest -f sandbox/Dockerfile ."
            )
            if job_id:
                add_scan_event(job_id, stage, "error", msg)
            raise RuntimeError(msg)
    return proc

def main():
    """Standalone test: run an exploit if CVE and target provided."""
    if len(sys.argv) < 3:
        print("Usage: python -m executor.runner <CVE> <target_url>")
        sys.exit(1)
    cve = sys.argv[1]
    target = sys.argv[2]
    logging.basicConfig(level=logging.INFO)
    res = run_exploit(cve, target)
    print(json.dumps(res, indent=2))

if __name__ == '__main__':
    main()
