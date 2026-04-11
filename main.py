#!/usr/bin/env python3
"""
Orchestrator Module

Main entry point for the vulnerability validation tool.
Reads normalized input, matches CVEs against database, and either runs existing exploits
or generates new ones using OpenAI (with up to MAX_OPENAI_ATTEMPTS retries).
Logs all steps and generates summary reports.
"""

import os
import sys
import logging
import json
import uuid
from datetime import datetime
from typing import Dict, Any, List

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Load configuration
from config import (
    MAX_OPENAI_ATTEMPTS,
    KNOWLEDGEBASE_DIR,
    REPORTS_DIR,
    LOGS_DIR
)

# Import components
from db.models import update_has_script
from scanner_parser.parser import parse_raw_input, write_normalized
from matcher.matcher import match_vulnerabilities
from executor.runner import run_exploit, ensure_docker_running
from db.models import create_scan_job, add_scan_report, get_scan_report, add_validator_result
from db.connection import init_db, ensure_schema
from sync_kb import sync_knowledgebase
from validator.validator import validate_report
from openai_generator.generator import (
    build_initial_prompt,
    save_prompt,
    generate_script_with_openai,
    save_generated_script as save_generated_script_from_generator,
)
from openai_generator.log_analyzer import analyze_failure
from utils.file_utils import get_cve_script_path, ensure_cve_dir
from utils.scanner_logging import (
    setup_scanner_logger,
    log_scan_event as _log_scan_event,
    log_stage_update as _log_stage_update,
)

# Ensure required directories exist
os.makedirs(KNOWLEDGEBASE_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

logger = setup_scanner_logger(__name__, "orchestrator.log", add_stream=True)

def _extract_json_from_text(text: str) -> Dict[str, Any] | None:
    if not text:
        return None
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        return json.loads(text[start:end + 1])
    except Exception:
        return None

def process_vulnerability(vuln: Dict[str, Any], target_url: str, job_id: str = None) -> Dict[str, Any]:
    """
    Process a single vulnerability: run or generate exploit.
    Returns a result dict with status and details.
    """
    cve = vuln['cve']
    action = vuln['action']
    logger.info(f"Processing {cve} with action: {action}")

    result = {
        'cve': cve,
        'target': target_url,
        'action': action,
        'success': False,
        'attempts': [],
        'final_script_path': None,
        'error': None
    }

    if action == 'run':
        # Execute existing script (sandboxed)
        if job_id:
            _log_stage_update(logger, job_id, "sandbox", cve=cve, action=action)
        exec_result = run_exploit(cve, target_url, job_id=job_id, stage="sandbox")
        result['success'] = exec_result.get('success', False)
        result['final_script_path'] = exec_result.get('script_path')
        result['attempts'].append({
            'attempt': 1,
            'type': 'run',
            'result': exec_result
        })
        if result['success']:
            logger.info(f"{cve} exploit succeeded.")
        else:
            logger.warning(f"{cve} exploit failed.")
        # Note: We don't update DB because script already existed.

    elif action == 'generate':
        # Attempt to generate and test script up to MAX_OPENAI_ATTEMPTS
        title = vuln.get('title', 'No title')
        description = vuln.get('description', 'No description')
        current_prompt = build_initial_prompt(cve, title, description)
        if job_id:
            _log_stage_update(logger, job_id, "generate", cve=cve, action=action)
            _log_scan_event(logger, "info", f"{cve} generation started", job_id=job_id, stage="generate")

        for attempt in range(1, MAX_OPENAI_ATTEMPTS + 1):
            logger.info(f"Generation attempt {attempt}/{MAX_OPENAI_ATTEMPTS} for {cve}")
            if job_id:
                _log_scan_event(
                    logger,
                    "info",
                    f"{cve} generation attempt {attempt}",
                    job_id=job_id,
                    stage="generate",
                    cve=cve,
                    attempt=attempt,
                    max_attempts=MAX_OPENAI_ATTEMPTS,
                )
            save_prompt(cve, attempt, current_prompt)

            script_content = generate_script_with_openai(current_prompt)
            if not script_content:
                if job_id:
                    _log_scan_event(
                        logger,
                        "error",
                        f"{cve} generation failed",
                        job_id=job_id,
                        stage="generate",
                        cve=cve,
                        attempt=attempt,
                    )
                result['attempts'].append({
                    'attempt': attempt,
                    'type': 'generate',
                    'error': 'OpenAI generation failed',
                    'prompt': current_prompt
                })
                continue

            script_path = save_generated_script_from_generator(cve, script_content)
            result['attempts'].append({
                'attempt': attempt,
                'type': 'generate',
                'prompt': current_prompt,
                'script_path': script_path
            })

            # Test the generated script (sandboxed)
            if job_id:
                _log_stage_update(logger, job_id, "sandbox", cve=cve, action=action, attempt=attempt)
                _log_scan_event(
                    logger,
                    "info",
                    f"{cve} sandbox validation started",
                    job_id=job_id,
                    stage="sandbox",
                    cve=cve,
                    attempt=attempt,
                )
            test_result = run_exploit(cve, target_url, job_id=job_id, stage="sandbox")
            result['attempts'][-1]['test_result'] = test_result

            if test_result.get('success', False):
                logger.info(f"{cve} exploit succeeded on attempt {attempt}.")
                result['success'] = True
                result['final_script_path'] = script_path
                update_has_script(cve, 1)
                if job_id:
                    _log_scan_event(
                        logger,
                        "info",
                        f"{cve} succeeded on attempt {attempt}",
                        job_id=job_id,
                        stage="generate",
                        cve=cve,
                        attempt=attempt,
                        script_path=script_path,
                    )
                break

            logger.warning(f"{cve} exploit failed on attempt {attempt}.")
            error_log = (test_result.get('stderr', '') or '') + '\n' + (test_result.get('stdout', '') or '')
            if test_result.get('error'):
                error_log += f"\n{test_result['error']}"
            current_prompt = analyze_failure(cve, error_log, current_prompt)
            if job_id:
                _log_scan_event(
                    logger,
                    "info",
                    f"{cve} revised prompt for next attempt",
                    job_id=job_id,
                    stage="generate",
                    cve=cve,
                    attempt=attempt,
                )
        else:
            # All attempts exhausted
            logger.error(f"All {MAX_OPENAI_ATTEMPTS} attempts failed for {cve}.")
            result['error'] = f"Failed after {MAX_OPENAI_ATTEMPTS} attempts."
    else:
        logger.error(f"Unknown action {action} for {cve}")
        result['error'] = f"Unknown action {action}"

    return result

def main():
    """Main orchestrator entry point."""
    target_url = "https://pentest-ground.com:81/"
    job_id = str(uuid.uuid4())

    # Hardcoded input/output directories
    INPUT_DIR = r'C:\aiaptt\ai_input_file'
    NORMALIZED_DIR = r'C:\aiaptt\ai_normalized_file'

    # Find the first JSON file in the input directory
    json_files = [f for f in os.listdir(INPUT_DIR) if f.lower().endswith('.json')]
    if not json_files:
        logger.error(f"No JSON file found in {INPUT_DIR}. Exiting.")
        sys.exit(1)
    input_filename = json_files[0]
    raw_file_path = os.path.join(INPUT_DIR, input_filename)
    normalized_file_path = os.path.join(NORMALIZED_DIR, f"normalized_{input_filename}")

    # Ensure DB schema exists before any job/event writes.
    init_db()
    ensure_schema()
    sync_knowledgebase()  # Sync knowledgebase scripts to DB (set has_script=1 for existing scripts)

    create_scan_job({
        "id": job_id,
        "job_name": f"scan_{input_filename}",
        "priority": "normal",
        "source_type": "file",
        "source_path": raw_file_path,
        "exploit_mode": "orchestrated",
        "fallback_llm": "openai",
        "validation_mode": "validator",
        "sandbox_target": target_url,
        "target_url": target_url,
        "input_file": raw_file_path,
        "output_file": normalized_file_path,
        "created_by": "main.py",
        "status": "created",
        "stage": "init",
    })

    logger.info("=" * 60)
    logger.info("Starting vulnerability orchestration")
    logger.info(f"Target URL: {target_url}")
    logger.info(f"Raw input file: {raw_file_path}")
    logger.info("=" * 60)

    # Step 1: Parse raw input file and save normalized copy
    if job_id:
        _log_stage_update(logger, job_id, "ingest", status="running", input_file=raw_file_path)
        _log_scan_event(logger, "info", f"Reading raw input: {raw_file_path}", job_id=job_id, stage="ingest")

    try:
        vuln_list = parse_raw_input(raw_file_path)
    except Exception as e:
        logger.error(f"Failed to parse raw input: {e}")
        sys.exit(1)

    if not vuln_list:
        logger.error("No vulnerabilities loaded. Exiting.")
        sys.exit(1)

    # Save normalized file to NORMALIZED_DIR with 'normalized_' prefix
    os.makedirs(NORMALIZED_DIR, exist_ok=True)
    write_normalized(vuln_list, normalized_file_path)
    logger.info(f"Normalized file saved: {normalized_file_path}")

    if job_id:
        _log_stage_update(logger, job_id, "parse", vulnerabilities_count=len(vuln_list))
        _log_scan_event(
            logger,
            "info",
            f"Parsed {len(vuln_list)} vulnerabilities",
            job_id=job_id,
            stage="parse",
            vulnerabilities_count=len(vuln_list),
            normalized_file=normalized_file_path,
        )

    # Step 2: Match against database to determine actions
    if job_id:
        _log_stage_update(logger, job_id, "match")
        _log_scan_event(logger, "info", "Matching CVEs against DB", job_id=job_id, stage="match")

    enriched_list = match_vulnerabilities(vuln_list)
    kb_found = sum(1 for v in enriched_list if v.get("action") == "run")
    kb_missing = sum(1 for v in enriched_list if v.get("action") == "generate")
    if job_id:
        _log_stage_update(logger, job_id, "kb", kb_found=kb_found, kb_missing=kb_missing)
        _log_scan_event(logger, "info", "Knowledgebase lookup complete", job_id=job_id, stage="kb")
        _log_scan_event(
            logger,
            "info",
            f"KB scripts found: {kb_found} | to generate: {kb_missing}",
            job_id=job_id,
            stage="kb",
            kb_found=kb_found,
            kb_missing=kb_missing,
        )

    # Step 3: Ensure Docker is running before sandbox execution
    try:
        ensure_docker_running(job_id=job_id, stage="sandbox")
    except Exception as e:
        logger.error(str(e))
        if job_id:
            _log_stage_update(logger, job_id, "sandbox", status="failed")
            _log_scan_event(logger, "error", str(e), job_id=job_id, stage="sandbox")
        sys.exit(1)

    # Step 4: Process each vulnerability
    results = []
    if job_id:
        _log_stage_update(logger, job_id, "sandbox")
        _log_scan_event(logger, "info", "Executing CVE scripts in sandbox", job_id=job_id, stage="sandbox")

    for vuln in enriched_list:
        try:
            res = process_vulnerability(vuln, target_url, job_id=job_id)
            results.append(res)
        except Exception as e:
            logger.error(str(e))
            if job_id:
                _log_stage_update(logger, job_id, "sandbox", status="failed")
                _log_scan_event(logger, "error", str(e), job_id=job_id, stage="sandbox")
            sys.exit(1)

    # Sandbox results reflect the primary execution (all runs are sandboxed)
    sandbox_results = [
        {
            "cve": r.get("cve"),
            "sandbox_target": target_url,
            "success": r.get("success", False),
            "returncode": r.get("attempts", [{}])[-1].get("test_result", {}).get("returncode") if r.get("attempts") else None,
            "error": r.get("error"),
        }
        for r in results
        if r.get("cve")
    ]

    # Step 5: Generate final summary report
    summary = {
        'timestamp': datetime.now().isoformat(),
        'target_url': target_url,
        'total_vulnerabilities': len(results),
        'successful': sum(1 for r in results if r['success']),
        'failed': sum(1 for r in results if not r['success']),
        'kb_found': kb_found,
        'kb_missing': kb_missing,
        'sandbox_results': sandbox_results,
        'details': results
    }

    report_id = None
    if job_id:
        _log_stage_update(logger, job_id, "report")
        _log_scan_event(logger, "info", "Summary report saved to database", job_id=job_id, stage="report")
        try:
            report_id = add_scan_report(job_id, summary)
        except Exception:
            report_id = None

    # Step 6: Validator stage (runs on report saved in DB)
    if job_id:
        _log_stage_update(logger, job_id, "validator")
        _log_scan_event(logger, "info", "Validator started", job_id=job_id, stage="validator")
        try:
            report_json = None
            if report_id:
                report_row = get_scan_report(report_id)
                if report_row:
                    report_json = report_row.get("summary_json")

            # If summary report doesn't include vulnerabilities, try to parse a CVE report from stdout
            if not report_json or not report_json.get("vulnerabilities"):
                for r in results:
                    attempts = r.get("attempts") or []
                    last = attempts[-1] if attempts else {}
                    test = last.get("test_result") or last.get("result") or {}
                    stdout = test.get("stdout") or ""
                    parsed = _extract_json_from_text(stdout)
                    if parsed and parsed.get("vulnerabilities"):
                        report_json = parsed
                        break

            if not report_json:
                report_json = summary

            validation = validate_report(report_json)
            add_validator_result(job_id, report_id, validation)
            _log_scan_event(
                logger,
                "info",
                f"Validator finished: {validation.get('overall_status')}",
                job_id=job_id,
                stage="validator",
                validator_status=validation.get('overall_status'),
            )
        except Exception as e:
            _log_scan_event(logger, "error", str(e), job_id=job_id, stage="validator")

    if job_id:
        _log_stage_update(logger, job_id, "validator", status="finished")

    # Also print summary to console
    print("\n" + "=" * 60)
    print("ORCHESTRATION SUMMARY")
    print("=" * 60)
    print(f"Target: {target_url}")
    print(f"Total CVEs processed: {summary['total_vulnerabilities']}")
    print(f"Successful: {summary['successful']}")
    print(f"Failed: {summary['failed']}")
    print("=" * 60)

if __name__ == '__main__':
    main()
