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
from scanner_parser.parser import load_normalized_input
from matcher.matcher import match_vulnerabilities
from executor.runner import run_exploit, ensure_docker_running
from db.models import add_scan_event, update_scan_job, get_scan_job, add_scan_report
from openai_generator.generator import (
    build_initial_prompt,
    save_prompt,
    generate_script_with_openai,
    save_generated_script as save_generated_script_from_generator,
)
from openai_generator.log_analyzer import analyze_failure
from utils.file_utils import get_cve_script_path, ensure_cve_dir

# Ensure required directories exist
os.makedirs(KNOWLEDGEBASE_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOGS_DIR, 'orchestrator.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

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
            update_scan_job(job_id, stage="sandbox")
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
            update_scan_job(job_id, stage="generate")
            add_scan_event(job_id, "generate", "info", f"{cve} generation started")

        for attempt in range(1, MAX_OPENAI_ATTEMPTS + 1):
            logger.info(f"Generation attempt {attempt}/{MAX_OPENAI_ATTEMPTS} for {cve}")
            if job_id:
                add_scan_event(job_id, "generate", "info", f"{cve} generation attempt {attempt}")
            save_prompt(cve, attempt, current_prompt)

            script_content = generate_script_with_openai(current_prompt)
            if not script_content:
                if job_id:
                    add_scan_event(job_id, "generate", "error", f"{cve} generation failed")
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
                update_scan_job(job_id, stage="sandbox")
                add_scan_event(job_id, "sandbox", "info", f"{cve} sandbox validation started")
            test_result = run_exploit(cve, target_url, job_id=job_id, stage="sandbox")
            result['attempts'][-1]['test_result'] = test_result

            if test_result.get('success', False):
                logger.info(f"{cve} exploit succeeded on attempt {attempt}.")
                result['success'] = True
                result['final_script_path'] = script_path
                update_has_script(cve, 1)
                if job_id:
                    add_scan_event(job_id, "generate", "info", f"{cve} succeeded on attempt {attempt}")
                break

            logger.warning(f"{cve} exploit failed on attempt {attempt}.")
            error_log = (test_result.get('stderr', '') or '') + '\n' + (test_result.get('stdout', '') or '')
            if test_result.get('error'):
                error_log += f"\n{test_result['error']}"
            current_prompt = analyze_failure(cve, error_log, current_prompt)
            if job_id:
                add_scan_event(job_id, "generate", "info", f"{cve} revised prompt for next attempt")
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
    if len(sys.argv) < 2:
        print("Usage: python main.py <target_url> [input_file]")
        print("  target_url : the base URL to test against")
        print("  input_file : optional path to normalized input JSON (default: input/norm_input_newt.json)")
        sys.exit(1)

    target_url = sys.argv[1]
    input_file = sys.argv[2] if len(sys.argv) > 2 else 'input/norm_input_newt.json'
    job_id = sys.argv[3] if len(sys.argv) > 3 else None

    logger.info("=" * 60)
    logger.info("Starting vulnerability orchestration")
    logger.info(f"Target URL: {target_url}")
    logger.info(f"Input file: {input_file}")
    logger.info("=" * 60)

    # Step 1: Load normalized input
    if job_id:
        update_scan_job(job_id, status="running", stage="ingest")
        add_scan_event(job_id, "ingest", "info", f"Loading normalized input: {input_file}")

    vuln_list = load_normalized_input(input_file)
    if not vuln_list:
        logger.error("No vulnerabilities loaded. Exiting.")
        sys.exit(1)
    if job_id:
        update_scan_job(job_id, stage="parse")
        add_scan_event(job_id, "parse", "info", f"Parsed {len(vuln_list)} vulnerabilities")

    # Step 2: Match against database to determine actions
    if job_id:
        update_scan_job(job_id, stage="match")
        add_scan_event(job_id, "match", "info", "Matching CVEs against DB")

    enriched_list = match_vulnerabilities(vuln_list)
    kb_found = sum(1 for v in enriched_list if v.get("action") == "run")
    kb_missing = sum(1 for v in enriched_list if v.get("action") == "generate")
    if job_id:
        update_scan_job(job_id, stage="kb")
        add_scan_event(job_id, "kb", "info", "Knowledgebase lookup complete")
        add_scan_event(
            job_id,
            "kb",
            "info",
            f"KB scripts found: {kb_found} | to generate: {kb_missing}",
        )

    # Step 3: Ensure Docker is running before sandbox execution
    try:
        ensure_docker_running(job_id=job_id, stage="sandbox")
    except Exception as e:
        logger.error(str(e))
        if job_id:
            update_scan_job(job_id, status="failed", stage="sandbox")
            add_scan_event(job_id, "sandbox", "error", str(e))
        sys.exit(1)

    # Step 4: Process each vulnerability
    results = []
    if job_id:
        update_scan_job(job_id, stage="sandbox")
        add_scan_event(job_id, "sandbox", "info", "Executing CVE scripts in sandbox")

    for vuln in enriched_list:
        try:
            res = process_vulnerability(vuln, target_url, job_id=job_id)
            results.append(res)
        except Exception as e:
            logger.error(str(e))
            if job_id:
                update_scan_job(job_id, status="failed", stage="sandbox")
                add_scan_event(job_id, "sandbox", "error", str(e))
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

    if job_id:
        update_scan_job(job_id, status="finished", stage="report")
        add_scan_event(job_id, "report", "info", "Summary report saved to database")
        try:
            add_scan_report(job_id, summary)
        except Exception:
            pass

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
