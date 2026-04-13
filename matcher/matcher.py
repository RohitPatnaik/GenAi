#!/usr/bin/env python3
"""
Matcher Module

Reads normalized input, checks database for each CVE, and decides whether to:
- run an existing exploit script (has_script = 1)
- generate a new script via OpenAI (has_script = 0)
Also inserts new CVEs into the database.
"""

import json
import os
import sys
import logging
from typing import List, Dict, Any

# Add project root to path for imports if needed
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db.models import (
    get_vulnerabilities_by_cves,
    insert_vulnerabilities,
    update_has_script,
    update_script_path,
)
from config import KNOWLEDGEBASE_DIR
from utils.file_utils import get_cve_script_path

logger = logging.getLogger(__name__)

def check_script_exists(cve: str) -> bool:
    """Return True if a Python script for the CVE exists in knowledgebase."""
    script_path = get_cve_script_path(cve)
    exists = os.path.isfile(script_path)
    if exists:
        logger.debug(f"Script exists for {cve}")
    else:
        logger.debug(f"No script found for {cve}")
    return exists

def match_vulnerabilities(normalized_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Process each vulnerability:
    - Query DB by CVE.
    - If not in DB, insert with has_script = 0.
    - Determine action: 'run' if has_script=1 and script file exists, else 'generate'.
    Returns a list of dicts with original data plus 'action' and 'db_record'.
    """
    results = []
    cves = [vuln.get('cve') for vuln in normalized_list if vuln.get('cve')]
    records_by_cve = get_vulnerabilities_by_cves(cves)

    missing_rows = []
    for vuln in normalized_list:
        cve = vuln.get('cve')
        if not cve:
            logger.warning("Skipping entry with missing CVE")
            continue
        if cve in records_by_cve:
            continue

        logger.info(f"CVE {cve} not found in DB. Inserting.")
        missing_rows.append({
            'cve': cve,
            'cwe': vuln.get('cwe', ''),
            'title': vuln.get('title', ''),
            'description': vuln.get('description', ''),
            'cvss_score': vuln.get('cvss_score'),
            'severity': vuln.get('severity'),
            'has_script': 0,
        })

    if missing_rows:
        insert_vulnerabilities(missing_rows)
        records_by_cve.update(get_vulnerabilities_by_cves([row['cve'] for row in missing_rows]))

    for vuln in normalized_list:
        cve = vuln.get('cve')
        if not cve:
            continue

        db_record = records_by_cve.get(cve)
        if not db_record:
            logger.error(f"Failed to insert {cve}")
            continue

        has_script_flag = db_record['has_script']
        script_path = get_cve_script_path(cve)
        script_exists = os.path.isfile(script_path)

        if has_script_flag == 1 and not script_exists:
            logger.warning(f"DB says script exists for {cve} but file missing. Will generate.")
            action = 'generate'
            update_has_script(cve, 0)
        elif has_script_flag == 1 and script_exists:
            action = 'run'
        else:
            action = 'generate'

        if script_exists and not db_record.get('script_path'):
            update_script_path(cve, script_path)

        result = {
            **vuln,
            'action': action,
            'db_record': dict(db_record)
        }
        results.append(result)
        logger.info(f"CVE {cve}: action = {action}")

    return results

