#!/usr/bin/env python3
"""
Scanner Parser Module

Reads a raw JSON input file, extracts vulnerability information,
and writes a normalized JSON file (norm_input_newt.json) to the input/ directory.
"""

import json
import os
import sys
import logging
from datetime import datetime
from typing import List, Dict, Any

# Ensure required directories exist before logger initialization
os.makedirs('input', exist_ok=True)
os.makedirs('logs', exist_ok=True)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join('logs', 'parser.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def parse_raw_input(raw_file_path: str) -> List[Dict[str, Any]]:
    """
    Parse raw JSON input and extract a list of vulnerabilities.
    
    Expected raw JSON format (example):
    {
        "scan_results": [
            {
                "cve": "CVE-2021-44228",
                "cwe": "CWE-917",
                "title": "Apache Log4j2 RCE",
                "description": "...",
                ... other fields ...
            },
            ...
        ]
    }
    
    Returns a list of normalized vulnerability dicts with keys:
    - cve
    - cwe (optional)
    - title
    - description
    - cvss_score (optional)
    - severity (optional)
    """
    try:
        # Use utf-8-sig to gracefully handle BOM from Windows editors.
        with open(raw_file_path, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)
    except Exception as e:
        logger.error(f"Failed to read raw input file: {e}")
        raise ValueError(f"Failed to read raw input file: {e}")
    
    normalized = []
    
    # Handle different possible structures
    if isinstance(data, dict):
        # If the top-level is an object, look for a key that contains the list
        if 'scan_results' in data:
            items = data['scan_results']
        elif 'vulnerabilities' in data:
            items = data['vulnerabilities']
        elif 'results' in data:
            items = data['results']
        else:
            # Assume the dict itself contains a list somewhere? We'll just take values if they are lists
            items = []
            for v in data.values():
                if isinstance(v, list):
                    items = v
                    break
            if not items:
                logger.error("Unable to find a list of vulnerabilities in the JSON structure.")
                raise ValueError("Unable to find a list of vulnerabilities in the JSON structure.")
    elif isinstance(data, list):
        items = data
    else:
        logger.error("Raw input must be a JSON object or array.")
        raise ValueError("Raw input must be a JSON object or array.")
    
    def _parse_float(val):
        try:
            return float(val)
        except (TypeError, ValueError):
            return None

    def _extract_cvss_score(v: Dict[str, Any]):
        # Common keys seen in scanner outputs
        keys = [
            "cvss_score", "cvssScore", "cvss", "cvss_v3", "cvssV3",
            "cvss_base_score", "baseScore", "score"
        ]
        for k in keys:
            if k in v:
                val = v.get(k)
                if isinstance(val, dict):
                    # Try nested score keys
                    for nk in ("score", "baseScore", "cvssScore"):
                        if nk in val:
                            return _parse_float(val.get(nk))
                else:
                    return _parse_float(val)
        return None

    def _extract_severity(v: Dict[str, Any]):
        sev = v.get("severity") or v.get("cvss_severity") or v.get("cvssSeverity")
        if isinstance(sev, str):
            return sev.strip().lower()
        return None

    skipped_low = 0

    for idx, item in enumerate(items):
        if not isinstance(item, dict):
            logger.warning(f"Skipping non-dict item at index {idx}")
            continue
        
        # Extract required fields (cve, title, description) with fallbacks
        cve = item.get('cve') or item.get('id') or item.get('vulnerability_id')
        if not cve:
            logger.warning(f"Skipping item at index {idx}: missing CVE identifier")
            continue
        
        cwe = item.get('cwe') or item.get('cwe_id')
        title = item.get('title') or item.get('name') or 'No title'
        description = item.get('description') or item.get('desc') or 'No description'
        cvss_score = _extract_cvss_score(item)
        severity = _extract_severity(item)

        # Filter out low severity (CVSS < 4.0 or severity == low)
        if cvss_score is not None and cvss_score < 4.0:
            logger.info(f"Skipping {cve.strip().upper()} due to low CVSS score: {cvss_score}")
            skipped_low += 1
            continue
        if cvss_score is None and severity == "low":
            logger.info(f"Skipping {cve.strip().upper()} due to low severity")
            skipped_low += 1
            continue
        
        normalized.append({
            'cve': cve.strip().upper(),
            'cwe': cwe.strip().upper() if cwe else None,
            'title': title.strip(),
            'description': description.strip(),
            'cvss_score': cvss_score,
            'severity': severity
        })
    
    logger.info(f"Parsed {len(normalized)} vulnerabilities from raw input. Skipped low: {skipped_low}")
    return normalized

def write_normalized(normalized_data: List[Dict[str, Any]], output_file: str = 'input/norm_input_newt.json'):
    """Write normalized data to a JSON file."""
    try:
        with open(output_file, 'w') as f:
            json.dump(normalized_data, f, indent=2)
        logger.info(f"Normalized data written to {output_file}")
    except Exception as e:
        logger.error(f"Failed to write normalized output: {e}")
        raise ValueError(f"Failed to write normalized output: {e}")

def load_normalized_input(input_file: str = 'input/norm_input_newt.json') -> List[Dict[str, Any]]:
    """Load normalized vulnerabilities from a JSON file."""
    try:
        with open(input_file, 'r') as f:
            data = json.load(f)
        if not isinstance(data, list):
            logger.error("Normalized input must be a JSON array of vulnerabilities.")
            return []
        logger.info(f"Loaded {len(data)} normalized vulnerabilities from {input_file}")
        return data
    except FileNotFoundError:
        logger.error(f"Normalized input file not found: {input_file}")
        return []
    except Exception as e:
        logger.error(f"Failed to read normalized input: {e}")
        return []

def main():
    """Main entry point when script is run directly."""
    if len(sys.argv) < 2:
        print("Usage: python -m scanner_parser.parser <raw_input_json>")
        sys.exit(1)
    
    raw_file = sys.argv[1]
    if not os.path.exists(raw_file):
        logger.error(f"Raw input file not found: {raw_file}")
        sys.exit(1)

    try:
        normalized = parse_raw_input(raw_file)
        if normalized:
            write_normalized(normalized)
        else:
            logger.warning("No vulnerabilities found to normalize.")
    except Exception as e:
        logger.error(str(e))
        sys.exit(1)

if __name__ == '__main__':
    main()
