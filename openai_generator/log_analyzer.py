#!/usr/bin/env python3
"""
Log Analyzer Module

Analyzes failure logs from exploit execution and suggests prompt improvements.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

def analyze_failure(cve: str, error_log: str, previous_prompt: str) -> str:
    """
    Analyze the error log and previous prompt to produce a revised prompt.

    Args:
        cve: CVE identifier
        error_log: combined stdout/stderr or error message from executor
        previous_prompt: the prompt that generated the failing script

    Returns:
        Revised prompt string.
    """
    # Simple heuristics: determine likely failure reason
    failure_reason = "unknown"
    if "ModuleNotFoundError" in error_log or "ImportError" in error_log:
        failure_reason = "Missing import or dependency"
    elif "ConnectionError" in error_log or "Timeout" in error_log:
        failure_reason = "Network connection issue or timeout"
    elif "SyntaxError" in error_log:
        failure_reason = "Syntax error in generated code"
    elif "NameError" in error_log:
        failure_reason = "Undefined variable or function"
    elif "AttributeError" in error_log:
        failure_reason = "Wrong method or attribute used"
    elif "TypeError" in error_log:
        failure_reason = "Type mismatch in arguments"
    elif "Permission denied" in error_log:
        failure_reason = "File permissions or execution issue"
    elif "not vulnerable" in error_log.lower():
        failure_reason = "Exploit check determined target not vulnerable (may be false negative)"
    elif "exploit failed" in error_log.lower():
        failure_reason = "Exploit ran but did not succeed"
    
    logger.info(f"Analyzed failure for {cve}: {failure_reason}")
    
    # Build a revised prompt that includes the failure analysis
    from .generator import build_revised_prompt
    revised = build_revised_prompt(previous_prompt, error_log, failure_reason)
    return revised

def main():
    """Test the analyzer with sample input."""
    # For testing only
    import sys
    if len(sys.argv) < 2:
        print("Usage: python -m openai_generator.log_analyzer <error_log_file>")
        sys.exit(1)
    with open(sys.argv[1], 'r') as f:
        error_log = f.read()
    # In a real scenario, you'd also need the previous prompt
    # For testing, just print revised prompt
    revised = analyze_failure("CVE-2021-44228", error_log, "previous prompt placeholder")
    print(revised)

if __name__ == '__main__':
    main()