#!/usr/bin/env python3
"""
Universal VAPT Report Validator – Zero False Positives
- Evidence authenticity (real data patterns, no placeholders)
- Payload-to-evidence correlation (for command injection/RCE)
- exploitation_success consistency
- CVSS alignment, deduplication, required fields
"""

import argparse
import json
import re
import sys
from typing import Dict, List, Any, Tuple

# ------------------------------------------------------------------------------
# Severity to CVSS score range
# ------------------------------------------------------------------------------
SEVERITY_RANGES = {
    "Critical": (9.0, 10.0),
    "High": (7.0, 8.9),
    "Medium": (4.0, 6.9),
    "Low": (0.1, 3.9),
    "Info": (0.0, 0.0)
}

# ------------------------------------------------------------------------------
# Forbidden phrases that indicate a false positive / placeholder evidence
# ------------------------------------------------------------------------------
FORBIDDEN_PHRASES = [
    "manual verification required",
    "check callback server",
    "payload sent",
    "would require",
    "no version output",
    "errors confirmed but no data",
    "out-of-band detection",
    "monitor callback domain",
    "this is a placeholder",
    "replace with actual"
]

# ------------------------------------------------------------------------------
# Real data patterns (at least one must appear in evidence for Critical/High)
# ------------------------------------------------------------------------------
REAL_DATA_PATTERNS = [
    r"uid=\d+",                     # command injection
    r"gid=\d+",
    r"root:x:",                     # /etc/passwd
    r"daemon:x:",
    r"@@version",                   # SQL version
    r"version\(\)",
    r"table_name",                  # SQL schema
    r"database\(\)",
    r"information_schema",
    r"\[boot loader\]",             # Windows INI
    r"Windows Registry",
    r"PATH=",
    r"[A-Za-z0-9/+]{40,}",          # base64 or long encoded data
    r"\{\s*\"[^\"]+\"\s*:\s*",      # JSON structure
    r"<[a-z]+>[^<]+</[a-z]+>",      # XML/HTML
    r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+",  # IP address
    r"Linux [0-9]+\.[0-9]+",        # kernel version
]

# ------------------------------------------------------------------------------
# Helper: extract command from payload (for correlation check)
# ------------------------------------------------------------------------------
def extract_command_from_payload(payload: str) -> str:
    """
    Try to extract the command being executed from a payload string.
    Supports: io.popen("cmd"), os.execute("cmd"), system("cmd"), etc.
    Returns the command or empty string.
    """
    if not payload or payload == "N/A":
        return ""
    # Look for patterns like io.popen("id; uname -a") or os.execute("id")
    patterns = [
        r'io\.popen\("([^"]+)"\)',
        r"io\.popen\('([^']+)'\)",
        r'os\.execute\("([^"]+)"\)',
        r"os\.execute\('([^']+)'\)",
        r'system\("([^"]+)"\)',
        r"system\('([^']+)'\)",
        r'`([^`]+)`',  # backticks in some languages
    ]
    for pattern in patterns:
        match = re.search(pattern, payload)
        if match:
            return match.group(1)
    return ""

# ------------------------------------------------------------------------------
# Evidence validation (generic)
# ------------------------------------------------------------------------------
def validate_evidence(finding: Dict[str, Any], payload: str) -> Tuple[bool, str, List[str]]:
    """
    Returns (is_valid, reason, warnings)
    - is_valid: False if evidence is clearly fake/empty
    - reason: short explanation
    - warnings: list of specific issues
    """
    severity = finding.get("severity", "")
    evidence = finding.get("proof_of_concept", {}).get("evidence", "").strip()
    title = finding.get("title", "").lower()

    # Info findings are always accepted
    if severity == "Info":
        return True, "Info finding – no strict evidence required", []

    if not evidence or evidence == "N/A":
        return False, "Evidence is empty or 'N/A'", ["empty_evidence"]

    warnings = []

    # 1. Length check
    if len(evidence) < 50:
        warnings.append(f"too_short ({len(evidence)} chars)")

    # 2. Forbidden phrases – automatic failure
    for phrase in FORBIDDEN_PHRASES:
        if phrase.lower() in evidence.lower():
            return False, f"Contains forbidden phrase: '{phrase}'", [f"forbidden_phrase:{phrase}"]

    # 3. For Critical/High, require at least one real data pattern
    if severity in ("Critical", "High"):
        matched = any(re.search(pattern, evidence, re.IGNORECASE) for pattern in REAL_DATA_PATTERNS)
        if not matched:
            warnings.append("no_real_data_pattern_found")
        else:
            # Good: at least one pattern matched
            pass

    # 4. Payload-to-evidence correlation (for command injection/RCE)
    if "command injection" in title or "rce" in title or "remote code execution" in title:
        cmd = extract_command_from_payload(payload)
        if cmd and len(cmd) > 2:
            # Check if command output appears in evidence
            # For commands like "id; uname -a", we expect "uid=" or "Linux"
            cmd_parts = re.split(r'[;&|]', cmd)
            found = False
            for part in cmd_parts:
                part = part.strip()
                if len(part) > 1:
                    # If part is like "id", look for "uid="; if "uname -a", look for "Linux"
                    if part == "id" and re.search(r"uid=\d+", evidence, re.I):
                        found = True
                        break
                    elif part == "uname -a" and re.search(r"Linux|GNU", evidence, re.I):
                        found = True
                        break
                    elif part in evidence:
                        found = True
                        break
            if not found:
                warnings.append(f"payload_command_not_reflected: '{cmd}' not found in evidence")

    # Final decision
    if "no_real_data_pattern_found" in warnings and severity in ("Critical", "High"):
        return False, "Evidence lacks real extracted data (no uid, version, file content, etc.)", warnings
    elif warnings:
        return True, "Evidence acceptable but has minor issues", warnings
    else:
        return True, "Evidence is strong and contains real data", []

# ------------------------------------------------------------------------------
# CVSS validation
# ------------------------------------------------------------------------------
def validate_cvss(finding: Dict[str, Any]) -> Tuple[bool, str]:
    severity = finding.get("severity")
    cvss = finding.get("cvss", {})
    score = cvss.get("score")
    vector = cvss.get("vector", "")

    if severity not in SEVERITY_RANGES:
        return False, f"Unknown severity '{severity}'"

    if score is None:
        return False, "CVSS score missing"

    min_score, max_score = SEVERITY_RANGES[severity]
    if not (min_score <= score <= max_score):
        return False, f"Score {score} not in range {min_score}-{max_score} for {severity}"

    if not vector or len(vector) < 10:
        return False, "CVSS vector missing or too short"

    return True, "OK"

# ------------------------------------------------------------------------------
# Deduplication check
# ------------------------------------------------------------------------------
def find_duplicates(findings: List[Dict]) -> List[Tuple[str, str, str]]:
    seen = {}
    duplicates = []
    for f in findings:
        loc = f.get("location", {})
        key = (loc.get("url", ""), loc.get("parameter", ""), f.get("title", ""))
        if key in seen:
            duplicates.append(key)
        else:
            seen[key] = True
    return duplicates

# ------------------------------------------------------------------------------
# Consistency: exploitation_success must match presence of Critical/High findings
# ------------------------------------------------------------------------------
def check_exploitation_success_consistency(report: Dict[str, Any]) -> Tuple[bool, str]:
    exploitation_success = report.get("exploitation_success", False)
    findings = report.get("vulnerabilities", [])
    has_critical_high = any(f.get("severity") in ("Critical", "High") for f in findings)
    if exploitation_success and not has_critical_high:
        return False, "exploitation_success is true but no Critical/High vulnerabilities found"
    if not exploitation_success and has_critical_high:
        return False, "exploitation_success is false but Critical/High vulnerabilities exist"
    return True, "OK"

# ------------------------------------------------------------------------------
# Main validation function
# ------------------------------------------------------------------------------
def validate_report(report: Dict[str, Any]) -> Dict[str, Any]:
    findings = report.get("vulnerabilities", [])
    if not findings:
        return {
            "validation_summary": {"total_findings": 0, "passed": 0, "failed": 0, "warnings": 0},
            "overall_status": "INVALID",
            "validation_details": [],
            "recommendations": ["Report has zero vulnerabilities – at least one Info finding is required."]
        }

    duplicates = find_duplicates(findings)
    details = []
    passed = 0
    failed = 0
    warnings = 0

    for idx, finding in enumerate(findings):
        poc = finding.get("proof_of_concept", {})
        payload = poc.get("payload_used", "")
        evidence = poc.get("evidence", "")
        result = {
            "finding_id": finding.get("id", f"index_{idx}"),
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "verdict": None,
            "issues": [],
            "evidence_snippet": evidence[:200]
        }

        # --- Structural checks ---
        rem = finding.get("remediation", {})
        loc = finding.get("location", {})
        if not payload:
            result["issues"].append("missing_payload_used")
        if not rem.get("action"):
            result["issues"].append("missing_remediation_action")
        if not rem.get("example_fix"):
            result["issues"].append("missing_remediation_example_fix")
        if not loc.get("url"):
            result["issues"].append("missing_location_url")

        # --- Evidence validation (includes payload correlation) ---
        evidence_ok, evidence_reason, evidence_warnings = validate_evidence(finding, payload)
        if evidence_warnings:
            result["issues"].extend(evidence_warnings)
        if not evidence_ok:
            result["issues"].append(f"evidence_fail: {evidence_reason}")

        # --- CVSS validation ---
        cvss_ok, cvss_reason = validate_cvss(finding)
        if not cvss_ok:
            result["issues"].append(f"cvss_fail: {cvss_reason}")

        # Determine verdict
        critical_fails = [i for i in result["issues"] if "fail" in i or "empty" in i or "missing" in i or "forbidden" in i]
        if critical_fails:
            result["verdict"] = "FAIL"
            failed += 1
        elif result["issues"]:
            result["verdict"] = "WARNING"
            warnings += 1
        else:
            result["verdict"] = "PASS"
            passed += 1

        details.append(result)

    # --- Consistency check for exploitation_success ---
    consistency_ok, consistency_msg = check_exploitation_success_consistency(report)
    if not consistency_ok:
        # Add a special entry in details or recommendations
        details.append({
            "finding_id": "CONSISTENCY",
            "title": "exploitation_success mismatch",
            "severity": "N/A",
            "verdict": "FAIL",
            "issues": [consistency_msg],
            "evidence_snippet": ""
        })
        failed += 1

    # Overall status
    if failed > 0:
        overall = "INVALID"
    elif warnings > 0:
        overall = "PARTIALLY_VALID"
    else:
        overall = "VALID"

    # Recommendations
    recommendations = []
    if duplicates:
        recommendations.append(f"Duplicate findings detected: {duplicates}")
    if failed > 0:
        recommendations.append("Fix failing findings: ensure evidence contains real extracted data, no placeholders, and exploitation_success matches findings.")
    if warnings > 0:
        recommendations.append("Review warning findings – evidence may be weak or generic.")
    if not any(f.get("severity") in ("Critical", "High") for f in findings):
        recommendations.append("No Critical/High findings – consider if deeper testing is possible.")

    return {
        "validation_summary": {
            "total_findings": len(findings),
            "passed": passed,
            "failed": failed,
            "warnings": warnings
        },
        "overall_status": overall,
        "validation_details": details,
        "recommendations": recommendations
    }

# ------------------------------------------------------------------------------
# CLI entry point
# ------------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Universal VAPT Report Validator")
    parser.add_argument("report_file", help="Path to JSON report from exploit generator")
    parser.add_argument("--output", help="Output JSON validation report file")
    parser.add_argument("--verbose", action="store_true", help="Print detailed info")
    args = parser.parse_args()

    try:
        with open(args.report_file, "r") as f:
            report = json.load(f)
    except Exception as e:
        print(f"Error reading report: {e}", file=sys.stderr)
        sys.exit(1)

    validation = validate_report(report)

    output_json = json.dumps(validation, indent=2)
    if args.output:
        with open(args.output, "w") as f:
            f.write(output_json)
        print(f"Validation report saved to {args.output}")
    else:
        print(output_json)

    if args.verbose:
        print("\n=== Validation Summary ===")
        print(f"Total findings: {validation['validation_summary']['total_findings']}")
        print(f"Passed: {validation['validation_summary']['passed']}")
        print(f"Failed: {validation['validation_summary']['failed']}")
        print(f"Warnings: {validation['validation_summary']['warnings']}")
        print(f"Overall status: {validation['overall_status']}")

if __name__ == "__main__":
    main()
# END OF VALIDATOR