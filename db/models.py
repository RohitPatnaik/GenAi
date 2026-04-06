from db.connection import get_connection
import json
import psycopg2.extras

def get_vulnerability_by_cve(cve):
    """Return vulnerability record as dict, or None if not found."""
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM network_vulnerabilities WHERE cve = %s", (cve,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row

def get_all_vulnerabilities():
    """Return all vulnerability records as list of dicts."""
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM network_vulnerabilities ORDER BY id DESC")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows

def insert_vulnerability(cve, cwe, title, description, cvss_score=None, severity=None, has_script=0):
    """Insert a new vulnerability record. Return the id."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO network_vulnerabilities (cve, cwe, title, description, cvss_score, severity, has_script, script_path)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
    """, (cve, cwe, title, description, cvss_score, severity, has_script, None))
    inserted_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return inserted_id

def update_has_script(cve, has_script):
    """Update has_script flag for a given CVE."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        UPDATE network_vulnerabilities
        SET has_script = %s, updated_at = CURRENT_TIMESTAMP
        WHERE cve = %s
    """, (has_script, cve))
    conn.commit()
    cur.close()
    conn.close()

def update_script_path(cve, script_path):
    """Update script_path for a given CVE."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        UPDATE network_vulnerabilities
        SET script_path = %s, updated_at = CURRENT_TIMESTAMP
        WHERE cve = %s
    """, (script_path, cve))
    conn.commit()
    cur.close()
    conn.close()

# ---- Scan jobs & events ----

def create_scan_job(job):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO scan_jobs
        (id, job_name, priority, source_type, source_path, exploit_mode, fallback_llm,
         validation_mode, sandbox_target, target_url, input_file, output_file, created_by, status, stage)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """,
        (
            job["id"], job.get("job_name"), job.get("priority"), job.get("source_type"),
            job.get("source_path"), job.get("exploit_mode"), job.get("fallback_llm"),
            job.get("validation_mode"), job.get("sandbox_target"), job.get("target_url"),
            job.get("input_file"), job.get("output_file"), job.get("created_by"),
            job.get("status"), job.get("stage")
        )
    )
    conn.commit()
    cur.close()
    conn.close()


def update_scan_job(job_id, **fields):
    if not fields:
        return
    sets = []
    vals = []
    for k, v in fields.items():
        sets.append(f"{k} = %s")
        vals.append(v)
    vals.append(job_id)
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        f"UPDATE scan_jobs SET {', '.join(sets)}, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
        tuple(vals),
    )
    conn.commit()
    cur.close()
    conn.close()


def get_scan_job(job_id):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM scan_jobs WHERE id = %s", (job_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row


def add_scan_event(job_id, stage, level, message):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO scan_events (job_id, stage, level, message) VALUES (%s,%s,%s,%s)",
        (job_id, stage, level, message)
    )
    conn.commit()
    cur.close()
    conn.close()


def get_scan_events(job_id, limit=200):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "SELECT * FROM scan_events WHERE job_id = %s ORDER BY id DESC LIMIT %s",
        (job_id, limit)
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows

# ---- Scan results & reports ----

def add_scan_result(job_id, result):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO scan_results
        (job_id, cve, stage, success, returncode, stdout, stderr, error, script_path)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """,
        (
            job_id,
            result.get("cve"),
            result.get("stage"),
            result.get("success"),
            result.get("returncode"),
            result.get("stdout"),
            result.get("stderr"),
            result.get("error"),
            result.get("script_path"),
        )
    )
    conn.commit()
    cur.close()
    conn.close()


def get_scan_results(job_id=None, limit=200, lite=False):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    select_cols = (
        "id, job_id, cve, stage, success, returncode, created_at"
        if lite
        else "*"
    )
    if job_id:
        cur.execute(
            f"SELECT {select_cols} FROM scan_results WHERE job_id = %s ORDER BY id DESC LIMIT %s",
            (job_id, limit),
        )
    else:
        cur.execute(
            f"SELECT {select_cols} FROM scan_results ORDER BY id DESC LIMIT %s",
            (limit,),
        )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows


def get_scan_result(result_id):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM scan_results WHERE id = %s", (result_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row


def add_scan_report(job_id, summary_json):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO scan_reports (job_id, summary_json) VALUES (%s,%s)",
        (job_id, json.dumps(summary_json)),
    )
    conn.commit()
    cur.close()
    conn.close()


def get_scan_reports(limit=50, job_id=None, lite=False):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    select_cols = "id, job_id, created_at" if lite else "*"
    if job_id:
        cur.execute(
            f"SELECT {select_cols} FROM scan_reports WHERE job_id = %s ORDER BY id DESC LIMIT %s",
            (job_id, limit),
        )
    else:
        cur.execute(
            f"SELECT {select_cols} FROM scan_reports ORDER BY id DESC LIMIT %s",
            (limit,),
        )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows


def get_scan_report(report_id):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM scan_reports WHERE id = %s", (report_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row
