from db.connection import get_connection
import json
import psycopg2.extras
from contextlib import contextmanager


@contextmanager
def _db_cursor(cursor_factory=None):
    """Yield (conn, cursor) and always return pooled connection on exit."""
    conn = get_connection()
    cur = None
    try:
        if cursor_factory is not None:
            cur = conn.cursor(cursor_factory=cursor_factory)
        else:
            cur = conn.cursor()
        yield conn, cur
    finally:
        if cur is not None:
            cur.close()
        conn.close()


def _commit_or_rollback(conn):
    try:
        conn.commit()
    except Exception:
        conn.rollback()
        raise

def get_vulnerability_by_cve(cve):
    """Return vulnerability record as dict, or None if not found."""
    with _db_cursor(psycopg2.extras.RealDictCursor) as (conn, cur):
        cur.execute("SELECT * FROM network_vulnerabilities WHERE cve = %s", (cve,))
        row = cur.fetchone()
        return row


def get_vulnerabilities_by_cves(cves):
    """Return vulnerability records keyed by CVE for the provided identifiers."""
    normalized_cves = sorted({cve for cve in cves if cve})
    if not normalized_cves:
        return {}

    with _db_cursor(psycopg2.extras.RealDictCursor) as (conn, cur):
        cur.execute(
            "SELECT * FROM network_vulnerabilities WHERE cve = ANY(%s)",
            (normalized_cves,),
        )
        rows = cur.fetchall()
        return {row["cve"]: row for row in rows}


def get_all_vulnerabilities():
    """Return all vulnerability records as list of dicts."""
    with _db_cursor(psycopg2.extras.RealDictCursor) as (conn, cur):
        cur.execute("SELECT * FROM network_vulnerabilities ORDER BY id DESC")
        rows = cur.fetchall()
        return rows

def insert_vulnerability(cve, cwe, title, description, cvss_score=None, severity=None, has_script=0):
    """Insert a new vulnerability record. Return the id."""
    with _db_cursor() as (conn, cur):
        try:
            cur.execute("""
                INSERT INTO network_vulnerabilities (cve, cwe, title, description, cvss_score, severity, has_script, script_path)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (cve, cwe, title, description, cvss_score, severity, has_script, None))
            inserted_id = cur.fetchone()[0]
            _commit_or_rollback(conn)
            return inserted_id
        except Exception:
            conn.rollback()
            raise


def insert_vulnerabilities(vulnerabilities):
    """Insert multiple vulnerability records, ignoring CVEs that already exist."""
    rows = [
        (
            vuln.get("cve"),
            vuln.get("cwe"),
            vuln.get("title"),
            vuln.get("description"),
            vuln.get("cvss_score"),
            vuln.get("severity"),
            vuln.get("has_script", 0),
            None,
        )
        for vuln in vulnerabilities
        if vuln.get("cve")
    ]
    if not rows:
        return 0

    with _db_cursor() as (conn, cur):
        try:
            psycopg2.extras.execute_values(
                cur,
                """
                INSERT INTO network_vulnerabilities
                (cve, cwe, title, description, cvss_score, severity, has_script, script_path)
                VALUES %s
                ON CONFLICT (cve) DO NOTHING
                """,
                rows,
            )
            _commit_or_rollback(conn)
            return len(rows)
        except Exception:
            conn.rollback()
            raise


def update_has_script(cve, has_script):
    """Update has_script flag for a given CVE."""
    with _db_cursor() as (conn, cur):
        try:
            cur.execute("""
                UPDATE network_vulnerabilities
                SET has_script = %s, updated_at = CURRENT_TIMESTAMP
                WHERE cve = %s
            """, (has_script, cve))
            _commit_or_rollback(conn)
        except Exception:
            conn.rollback()
            raise

def update_script_path(cve, script_path):
    """Update script_path for a given CVE."""
    with _db_cursor() as (conn, cur):
        try:
            cur.execute("""
                UPDATE network_vulnerabilities
                SET script_path = %s, updated_at = CURRENT_TIMESTAMP
                WHERE cve = %s
            """, (script_path, cve))
            _commit_or_rollback(conn)
        except Exception:
            conn.rollback()
            raise

# ---- Scan jobs & events ----

def create_scan_job(job):
    with _db_cursor() as (conn, cur):
        try:
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
            _commit_or_rollback(conn)
        except Exception:
            conn.rollback()
            raise


def update_scan_job(job_id, **fields):
    if not fields:
        return
    sets = []
    vals = []
    for k, v in fields.items():
        sets.append(f"{k} = %s")
        vals.append(v)
    vals.append(job_id)
    with _db_cursor() as (conn, cur):
        try:
            cur.execute(
                f"UPDATE scan_jobs SET {', '.join(sets)}, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                tuple(vals),
            )
            _commit_or_rollback(conn)
        except Exception:
            conn.rollback()
            raise


def get_scan_job(job_id):
    with _db_cursor(psycopg2.extras.RealDictCursor) as (conn, cur):
        cur.execute("SELECT * FROM scan_jobs WHERE id = %s", (job_id,))
        row = cur.fetchone()
        return row


def add_scan_event(job_id, stage, level, message):
    with _db_cursor() as (conn, cur):
        try:
            cur.execute(
                "INSERT INTO scan_events (job_id, stage, level, message) VALUES (%s,%s,%s,%s)",
                (job_id, stage, level, message)
            )
            _commit_or_rollback(conn)
        except Exception:
            conn.rollback()
            raise


def get_scan_events(job_id, limit=200):
    with _db_cursor(psycopg2.extras.RealDictCursor) as (conn, cur):
        cur.execute(
            "SELECT * FROM scan_events WHERE job_id = %s ORDER BY id DESC LIMIT %s",
            (job_id, limit)
        )
        rows = cur.fetchall()
        return rows

# ---- Scan results & reports ----

def add_scan_result(job_id, result):
    with _db_cursor() as (conn, cur):
        try:
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
            _commit_or_rollback(conn)
        except Exception:
            conn.rollback()
            raise


def get_scan_results(job_id=None, limit=200, offset=0, lite=False):
    with _db_cursor(psycopg2.extras.RealDictCursor) as (conn, cur):
        select_cols = (
            "id, job_id, cve, stage, success, returncode, created_at"
            if lite
            else "*"
        )
        if job_id:
            cur.execute(
                f"SELECT {select_cols} FROM scan_results WHERE job_id = %s ORDER BY id DESC LIMIT %s OFFSET %s",
                (job_id, limit, offset),
            )
        else:
            cur.execute(
                f"SELECT {select_cols} FROM scan_results ORDER BY id DESC LIMIT %s OFFSET %s",
                (limit, offset),
            )
        rows = cur.fetchall()
        return rows


def get_scan_result(result_id):
    with _db_cursor(psycopg2.extras.RealDictCursor) as (conn, cur):
        cur.execute("SELECT * FROM scan_results WHERE id = %s", (result_id,))
        row = cur.fetchone()
        return row


def count_scan_results(job_id=None):
    with _db_cursor() as (conn, cur):
        if job_id:
            cur.execute("SELECT COUNT(*) FROM scan_results WHERE job_id = %s", (job_id,))
        else:
            cur.execute("SELECT COUNT(*) FROM scan_results")
        count = cur.fetchone()[0]
        return count


def add_scan_report(job_id, summary_json):
    with _db_cursor() as (conn, cur):
        try:
            cur.execute(
                "INSERT INTO scan_reports (job_id, summary_json) VALUES (%s,%s)",
                (job_id, json.dumps(summary_json)),
            )
            cur.execute("SELECT currval(pg_get_serial_sequence('scan_reports','id'))")
            report_id = cur.fetchone()[0]
            _commit_or_rollback(conn)
            return report_id
        except Exception:
            conn.rollback()
            raise


def get_scan_reports(limit=50, offset=0, job_id=None, lite=False):
    with _db_cursor(psycopg2.extras.RealDictCursor) as (conn, cur):
        select_cols = "id, job_id, created_at" if lite else "*"
        if job_id:
            cur.execute(
                f"SELECT {select_cols} FROM scan_reports WHERE job_id = %s ORDER BY id DESC LIMIT %s OFFSET %s",
                (job_id, limit, offset),
            )
        else:
            cur.execute(
                f"SELECT {select_cols} FROM scan_reports ORDER BY id DESC LIMIT %s OFFSET %s",
                (limit, offset),
            )
        rows = cur.fetchall()
        return rows


def get_scan_report(report_id):
    with _db_cursor(psycopg2.extras.RealDictCursor) as (conn, cur):
        cur.execute("SELECT * FROM scan_reports WHERE id = %s", (report_id,))
        row = cur.fetchone()
        return row


def count_scan_reports(job_id=None):
    with _db_cursor() as (conn, cur):
        if job_id:
            cur.execute("SELECT COUNT(*) FROM scan_reports WHERE job_id = %s", (job_id,))
        else:
            cur.execute("SELECT COUNT(*) FROM scan_reports")
        count = cur.fetchone()[0]
        return count

# ---- Validator results ----

def add_validator_result(job_id, report_id, validation_json):
    with _db_cursor() as (conn, cur):
        try:
            cur.execute(
                """
                INSERT INTO validator_results
                (job_id, report_id, overall_status, summary_json, details_json, recommendations)
                VALUES (%s,%s,%s,%s,%s,%s)
                """,
                (
                    job_id,
                    report_id,
                    validation_json.get("overall_status"),
                    json.dumps(validation_json.get("validation_summary")),
                    json.dumps(validation_json.get("validation_details")),
                    json.dumps(validation_json.get("recommendations")),
                )
            )
            _commit_or_rollback(conn)
        except Exception:
            conn.rollback()
            raise


def get_validator_results(limit=50, offset=0, job_id=None, lite=False):
    with _db_cursor(psycopg2.extras.RealDictCursor) as (conn, cur):
        select_cols = "id, job_id, report_id, overall_status, created_at" if lite else "*"
        if job_id:
            cur.execute(
                f"SELECT {select_cols} FROM validator_results WHERE job_id = %s ORDER BY id DESC LIMIT %s OFFSET %s",
                (job_id, limit, offset),
            )
        else:
            cur.execute(
                f"SELECT {select_cols} FROM validator_results ORDER BY id DESC LIMIT %s OFFSET %s",
                (limit, offset),
            )
        rows = cur.fetchall()
        return rows


def get_validator_result(result_id):
    with _db_cursor(psycopg2.extras.RealDictCursor) as (conn, cur):
        cur.execute("SELECT * FROM validator_results WHERE id = %s", (result_id,))
        row = cur.fetchone()
        return row


def count_validator_results(job_id=None):
    with _db_cursor() as (conn, cur):
        if job_id:
            cur.execute("SELECT COUNT(*) FROM validator_results WHERE job_id = %s", (job_id,))
        else:
            cur.execute("SELECT COUNT(*) FROM validator_results")
        count = cur.fetchone()[0]
        return count
