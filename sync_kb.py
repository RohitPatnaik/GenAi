import os
import re
import psycopg2
from typing import List

from config import KNOWLEDGEBASE_DIR, DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD, DB_CONNECT_TIMEOUT
from utils.file_utils import get_cve_script_path

CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")


def find_cve_dirs(base: str) -> List[str]:
    if not os.path.isdir(base):
        return []
    return [name for name in os.listdir(base) if os.path.isdir(os.path.join(base, name)) and CVE_RE.match(name)]


def get_conn():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        connect_timeout=DB_CONNECT_TIMEOUT,
    )


def sync_knowledgebase() -> int:
    cves = find_cve_dirs(KNOWLEDGEBASE_DIR)
    updated = 0
    conn = get_conn()
    cur = conn.cursor()
    try:
        for cve in cves:
            script_path = get_cve_script_path(cve)
            if not os.path.isfile(script_path):
                continue

            cur.execute("SELECT 1 FROM network_vulnerabilities WHERE cve = %s", (cve,))
            exists = cur.fetchone() is not None

            if not exists:
                cur.execute(
                    """
                    INSERT INTO network_vulnerabilities (cve, cwe, title, description, has_script, script_path)
                    VALUES (%s,%s,%s,%s,%s,%s)
                    """,
                    (cve, '', '', '', 1, script_path)
                )
            else:
                cur.execute(
                    """
                    UPDATE network_vulnerabilities
                    SET has_script = %s, script_path = %s, updated_at = CURRENT_TIMESTAMP
                    WHERE cve = %s
                    """,
                    (1, script_path, cve)
                )
            updated += 1

        conn.commit()
    finally:
        cur.close()
        conn.close()
    return updated


if __name__ == '__main__':
    try:
        count = sync_knowledgebase()
        print(f"Synced {count} scripts from knowledgebase into DB.")
    except Exception as e:
        print("DB connection failed. Check DB settings and that Postgres is running.")
        print(e)
