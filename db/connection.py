import threading

import psycopg2
from psycopg2 import sql
from psycopg2.pool import SimpleConnectionPool
from config import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD, DB_CONNECT_TIMEOUT


_db_initialized = False
_db_initialized_lock = threading.Lock()
_pool = None
_pool_lock = threading.Lock()


class _PooledConnection:
    """Proxy connection that returns the underlying connection to the pool on close."""

    def __init__(self, pool, connection):
        self._pool = pool
        self._connection = connection
        self._returned = False

    def close(self):
        if not self._returned and self._connection is not None:
            self._pool.putconn(self._connection)
            self._returned = True

    def __getattr__(self, name):
        return getattr(self._connection, name)


def _build_connection_kwargs(dbname: str) -> dict:
    return {
        "host": DB_HOST,
        "port": DB_PORT,
        "dbname": dbname,
        "user": DB_USER,
        "password": DB_PASSWORD,
        "connect_timeout": DB_CONNECT_TIMEOUT,
    }


def ensure_database_exists():
    """Create the configured database if it does not already exist."""
    global _db_initialized
    if _db_initialized:
        return

    with _db_initialized_lock:
        if _db_initialized:
            return

        conn = None
        try:
            conn = psycopg2.connect(**_build_connection_kwargs("postgres"))
            conn.autocommit = True
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (DB_NAME,))
            exists = cur.fetchone() is not None
            if not exists:
                cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(DB_NAME)))
            cur.close()
            _db_initialized = True
        finally:
            if conn is not None:
                conn.close()


def _get_pool():
    global _pool
    ensure_database_exists()
    if _pool is not None:
        return _pool

    with _pool_lock:
        if _pool is None:
            _pool = SimpleConnectionPool(1, 10, **_build_connection_kwargs(DB_NAME))
    return _pool


def get_connection():
    """Return a pooled connection to the PostgreSQL database."""
    pool = _get_pool()
    connection = pool.getconn()
    connection.reset()
    return _PooledConnection(pool, connection)

def init_db():
    """Create the network_vulnerabilities table if it doesn't exist."""
    commands = (
        """
        CREATE TABLE IF NOT EXISTS network_vulnerabilities (
            id SERIAL PRIMARY KEY,
            cve VARCHAR(20) UNIQUE NOT NULL,
            cwe VARCHAR(20),
            title TEXT,
            description TEXT,
            cvss_score NUMERIC,
            severity TEXT,
            has_script SMALLINT DEFAULT 0,
            script_path TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_network_vulnerabilities_cve
        ON network_vulnerabilities (cve)
        """,
        """
        CREATE TABLE IF NOT EXISTS scan_jobs (
            id UUID PRIMARY KEY,
            job_name TEXT,
            priority TEXT,
            source_type TEXT,
            source_path TEXT,
            exploit_mode TEXT,
            fallback_llm TEXT,
            validation_mode TEXT,
            sandbox_target TEXT,
            target_url TEXT,
            input_file TEXT,
            output_file TEXT,
            created_by TEXT,
            status TEXT,
            stage TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS scan_events (
            id SERIAL PRIMARY KEY,
            job_id UUID REFERENCES scan_jobs(id) ON DELETE CASCADE,
            stage TEXT,
            level TEXT,
            message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_scan_events_job_id
        ON scan_events (job_id)
        """,
        """
        CREATE TABLE IF NOT EXISTS scan_results (
            id SERIAL PRIMARY KEY,
            job_id UUID REFERENCES scan_jobs(id) ON DELETE CASCADE,
            cve TEXT,
            stage TEXT,
            success BOOLEAN,
            returncode INT,
            stdout TEXT,
            stderr TEXT,
            error TEXT,
            script_path TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_scan_results_job_id
        ON scan_results (job_id)
        """,
        """
        CREATE TABLE IF NOT EXISTS scan_reports (
            id SERIAL PRIMARY KEY,
            job_id UUID REFERENCES scan_jobs(id) ON DELETE CASCADE,
            summary_json JSONB,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_scan_reports_job_id
        ON scan_reports (job_id)
        """,
        """
        CREATE TABLE IF NOT EXISTS validator_results (
            id SERIAL PRIMARY KEY,
            job_id UUID REFERENCES scan_jobs(id) ON DELETE CASCADE,
            report_id INT REFERENCES scan_reports(id) ON DELETE CASCADE,
            overall_status TEXT,
            summary_json JSONB,
            details_json JSONB,
            recommendations JSONB,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_validator_results_job_id
        ON validator_results (job_id)
        """
    )
    conn = None
    try:
        conn = get_connection()
        cur = conn.cursor()
        for command in commands:
            cur.execute(command)
        cur.close()
        conn.commit()
        print("Database initialized successfully.")
    except (Exception, psycopg2.DatabaseError) as error:
        print(f"Error initializing database: {error}")
    finally:
        if conn is not None:
            conn.close()

def ensure_schema():
    """Ensure newer columns exist on existing tables."""
    commands = (
        "ALTER TABLE network_vulnerabilities ADD COLUMN IF NOT EXISTS cvss_score NUMERIC",
        "ALTER TABLE network_vulnerabilities ADD COLUMN IF NOT EXISTS severity TEXT",
        "ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS input_file TEXT",
        "ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS output_file TEXT",
        "ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS created_by TEXT",
        "CREATE TABLE IF NOT EXISTS scan_results (id SERIAL PRIMARY KEY, job_id UUID REFERENCES scan_jobs(id) ON DELETE CASCADE, cve TEXT, stage TEXT, success BOOLEAN, returncode INT, stdout TEXT, stderr TEXT, error TEXT, script_path TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)",
        "CREATE INDEX IF NOT EXISTS idx_scan_results_job_id ON scan_results (job_id)",
        "CREATE TABLE IF NOT EXISTS scan_reports (id SERIAL PRIMARY KEY, job_id UUID REFERENCES scan_jobs(id) ON DELETE CASCADE, summary_json JSONB, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)",
        "CREATE INDEX IF NOT EXISTS idx_scan_reports_job_id ON scan_reports (job_id)",
        "CREATE TABLE IF NOT EXISTS validator_results (id SERIAL PRIMARY KEY, job_id UUID REFERENCES scan_jobs(id) ON DELETE CASCADE, report_id INT REFERENCES scan_reports(id) ON DELETE CASCADE, overall_status TEXT, summary_json JSONB, details_json JSONB, recommendations JSONB, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)",
        "CREATE INDEX IF NOT EXISTS idx_validator_results_job_id ON validator_results (job_id)",
    )
    conn = None
    try:
        conn = get_connection()
        cur = conn.cursor()
        for command in commands:
            cur.execute(command)
        cur.close()
        conn.commit()
    except (Exception, psycopg2.DatabaseError) as error:
        print(f"Error ensuring schema: {error}")
    finally:
        if conn is not None:
            conn.close()
