import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "vulnerability_db")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_CONNECT_TIMEOUT = int(os.getenv("DB_CONNECT_TIMEOUT", "5"))
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
MAX_OPENAI_ATTEMPTS = int(os.getenv("MAX_OPENAI_ATTEMPTS", "3"))

def _abs_path(value: str) -> str:
    if os.path.isabs(value):
        return value
    return os.path.join(BASE_DIR, value)

KNOWLEDGEBASE_DIR = _abs_path(os.getenv("KNOWLEDGEBASE_DIR", "knowledgebase"))
REPORTS_DIR = _abs_path(os.getenv("REPORTS_DIR", "reports"))
LOGS_DIR = _abs_path(os.getenv("LOGS_DIR", "logs"))
SCRIPT_RESULTS_DIR = _abs_path(os.getenv("SCRIPT_RESULTS_DIR", "script_result"))

SANDBOX_DOCKER = os.getenv("SANDBOX_DOCKER", "1")
SANDBOX_DOCKER_IMAGE = os.getenv("SANDBOX_DOCKER_IMAGE", "vulnops-sandbox:latest")
SANDBOX_DOCKER_FALLBACK = os.getenv("SANDBOX_DOCKER_FALLBACK", "0")
SANDBOX_TIMEOUT = int(os.getenv("SANDBOX_TIMEOUT", "120"))
