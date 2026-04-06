import os
from config import REPORTS_DIR, LOGS_DIR, KNOWLEDGEBASE_DIR, SCRIPT_RESULTS_DIR

def ensure_dirs():
    """Create necessary directories if they don't exist."""
    dirs = [REPORTS_DIR, LOGS_DIR, KNOWLEDGEBASE_DIR, SCRIPT_RESULTS_DIR, "prompts", "scanner_parser"]
    for d in dirs:
        os.makedirs(d, exist_ok=True)

def get_cve_script_path(cve: str) -> str:
    """Return the canonical script path for a CVE inside the knowledgebase."""
    return os.path.join(KNOWLEDGEBASE_DIR, cve, f"{cve}.py")

def ensure_cve_dir(cve: str):
    """Ensure the CVE subdirectory exists in the knowledgebase."""
    os.makedirs(os.path.join(KNOWLEDGEBASE_DIR, cve), exist_ok=True)
