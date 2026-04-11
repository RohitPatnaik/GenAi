import json
import logging
import os
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Any

AI_SCANNER_LOG_DIR = r"C:\aiaptt\logs\ai_scanner_logs"
LOG_FORMAT = "%(asctime)s | %(levelname)s | %(name)s | %(filename)s:%(lineno)d | %(message)s"


def setup_scanner_logger(name: str, log_filename: str, add_stream: bool = False) -> logging.Logger:
    """Create or reuse scanner logger with rotating file output."""
    os.makedirs(AI_SCANNER_LOG_DIR, exist_ok=True)
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    log_file_path = os.path.abspath(os.path.join(AI_SCANNER_LOG_DIR, log_filename))
    formatter = logging.Formatter(LOG_FORMAT)

    has_rotating_handler = False
    has_stream_handler = False

    for handler in logger.handlers:
        if isinstance(handler, RotatingFileHandler) and os.path.abspath(getattr(handler, "baseFilename", "")) == log_file_path:
            has_rotating_handler = True
        if isinstance(handler, logging.StreamHandler) and not isinstance(handler, RotatingFileHandler):
            has_stream_handler = True

    if not has_rotating_handler:
        rotating_handler = RotatingFileHandler(
            log_file_path,
            maxBytes=100 * 1024 * 1024,
            backupCount=20,
            encoding="utf-8",
        )
        rotating_handler.setFormatter(formatter)
        logger.addHandler(rotating_handler)

    if add_stream and not has_stream_handler:
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

    return logger


def log_scan_event(
    logger: logging.Logger,
    level: str,
    message: str,
    job_id: str | None = None,
    stage: str | None = None,
    **details: Any,
) -> None:
    payload = {
        "event_time_utc": datetime.utcnow().isoformat() + "Z",
        "job_id": job_id,
        "stage": stage,
        "message": message,
    }
    payload.update(details)

    line = json.dumps(payload, ensure_ascii=True)
    lvl = (level or "info").lower()
    if lvl == "error":
        logger.error(line)
    elif lvl == "warning":
        logger.warning(line)
    else:
        logger.info(line)


def log_stage_update(
    logger: logging.Logger,
    job_id: str | None,
    stage: str,
    status: str | None = None,
    **details: Any,
) -> None:
    log_scan_event(
        logger,
        "info",
        "scan_stage_update",
        job_id=job_id,
        stage=stage,
        status=status,
        **details,
    )
