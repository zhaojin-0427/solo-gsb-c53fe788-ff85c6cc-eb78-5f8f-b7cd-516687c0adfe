"""JSON structured logging.

Only whitelisted, non-sensitive fields may appear in log records:
request id, route, status, policy name/version, input digest, error code.
Payload values (raw or masked) and secrets must never be logged.
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone

ALLOWED_EXTRA_FIELDS = (
    "request_id",
    "method",
    "route",
    "status_code",
    "policy",
    "version",
    "input_digest",
    "error_code",
    "event",
)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key in ALLOWED_EXTRA_FIELDS:
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        return json.dumps(payload, ensure_ascii=False, default=str)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    # Tame noisy framework loggers but keep them structured.
    for name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
        lg = logging.getLogger(name)
        lg.handlers[:] = [handler]
        lg.propagate = False


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
