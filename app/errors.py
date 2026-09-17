"""Application error type and stable error codes.

Error responses and logs must only ever carry: request id, policy/version,
input digest and the error code — never raw or masked sensitive values.
"""
from __future__ import annotations

from typing import Optional


# Stable error codes
POLICY_NOT_FOUND = "POLICY_NOT_FOUND"
VERSION_NOT_FOUND = "VERSION_NOT_FOUND"
POLICY_EXISTS = "POLICY_EXISTS"
REVISION_CONFLICT = "REVISION_CONFLICT"
IDEMPOTENCY_KEY_CONFLICT = "IDEMPOTENCY_KEY_CONFLICT"
IDEMPOTENCY_WAIT_TIMEOUT = "IDEMPOTENCY_WAIT_TIMEOUT"
INVALID_RULES = "INVALID_RULES"
INVALID_DOCUMENT = "INVALID_DOCUMENT"
VALIDATION_FAILED = "VALIDATION_FAILED"
TRANSFORM_FAILED = "TRANSFORM_FAILED"
INTERNAL_ERROR = "INTERNAL_ERROR"


class ApiError(Exception):
    def __init__(self, status_code: int, code: str, message: Optional[str] = None):
        super().__init__(code)
        self.status_code = status_code
        self.code = code
        # Messages must be static/generic — never include payload values.
        self.message = message or code
