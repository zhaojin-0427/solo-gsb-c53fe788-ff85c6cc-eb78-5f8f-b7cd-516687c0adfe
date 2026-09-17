"""Audit helpers.

Audit rows contain only: request id, policy id, policy version, input digest,
outcome, error code and applied-rule count. They are committed in the same
transaction as the transform result (success path); failure audits are written
in a separate transaction after the failed one has been rolled back.
"""
from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session, sessionmaker

from .logging_config import get_logger
from .models import AuditEvent

logger = get_logger("gateway.audit")

OUTCOME_SUCCESS = "success"
OUTCOME_ERROR = "error"


def add_audit_event(
    session: Session,
    *,
    request_id: str,
    policy_id,
    version: int,
    input_digest: str,
    outcome: str,
    error_code: Optional[str] = None,
    rules_applied: Optional[int] = None,
) -> None:
    session.add(
        AuditEvent(
            request_id=request_id,
            policy_id=policy_id,
            version=version,
            input_digest=input_digest,
            outcome=outcome,
            error_code=error_code,
            rules_applied=rules_applied,
        )
    )


def audit_failure(
    session_factory: sessionmaker,
    *,
    request_id: str,
    policy_id,
    version: int,
    input_digest: str,
    error_code: str,
) -> None:
    """Best-effort failure audit in its own transaction (post-rollback)."""
    try:
        with session_factory() as session:
            add_audit_event(
                session,
                request_id=request_id,
                policy_id=policy_id,
                version=version,
                input_digest=input_digest,
                outcome=OUTCOME_ERROR,
                error_code=error_code,
            )
            session.commit()
    except Exception:  # noqa: BLE001 - auditing must never break the request
        logger.error(
            "audit_write_failed",
            extra={"request_id": request_id, "error_code": error_code},
        )
