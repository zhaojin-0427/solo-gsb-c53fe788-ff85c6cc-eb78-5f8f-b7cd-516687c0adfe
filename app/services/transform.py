"""Transform execution with scoped idempotency.

Idempotency record lifecycle (unique on policy_id + version + key):
- The first request inserts an in_progress placeholder inside the transform
  transaction. Concurrent requests with the same key block on the unique
  constraint until the leader commits or rolls back.
- Leader commits result + audit in ONE transaction; followers then read the
  stored response and replay it (no new audit row).
- Same key with a different input digest -> 409 IDEMPOTENCY_KEY_CONFLICT.
- If the leader fails before commit, the placeholder is rolled back, so the
  same key can be retried (a blocked follower then becomes the new leader).
"""
from __future__ import annotations

from typing import Any, Callable, Dict

from sqlalchemy import func, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from .. import errors
from ..audit import OUTCOME_SUCCESS, add_audit_event, audit_failure
from ..config import Settings
from ..jcs import CanonicalizationError, digest as jcs_digest
from ..logging_config import get_logger
from ..masking import STATUS_APPLIED, apply_rules, validate_rules
from ..models import IdempotencyKey, Policy, PolicyVersion
from .policies import get_policy_or_404, get_version_or_404

logger = get_logger("gateway.transform")


def _is_lock_timeout(exc: OperationalError) -> bool:
    orig = getattr(exc, "orig", None)
    pgcode = getattr(orig, "pgcode", None)
    if pgcode == "55P03":  # lock_not_available
        return True
    return "lock timeout" in str(exc).lower()


def run_transform(
    session_factory: sessionmaker,
    *,
    settings: Settings,
    policy_name: str,
    version: int,
    idempotency_key: str,
    document: Any,
    request_id: str,
    token_fn: Callable[[Any], str],
) -> Dict[str, Any]:
    try:
        input_digest = jcs_digest(document)
    except CanonicalizationError:
        raise errors.ApiError(
            422, errors.INVALID_DOCUMENT, "document cannot be canonicalized"
        ) from None

    with session_factory() as session:
        policy = get_policy_or_404(session, policy_name)
        pv = get_version_or_404(session, policy, version)

        session.execute(
            text(f"SET LOCAL lock_timeout = {int(settings.idempotency_lock_timeout_ms)}")
        )
        insert_stmt = (
            pg_insert(IdempotencyKey)
            .values(
                policy_id=policy.id,
                version=pv.version,
                key=idempotency_key,
                input_digest=input_digest,
                status=IdempotencyKey.STATUS_IN_PROGRESS,
            )
            .on_conflict_do_nothing(constraint="uq_idem_scope")
            .returning(IdempotencyKey.id)
        )
        try:
            leader_row_id = session.execute(insert_stmt).scalar_one_or_none()
        except OperationalError as exc:
            session.rollback()
            if _is_lock_timeout(exc):
                raise errors.ApiError(
                    503,
                    errors.IDEMPOTENCY_WAIT_TIMEOUT,
                    "timed out waiting for a concurrent request with the same key",
                ) from None
            raise

        if leader_row_id is None:
            return _replay(session, policy, pv, idempotency_key, input_digest, request_id)

        return _execute_as_leader(
            session,
            session_factory,
            policy=policy,
            pv=pv,
            leader_row_id=leader_row_id,
            idempotency_key=idempotency_key,
            input_digest=input_digest,
            document=document,
            request_id=request_id,
            token_fn=token_fn,
        )


def _replay(
    session,
    policy: Policy,
    pv: PolicyVersion,
    idempotency_key: str,
    input_digest: str,
    request_id: str,
) -> Dict[str, Any]:
    """Follower path: the leader's transaction has finished (our insert was a
    no-op), so the completed row is visible under READ COMMITTED."""
    stmt = select(IdempotencyKey).where(
        IdempotencyKey.policy_id == policy.id,
        IdempotencyKey.version == pv.version,
        IdempotencyKey.key == idempotency_key,
    )
    existing = session.execute(stmt).scalar_one()
    if existing.status != IdempotencyKey.STATUS_COMPLETED or existing.response is None:
        # Defensive: a persisted row is always completed (placeholder and
        # completion live in one transaction). If not, ask the client to retry.
        raise errors.ApiError(
            503,
            errors.IDEMPOTENCY_WAIT_TIMEOUT,
            "a request with the same key is still in progress; retry later",
        )
    if existing.input_digest != input_digest:
        add_audit_event(
            session,
            request_id=request_id,
            policy_id=policy.id,
            version=pv.version,
            input_digest=input_digest,
            outcome="error",
            error_code=errors.IDEMPOTENCY_KEY_CONFLICT,
        )
        session.commit()
        raise errors.ApiError(
            409,
            errors.IDEMPOTENCY_KEY_CONFLICT,
            "idempotency key was already used with a different input",
        )
    logger.info(
        "idempotent_replay",
        extra={
            "request_id": request_id,
            "policy": policy.name,
            "version": pv.version,
            "input_digest": input_digest,
        },
    )
    body = dict(existing.response)
    body["request_id"] = request_id
    body["replayed"] = True
    return body


def _execute_as_leader(
    session,
    session_factory: sessionmaker,
    *,
    policy: Policy,
    pv: PolicyVersion,
    leader_row_id,
    idempotency_key: str,
    input_digest: str,
    document: Any,
    request_id: str,
    token_fn: Callable[[Any], str],
) -> Dict[str, Any]:
    try:
        rules = validate_rules(pv.rules)
        result, trace = apply_rules(document, rules, token_fn)
    except CanonicalizationError:
        session.rollback()  # placeholder rolled back -> same key may retry
        audit_failure(
            session_factory,
            request_id=request_id,
            policy_id=policy.id,
            version=pv.version,
            input_digest=input_digest,
            error_code=errors.INVALID_DOCUMENT,
        )
        raise errors.ApiError(
            422, errors.INVALID_DOCUMENT, "document contains values that cannot be processed"
        ) from None
    except Exception:
        session.rollback()  # placeholder rolled back -> same key may retry
        audit_failure(
            session_factory,
            request_id=request_id,
            policy_id=policy.id,
            version=pv.version,
            input_digest=input_digest,
            error_code=errors.TRANSFORM_FAILED,
        )
        # Note: the traceback is deliberately not logged — it may contain values.
        raise errors.ApiError(500, errors.TRANSFORM_FAILED, "transform failed") from None

    response_body = {
        "policy": policy.name,
        "version": pv.version,
        "result": result,
        "trace": trace,
    }
    applied = sum(1 for e in trace if e["status"] == STATUS_APPLIED)
    session.execute(
        update(IdempotencyKey)
        .where(IdempotencyKey.id == leader_row_id)
        .values(
            status=IdempotencyKey.STATUS_COMPLETED,
            response=response_body,
            completed_at=func.now(),
        )
    )
    add_audit_event(
        session,
        request_id=request_id,
        policy_id=policy.id,
        version=pv.version,
        input_digest=input_digest,
        outcome=OUTCOME_SUCCESS,
        rules_applied=applied,
    )
    # Result + audit commit atomically here.
    session.commit()
    logger.info(
        "transform_completed",
        extra={
            "request_id": request_id,
            "policy": policy.name,
            "version": pv.version,
            "input_digest": input_digest,
        },
    )
    body = dict(response_body)
    body["request_id"] = request_id
    body["replayed"] = False
    return body
