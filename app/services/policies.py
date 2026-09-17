"""Policy management: drafts, immutable versions, CAS publish."""
from __future__ import annotations

from typing import Any, Dict, List

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import errors
from ..masking import RuleValidationError, validate_rules
from ..models import Policy, PolicyVersion


def _validate_or_raise(raw_rules: Any) -> None:
    try:
        validate_rules(raw_rules)
    except RuleValidationError as exc:
        raise errors.ApiError(422, errors.INVALID_RULES, str(exc)) from None


def create_policy(session: Session, name: str, raw_rules: List[Dict[str, Any]]) -> Policy:
    _validate_or_raise(raw_rules)
    policy = Policy(name=name, draft_rules=raw_rules)
    session.add(policy)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise errors.ApiError(409, errors.POLICY_EXISTS, "policy name already exists")
    return policy


def list_policies(session: Session) -> List[Policy]:
    return list(session.execute(select(Policy).order_by(Policy.name)).scalars())


def get_policy_or_404(session: Session, name: str) -> Policy:
    policy = session.execute(select(Policy).where(Policy.name == name)).scalar_one_or_none()
    if policy is None:
        raise errors.ApiError(404, errors.POLICY_NOT_FOUND, "policy not found")
    return policy


def update_draft(session: Session, policy: Policy, raw_rules: List[Dict[str, Any]]) -> Policy:
    _validate_or_raise(raw_rules)
    policy.draft_rules = raw_rules
    session.commit()
    return policy


def publish(session: Session, policy: Policy, expected_revision: int) -> PolicyVersion:
    """Publish the current draft as a new immutable version.

    CAS: the revision is incremented only if it still equals
    `expected_revision`; a concurrent publish loses the race and gets 409.
    """
    _validate_or_raise(policy.draft_rules)
    result = session.execute(
        update(Policy)
        .where(Policy.id == policy.id, Policy.revision == expected_revision)
        .values(revision=Policy.revision + 1)
        .returning(Policy.revision)
    )
    new_revision = result.scalar_one_or_none()
    if new_revision is None:
        session.rollback()
        raise errors.ApiError(
            409,
            errors.REVISION_CONFLICT,
            "expected_revision does not match current revision",
        )
    # The row is now locked by this transaction; the draft we read is the one
    # being published.
    session.refresh(policy)
    version = PolicyVersion(
        policy_id=policy.id, version=new_revision, rules=policy.draft_rules
    )
    session.add(version)
    session.commit()
    return version


def list_versions(session: Session, policy: Policy) -> List[PolicyVersion]:
    stmt = (
        select(PolicyVersion)
        .where(PolicyVersion.policy_id == policy.id)
        .order_by(PolicyVersion.version)
    )
    return list(session.execute(stmt).scalars())


def get_version_or_404(session: Session, policy: Policy, version: int) -> PolicyVersion:
    stmt = select(PolicyVersion).where(
        PolicyVersion.policy_id == policy.id, PolicyVersion.version == version
    )
    pv = session.execute(stmt).scalar_one_or_none()
    if pv is None:
        raise errors.ApiError(404, errors.VERSION_NOT_FOUND, "policy version not found")
    return pv
