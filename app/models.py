"""ORM models.

Data-minimization note: idempotency_keys.response stores the *masked* result
(required for replay) and audit_events stores only request id, policy version,
input digest and outcome — never raw or sensitive values.
"""
from __future__ import annotations

import uuid

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID

from .db import Base


class Policy(Base):
    __tablename__ = "policies"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(128), unique=True, nullable=False, index=True)
    # CAS counter: incremented on every successful publish.
    revision = Column(Integer, nullable=False, default=0)
    draft_rules = Column(JSONB, nullable=False, default=list)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class PolicyVersion(Base):
    """Immutable published snapshot of a policy's rules."""

    __tablename__ = "policy_versions"
    __table_args__ = (UniqueConstraint("policy_id", "version", name="uq_policy_version"),)

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    policy_id = Column(
        UUID(as_uuid=True), ForeignKey("policies.id", ondelete="CASCADE"), nullable=False
    )
    version = Column(Integer, nullable=False)
    rules = Column(JSONB, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class IdempotencyKey(Base):
    """Idempotency record, scoped to (policy, version, key).

    status: in_progress -> completed. A failed attempt is rolled back, so no
    persisted 'failed' state exists and the same key may be retried.
    """

    __tablename__ = "idempotency_keys"
    __table_args__ = (
        UniqueConstraint("policy_id", "version", "key", name="uq_idem_scope"),
    )

    STATUS_IN_PROGRESS = "in_progress"
    STATUS_COMPLETED = "completed"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    policy_id = Column(
        UUID(as_uuid=True), ForeignKey("policies.id", ondelete="CASCADE"), nullable=False
    )
    version = Column(Integer, nullable=False)
    key = Column(String(200), nullable=False)
    input_digest = Column(String(64), nullable=False)
    status = Column(String(16), nullable=False, default=STATUS_IN_PROGRESS)
    response = Column(JSONB, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)


class AuditEvent(Base):
    """Audit trail. Only non-sensitive metadata is ever stored here."""

    __tablename__ = "audit_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    request_id = Column(String(64), nullable=False, index=True)
    policy_id = Column(UUID(as_uuid=True), nullable=False)
    version = Column(Integer, nullable=False)
    input_digest = Column(String(64), nullable=False)
    outcome = Column(String(16), nullable=False)  # success | error
    error_code = Column(String(64), nullable=True)
    rules_applied = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
