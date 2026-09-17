"""Pydantic request/response schemas."""
from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

POLICY_NAME_PATTERN = r"^[a-z0-9][a-z0-9-]{0,127}$"


class RuleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=64)
    path: str = Field(min_length=2, max_length=512)
    action: Literal["delete", "mask", "tokenize"]
    params: Optional[Dict[str, Any]] = None


class PolicyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=POLICY_NAME_PATTERN)
    rules: Optional[List[RuleIn]] = None


class DraftUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rules: List[RuleIn]


class PublishRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_revision: int = Field(ge=0)


class TransformRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = Field(ge=1)
    idempotency_key: Optional[str] = Field(default=None, min_length=1, max_length=200)
    document: Any  # required; any JSON value


def rules_to_raw(rules: Optional[List[RuleIn]]) -> List[Dict[str, Any]]:
    """Normalize validated rule models into the stored JSONB representation."""
    raw: List[Dict[str, Any]] = []
    for r in rules or []:
        raw.append(
            {
                "id": r.id,
                "path": r.path,
                "action": r.action,
                "params": r.params or {},
            }
        )
    return raw
