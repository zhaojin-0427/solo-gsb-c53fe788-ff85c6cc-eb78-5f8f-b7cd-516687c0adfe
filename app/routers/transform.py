"""Transform endpoint."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Header, Request

from .. import errors
from ..config import get_settings
from ..db import get_session_factory
from ..schemas import TransformRequest
from ..services.transform import run_transform
from ..tokenize import make_token_fn

router = APIRouter(prefix="/v1/policies", tags=["transform"])

_token_fn = None


def _get_token_fn():
    global _token_fn
    if _token_fn is None:
        _token_fn = make_token_fn(get_settings().hmac_key)
    return _token_fn


@router.post("/{name}/transform")
def transform(
    name: str,
    body: TransformRequest,
    request: Request,
    idempotency_key: Optional[str] = Header(default=None),
):
    key = body.idempotency_key or idempotency_key
    if not key:
        raise errors.ApiError(
            422,
            errors.VALIDATION_FAILED,
            "idempotency key required (body field 'idempotency_key' or 'Idempotency-Key' header)",
        )
    settings = get_settings()
    return run_transform(
        get_session_factory(),
        settings=settings,
        policy_name=name,
        version=body.version,
        idempotency_key=key,
        document=body.document,
        request_id=request.state.request_id,
        token_fn=_get_token_fn(),
    )
