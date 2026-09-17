"""Deterministic HMAC-SHA256 tokenization based on a server-side key.

The same logical value always maps to the same token (deterministic), which
lets internal systems join/token-match without seeing cleartext. The key comes
from the MASKING_HMAC_KEY environment variable and is never logged or exposed.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Any, Callable

from . import jcs

_TOKEN_PREFIX = "tok_"
_DOMAIN = b"masking-gateway:v1:"


def make_token_fn(secret: str) -> Callable[[Any], str]:
    key = secret.encode("utf-8")

    def token_fn(value: Any) -> str:
        canonical = jcs.canonicalize(value).encode("utf-8")
        mac = hmac.new(key, _DOMAIN + canonical, hashlib.sha256)
        return _TOKEN_PREFIX + mac.hexdigest()

    return token_fn
