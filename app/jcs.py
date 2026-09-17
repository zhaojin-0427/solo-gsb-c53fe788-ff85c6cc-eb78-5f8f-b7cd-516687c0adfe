"""RFC 8785 JSON Canonicalization Scheme (JCS) — minimal, dependency-free implementation.

Used to compute the stable input digest stored with each idempotency key.
Only JSON data model values are supported: None, bool, int, float, str, list, dict.
"""
from __future__ import annotations

import hashlib
import math
from typing import Any


class CanonicalizationError(ValueError):
    """Raised when a value cannot be canonicalized (e.g. lone surrogates, NaN)."""


def _escape_string(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\r":
            out.append("\\r")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        elif 0xD800 <= o <= 0xDFFF:
            raise CanonicalizationError("string contains a lone surrogate")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _number(value: Any) -> str:
    """ECMAScript Number::toString semantics, as required by RFC 8785."""
    if isinstance(value, bool):
        raise CanonicalizationError("bool is not a number")
    if isinstance(value, int):
        return str(value)
    f = float(value)
    if math.isnan(f) or math.isinf(f):
        raise CanonicalizationError("non-finite number")
    if f == 0:
        return "0"
    sign = ""
    if f < 0:
        sign = "-"
        f = -f
    # repr() yields the shortest round-trip decimal, same digits as ES6.
    r = repr(f)
    if "e" in r or "E" in r:
        mant, _, exp_s = r.replace("E", "e").partition("e")
        exp = int(exp_s)
    else:
        mant, exp = r, 0
    if "." in mant:
        ip, _, fp = mant.partition(".")
    else:
        ip, fp = mant, ""
    # value = I * 10^E
    digits = ip + fp
    e = exp - len(fp)
    i_val = int(digits) if digits else 0
    # strip trailing zeros, shifting them into the exponent
    while i_val and i_val % 10 == 0:
        i_val //= 10
        e += 1
    d = str(i_val)
    k = len(d)
    n = e + k  # value == 0.d * 10^n
    if k <= n <= 21:
        body = d + "0" * (n - k)
    elif 0 < n <= 21:
        body = d[:n] + "." + d[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + d
    else:
        body = d[0]
        if k > 1:
            body += "." + d[1:]
        body += "e" + ("+" if n - 1 >= 0 else "-") + str(abs(n - 1))
    return sign + body


def _sort_key(key: Any) -> bytes:
    if not isinstance(key, str):
        raise CanonicalizationError("object keys must be strings")
    try:
        # RFC 8785 sorts by UTF-16 code units.
        return key.encode("utf-16-be")
    except UnicodeEncodeError:
        raise CanonicalizationError("object key contains a lone surrogate") from None


def canonicalize(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return _number(value)
    if isinstance(value, str):
        return _escape_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonicalize(v) for v in value) + "]"
    if isinstance(value, dict):
        parts = []
        for k in sorted(value.keys(), key=_sort_key):
            parts.append(_escape_string(k) + ":" + canonicalize(value[k]))
        return "{" + ",".join(parts) + "}"
    raise CanonicalizationError(f"unsupported type: {type(value).__name__}")


def digest(value: Any) -> str:
    """SHA-256 hex digest of the JCS canonical form."""
    return hashlib.sha256(canonicalize(value).encode("utf-8")).hexdigest()
