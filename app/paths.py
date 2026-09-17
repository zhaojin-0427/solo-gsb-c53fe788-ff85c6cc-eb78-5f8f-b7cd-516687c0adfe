"""Restricted JSON path syntax: `$`, `.name`, `[n]`, `[*]`.

- `$`         document root (must be followed by at least one segment)
- `.name`     object member; name must match [A-Za-z_][A-Za-z0-9_]*
- `[n]`       array index (non-negative integer)
- `[*]`       wildcard over all array elements

Matching is always performed against the *original* document; the matcher
returns concrete matches (parent reference, key/index, value, canonical path)
so the masking engine can mutate the document afterwards.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, List, Optional


class PathSyntaxError(ValueError):
    """Raised when a rule path does not conform to the supported grammar."""


_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

KIND_KEY = "key"
KIND_INDEX = "index"
KIND_WILDCARD = "wildcard"


@dataclass(frozen=True)
class Segment:
    kind: str
    value: Optional[Any] = None


@dataclass
class Match:
    parent: Any          # container holding the matched node
    key: Any             # dict key or list index of the matched node
    value: Any           # matched value (snapshot from the original document)
    path: str            # canonical concrete path, e.g. $.users[2].ssn


def parse_path(text: Any) -> List[Segment]:
    if not isinstance(text, str) or not text:
        raise PathSyntaxError("path must be a non-empty string")
    if text[0] != "$":
        raise PathSyntaxError("path must start with '$'")
    segments: List[Segment] = []
    i = 1
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == ".":
            m = _NAME_RE.match(text, i + 1)
            if not m:
                raise PathSyntaxError(f"invalid member name at position {i}")
            segments.append(Segment(KIND_KEY, m.group(0)))
            i = m.end()
        elif ch == "[":
            j = text.find("]", i)
            if j == -1:
                raise PathSyntaxError("unclosed '['")
            inner = text[i + 1 : j]
            if inner == "*":
                segments.append(Segment(KIND_WILDCARD))
            elif inner.isdigit():
                segments.append(Segment(KIND_INDEX, int(inner)))
            else:
                raise PathSyntaxError(f"invalid bracket selector '[{inner}]'")
            i = j + 1
        else:
            raise PathSyntaxError(f"unexpected character {ch!r} at position {i}")
    if not segments:
        raise PathSyntaxError("path must contain at least one segment after '$'")
    return segments


def find_matches(document: Any, segments: List[Segment]) -> List[Match]:
    """Return every concrete match of `segments` in `document`, in document order."""
    results: List[Match] = []

    def walk(node: Any, parent: Any, key: Any, idx: int, path: str) -> None:
        if idx == len(segments):
            results.append(Match(parent=parent, key=key, value=node, path=path))
            return
        seg = segments[idx]
        if seg.kind == KIND_KEY:
            if isinstance(node, dict) and seg.value in node:
                walk(node[seg.value], node, seg.value, idx + 1, path + "." + seg.value)
        elif seg.kind == KIND_INDEX:
            if isinstance(node, list) and 0 <= seg.value < len(node):
                walk(node[seg.value], node, seg.value, idx + 1, f"{path}[{seg.value}]")
        else:  # wildcard over array elements
            if isinstance(node, list):
                for i, item in enumerate(node):
                    walk(item, node, i, idx + 1, f"{path}[{i}]")

    walk(document, None, None, 0, "$")
    return results
