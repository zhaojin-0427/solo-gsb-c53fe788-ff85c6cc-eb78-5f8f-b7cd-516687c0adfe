"""Rule validation and the masking engine.

Execution semantics (per transform):
1. All matches for all rules are computed against the ORIGINAL document.
2. A node hit by several rules is governed only by the first rule in
   declaration order; later hits on the same node are traced as "shadowed".
3. Hits whose ancestor node is deleted are traced as "skipped"
   (reason "ancestor_deleted").
4. Value-changing actions (mask / tokenize) are applied first, in declaration
   order; deletions are applied last, array elements in descending index order
   so that indices computed on the original document stay valid.
"""
from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .paths import PathSyntaxError, Segment, find_matches, parse_path

ACTION_DELETE = "delete"
ACTION_MASK = "mask"
ACTION_TOKENIZE = "tokenize"
ACTIONS = (ACTION_DELETE, ACTION_MASK, ACTION_TOKENIZE)

STATUS_APPLIED = "applied"
STATUS_SHADOWED = "shadowed"
STATUS_SKIPPED = "skipped"
STATUS_NO_MATCH = "no_match"

MASK_PARAM_KEYS = {"keep_first", "keep_last", "mask_char"}
DEFAULT_MASK_CHAR = "*"
SCALAR_MASK_LENGTH = 6

_RULE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class RuleValidationError(ValueError):
    """Raised when a rule set fails validation."""


@dataclass
class Rule:
    id: str
    path: str
    action: str
    params: Dict[str, Any] = field(default_factory=dict)
    segments: List[Segment] = field(default_factory=list)


def validate_rules(raw_rules: Any) -> List[Rule]:
    """Validate a raw rules list (as stored in a draft / version) into Rule objects."""
    if not isinstance(raw_rules, list):
        raise RuleValidationError("rules must be a list")
    rules: List[Rule] = []
    seen_ids = set()
    for i, raw in enumerate(raw_rules):
        where = f"rules[{i}]"
        if not isinstance(raw, dict):
            raise RuleValidationError(f"{where}: rule must be an object")
        rid = raw.get("id")
        if not isinstance(rid, str) or not _RULE_ID_RE.match(rid):
            raise RuleValidationError(f"{where}.id: must match {_RULE_ID_RE.pattern}")
        if rid in seen_ids:
            raise RuleValidationError(f"{where}.id: duplicate rule id")
        seen_ids.add(rid)
        try:
            segments = parse_path(raw.get("path"))
        except PathSyntaxError as exc:
            raise RuleValidationError(f"{where}.path: {exc}") from None
        action = raw.get("action")
        if action not in ACTIONS:
            raise RuleValidationError(
                f"{where}.action: must be one of {', '.join(ACTIONS)}"
            )
        params = raw.get("params")
        if params is None:
            params = {}
        if not isinstance(params, dict):
            raise RuleValidationError(f"{where}.params: must be an object")
        if action == ACTION_MASK:
            extra = set(params) - MASK_PARAM_KEYS
            if extra:
                raise RuleValidationError(
                    f"{where}.params: unsupported keys: {sorted(extra)}"
                )
            for name in ("keep_first", "keep_last"):
                v = params.get(name, 0)
                if not isinstance(v, int) or isinstance(v, bool) or not 0 <= v <= 10000:
                    raise RuleValidationError(
                        f"{where}.params.{name}: must be an integer between 0 and 10000"
                    )
            mc = params.get("mask_char", DEFAULT_MASK_CHAR)
            if not isinstance(mc, str) or len(mc) != 1:
                raise RuleValidationError(
                    f"{where}.params.mask_char: must be a single character"
                )
        elif params:
            raise RuleValidationError(f"{where}.params: action '{action}' takes no params")
        rules.append(
            Rule(id=rid, path=raw["path"], action=action, params=params, segments=segments)
        )
    return rules


@dataclass
class _Hit:
    rule_idx: int
    rule: Rule
    parent: Any
    key: Any
    value: Any
    path: str


def _trace_entry(hit: _Hit, status: str, reason: Optional[str] = None) -> Dict[str, Any]:
    entry = {
        "rule_id": hit.rule.id,
        "rule_index": hit.rule_idx,
        "path": hit.path,
        "action": hit.rule.action,
        "status": status,
    }
    if reason:
        entry["reason"] = reason
    return entry


def _is_descendant(path: str, ancestor: str) -> bool:
    return path.startswith(ancestor + ".") or path.startswith(ancestor + "[")


def _mask_value(value: Any, params: Dict[str, Any]) -> Tuple[Any, Optional[str]]:
    keep_first = params.get("keep_first", 0)
    keep_last = params.get("keep_last", 0)
    ch = params.get("mask_char", DEFAULT_MASK_CHAR)
    if isinstance(value, str):
        if len(value) <= keep_first + keep_last:
            return ch * len(value), None
        middle = len(value) - keep_first - keep_last
        tail = value[len(value) - keep_last :] if keep_last else ""
        return value[:keep_first] + ch * middle + tail, None
    if value is None or isinstance(value, (bool, int, float)):
        return ch * SCALAR_MASK_LENGTH, None
    return None, "unsupported_target_type"


def _tokenize_value(value: Any, token_fn: Callable[[Any], str]) -> Tuple[Any, Optional[str]]:
    if isinstance(value, (dict, list)):
        return None, "unsupported_target_type"
    return token_fn(value), None


def apply_rules(
    document: Any,
    rules: List[Rule],
    token_fn: Callable[[Any], str],
) -> Tuple[Any, List[Dict[str, Any]]]:
    """Apply `rules` to a deep copy of `document`; return (result, trace)."""
    result = copy.deepcopy(document)

    # 1. All matches are computed against the original (unmodified) document.
    hits: List[_Hit] = []
    for idx, rule in enumerate(rules):
        for m in find_matches(result, rule.segments):
            hits.append(
                _Hit(
                    rule_idx=idx,
                    rule=rule,
                    parent=m.parent,
                    key=m.key,
                    value=m.value,
                    path=m.path,
                )
            )

    # 2. First rule in declaration order wins per node; later hits are shadowed.
    winners: Dict[str, _Hit] = {}
    shadowed: List[_Hit] = []
    for hit in hits:
        if hit.path in winners:
            shadowed.append(hit)
        else:
            winners[hit.path] = hit

    # 3. Hits below a deleted ancestor are skipped.
    deleted_paths = {p for p, h in winners.items() if h.rule.action == ACTION_DELETE}
    applicable: List[_Hit] = []
    skipped: List[Tuple[_Hit, str]] = []
    for path, hit in winners.items():
        if any(_is_descendant(path, dp) for dp in deleted_paths):
            skipped.append((hit, "ancestor_deleted"))
        else:
            applicable.append(hit)

    trace: List[Dict[str, Any]] = []

    # 4a. Value-changing actions first, in declaration order.
    changers = sorted(
        (h for h in applicable if h.rule.action != ACTION_DELETE),
        key=lambda h: h.rule_idx,
    )
    for hit in changers:
        if hit.rule.action == ACTION_MASK:
            new_value, reason = _mask_value(hit.value, hit.rule.params)
        else:
            new_value, reason = _tokenize_value(hit.value, token_fn)
        if reason is not None:
            trace.append(_trace_entry(hit, STATUS_SKIPPED, reason))
        else:
            hit.parent[hit.key] = new_value
            trace.append(_trace_entry(hit, STATUS_APPLIED))

    # 4b. Deletions last; array elements in descending index order per array.
    deletions = [h for h in applicable if h.rule.action == ACTION_DELETE]
    array_deletions: Dict[int, List[_Hit]] = {}
    object_deletions: List[_Hit] = []
    for hit in deletions:
        if isinstance(hit.parent, list):
            array_deletions.setdefault(id(hit.parent), []).append(hit)
        else:
            object_deletions.append(hit)
    for group in array_deletions.values():
        for hit in sorted(group, key=lambda h: h.key, reverse=True):
            del hit.parent[hit.key]
            trace.append(_trace_entry(hit, STATUS_APPLIED))
    for hit in object_deletions:
        hit.parent.pop(hit.key, None)
        trace.append(_trace_entry(hit, STATUS_APPLIED))

    for hit in shadowed:
        trace.append(_trace_entry(hit, STATUS_SHADOWED))
    for hit, reason in skipped:
        trace.append(_trace_entry(hit, STATUS_SKIPPED, reason))

    matched_rules = {h.rule_idx for h in hits}
    for idx, rule in enumerate(rules):
        if idx not in matched_rules:
            trace.append(
                {
                    "rule_id": rule.id,
                    "rule_index": idx,
                    "path": None,
                    "action": rule.action,
                    "status": STATUS_NO_MATCH,
                }
            )

    trace.sort(key=lambda e: (e["rule_index"], e["path"] or ""))
    return result, trace
