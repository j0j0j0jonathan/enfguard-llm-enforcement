"""Narrow static analysis for EnfGuard policy formulas.

This is intentionally not a general MFOTL parser. It recognises the policy
shapes we use for batching predicate calls:

* ``Event(t, c, n) AND pred(c) > 0.5``
* ``Event(t, c, n) AND n > K`` (recognised as no predicate work)
* ``Event(t, s) AND pred(s) > 0.5``

Everything else is logged and skipped. Skipping is safe because EnfGuard can
still call the predicate normally; we only lose pre-evaluation speed.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

from event_schema import EVENT_TYPES

LOGGER = logging.getLogger(__name__)

_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(([^()]*)\)")
_FUN_RE = re.compile(
    r"^\s*(?:fun\s+)?([a-z_][A-Za-z0-9_]*)\s*\((.*?)\)(?:\s*:\s*float)?\s*$"
)
_EVENT_SIG_RE = re.compile(r"^\s*([A-Z][A-Za-z0-9_]*)\s*\((.*?)\)")
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_POLICY_ACTIVE_RE = re.compile(r'PolicyActive\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*,\s*"([^"]+)"\s*\)')

_EVENT_FIELD_NAMES: dict[str, tuple[str, ...]] = {
    "SessionStart": ("sid",),
    "Turn": ("tid", "sid"),
    "UserMessage": ("tid", "content", "token_count"),
    "AssistantHistory": ("tid", "content", "token_count"),
    "SystemPrompt": ("tid", "content", "token_count"),
    "ModelSelection": ("tid", "provider", "model"),
    "StreamConfig": ("tid", "enabled"),
    "PolicyActive": ("tid", "policy_id"),
    "CompletionObserved": ("tid", "content", "token_count"),
    "CompletionReleased": ("tid", "content", "token_count"),
    "TokenUsage": ("tid", "prompt_tokens", "completion_tokens", "total_tokens"),
    "UserFeedback": ("tid", "kind", "payload"),
    "ToolCall": ("tid", "call_id", "tool", "input"),
    "ToolPlanned": ("tid", "call_id", "tool", "input"),
}
_FALLBACK_EVENT_FIELDS: dict[str, tuple[str, ...]] = {
    name: _EVENT_FIELD_NAMES[name] for name, _types in EVENT_TYPES if name in _EVENT_FIELD_NAMES
}
@dataclass(frozen=True)
class PredicateCall:
    """One predicate call that can be pre-evaluated from a single event."""

    predicate: str
    arg_sources: tuple[str, ...]
    event_name: str
    event_arg_indices: tuple[int, ...]
    variables: tuple[str, ...]


def extract_predicate_calls(
    mfotl_path: Path | str,
    sig_path: Path | None = None,
) -> dict[str, list[PredicateCall]]:
    """Return pre-evaluable predicate calls grouped by source event name."""

    path = Path(mfotl_path)
    formula = _strip_comments(path.read_text(encoding="utf-8"))
    signature_path = sig_path or _guess_signature_path(path)
    event_fields, predicate_names = _load_signature_metadata(signature_path)

    calls: dict[str, list[PredicateCall]] = {}
    seen: set[tuple[str, str, tuple[str, ...]]] = set()

    for clause in _split_always_clauses(formula):
        lhs = clause.split("IMPLIES", 1)[0]
        bindings = _collect_bindings(lhs, event_fields)
        for predicate_name, raw_args in _predicate_calls(lhs, predicate_names):
            call = _resolve_predicate_call(predicate_name, raw_args, bindings, clause)
            if call is None:
                continue
            dedupe_key = (call.event_name, call.predicate, call.arg_sources)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            calls.setdefault(call.event_name, []).append(call)

    return calls


def extract_predicate_policies(
    mfotl_path: Path | str,
    sig_path: Path | None = None,
) -> dict[str, frozenset[str]]:
    """Return ``{predicate_name: {policy_id, ...}}`` over the composite formula.

    A predicate maps to the set of policy ids whose clause references it via
    ``PolicyActive(t, "<policy_id>")``. Predicates that appear in clauses
    *without* a ``PolicyActive`` gate are mapped to an empty frozenset, which
    callers should treat as "always pre-evaluate" since there is no operator
    knob that can disable the clause.
    """

    path = Path(mfotl_path)
    formula = _strip_comments(path.read_text(encoding="utf-8"))
    signature_path = sig_path or _guess_signature_path(path)
    _, predicate_names = _load_signature_metadata(signature_path)

    index: dict[str, set[str]] = {}
    ungated: set[str] = set()
    for clause in _split_always_clauses(formula):
        lhs = clause.split("IMPLIES", 1)[0]
        policies = {match.group(1) for match in _POLICY_ACTIVE_RE.finditer(lhs)}
        for predicate_name, _ in _predicate_calls(lhs, predicate_names):
            if not policies:
                ungated.add(predicate_name)
                index.setdefault(predicate_name, set())
                continue
            index.setdefault(predicate_name, set()).update(policies)

    result: dict[str, frozenset[str]] = {}
    for name, policies in index.items():
        if name in ungated:
            result[name] = frozenset()
        else:
            result[name] = frozenset(policies)
    return result


def _load_signature_metadata(sig_path: Path | None) -> tuple[dict[str, tuple[str, ...]], set[str]]:
    if sig_path is None or not sig_path.exists():
        LOGGER.warning(
            "static analysis skipped batching: signature file is missing; "
            "falling back to EnfGuard predicate calls"
        )
        return dict(_FALLBACK_EVENT_FIELDS), set()

    event_fields: dict[str, tuple[str, ...]] = {}
    predicate_names: set[str] = set()
    for raw_line in sig_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue

        fun_match = _FUN_RE.match(line)
        if fun_match:
            predicate_names.add(fun_match.group(1))
            continue

        event_match = _EVENT_SIG_RE.match(line)
        if event_match:
            event_fields[event_match.group(1)] = _field_names(event_match.group(2))

    if not event_fields:
        event_fields = dict(_FALLBACK_EVENT_FIELDS)
    if not predicate_names:
        LOGGER.warning(
            "static analysis skipped batching: signature file %s declares no predicates; "
            "falling back to EnfGuard predicate calls",
            sig_path,
        )
        predicate_names = set()
    return event_fields, predicate_names


def _field_names(raw_args: str) -> tuple[str, ...]:
    names: list[str] = []
    for raw in _split_args(raw_args):
        name = raw.split(":", 1)[0].strip()
        if name.endswith("+") or name.endswith("-"):
            name = name[:-1]
        names.append(name or f"arg{len(names)}")
    return tuple(names)


def _split_always_clauses(formula: str) -> list[str]:
    return [part.strip() for part in re.split(r"(?=\bALWAYS\s*\()", formula) if part.strip()]


def _collect_bindings(
    lhs: str,
    event_fields: dict[str, tuple[str, ...]],
) -> dict[str, list[tuple[str, str, int]]]:
    bindings: dict[str, list[tuple[str, str, int]]] = {}
    for name, raw_args in _CALL_RE.findall(lhs):
        fields = event_fields.get(name)
        if fields is None:
            continue
        args = _split_args(raw_args)
        for index, variable in enumerate(args):
            if not _IDENT_RE.match(variable):
                continue
            field = fields[index] if index < len(fields) else f"arg{index}"
            bindings.setdefault(variable, []).append((name, field, index))
    return bindings


def _predicate_calls(lhs: str, predicate_names: set[str]) -> list[tuple[str, list[str]]]:
    calls: list[tuple[str, list[str]]] = []
    for name, raw_args in _CALL_RE.findall(lhs):
        if name in predicate_names:
            calls.append((name, _split_args(raw_args)))
    return calls


def _resolve_predicate_call(
    predicate_name: str,
    args: list[str],
    bindings: dict[str, list[tuple[str, str, int]]],
    clause: str,
) -> PredicateCall | None:
    if len(args) != 1:
        _warn_skip(predicate_name, "only single-argument predicate calls are batched", clause)
        return None

    variable = args[0]
    if not _IDENT_RE.match(variable):
        _warn_skip(predicate_name, f"argument {variable!r} is not an event-bound variable", clause)
        return None

    sources = _unique_bindings(bindings.get(variable, []))
    if len(sources) != 1:
        _warn_skip(
            predicate_name,
            f"variable {variable!r} has {len(sources)} possible event bindings",
            clause,
        )
        return None

    event_name, field_name, index = sources[0]
    return PredicateCall(
        predicate=predicate_name,
        arg_sources=(f"{event_name}.{field_name}",),
        event_name=event_name,
        event_arg_indices=(index,),
        variables=(variable,),
    )


def _unique_bindings(bindings: list[tuple[str, str, int]]) -> list[tuple[str, str, int]]:
    unique: list[tuple[str, str, int]] = []
    seen: set[tuple[str, str, int]] = set()
    for binding in bindings:
        if binding in seen:
            continue
        seen.add(binding)
        unique.append(binding)
    return unique


def _split_args(raw_args: str) -> list[str]:
    return [arg.strip() for arg in raw_args.split(",") if arg.strip()]


def _strip_comments(text: str) -> str:
    return re.sub(r"\(\*.*?\*\)", "", text, flags=re.DOTALL)


def _guess_signature_path(mfotl_path: Path) -> Path | None:
    candidates = [
        mfotl_path.with_suffix(".sig"),
        mfotl_path.with_name(mfotl_path.name.replace(".mfotl", ".sig")),
        mfotl_path.parent / "enfguard_composite.sig",
        mfotl_path.parent / "enfguard_user.sig",
        mfotl_path.parent.parent / "enfguard_user.sig",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _warn_skip(predicate_name: str, reason: str, clause: str) -> None:
    preview = " ".join(clause.split())[:180]
    LOGGER.warning(
        "static analysis skipped predicate %s: %s; falling back to EnfGuard predicate call. Clause: %s",
        predicate_name,
        reason,
        preview,
    )
