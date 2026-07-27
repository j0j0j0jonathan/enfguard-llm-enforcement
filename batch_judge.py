"""Pre-evaluate judge predicates before EnfGuard asks for them.

The selection logic is *strategy-driven* so the bench harness can sweep
the matrix of "which judge calls do we run early" × "how do we dispatch
them upstream" × "which model" while keeping the rest of the proxy
unchanged.

Strategies (selected via ``runtime.judge_strategy``):

* ``off`` — no pre-evaluation. EnfGuard's subprocess calls each predicate
  sequentially as it needs it. Correctness baseline.
* ``all_firing`` — every declared judge predicate × every input source
  it could read in this phase. No policy / switch filtering. Greedy
  upper bound on pre-batching benefit.
* ``active_policy`` — only judges referenced by at least one active
  policy. Uses the persisted ``predicate_policies`` index.
* ``guard_aware`` — ``active_policy`` plus skip judges whose only owning
  clauses include a ``SwitchBool(t, "name", 0|1)`` guard that the
  current switch state cannot satisfy.

Call mode (``runtime.judge_call_mode``) is orthogonal and consumed
inside ``predicates.pre_evaluate_judges``: ``batched`` (one upstream
call carrying N tasks) vs ``parallel`` (N concurrent single-task calls
via a thread pool).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any, Iterable

import predicates
from instrlib import Event

LOGGER = logging.getLogger(__name__)

_EVENT_ARG_INDEX: dict[str, dict[str, int]] = {
    "SessionStart": {"sid": 0},
    "Turn": {"tid": 0, "sid": 1},
    "UserMessage": {"tid": 0, "content": 1, "token_count": 2},
    "AssistantHistory": {"tid": 0, "content": 1, "token_count": 2},
    "SystemPrompt": {"tid": 0, "content": 1, "token_count": 2},
    "ModelSelection": {"tid": 0, "provider": 1, "model": 2},
    "StreamConfig": {"tid": 0, "enabled": 1},
    "CompletionObserved": {"tid": 0, "content": 1, "token_count": 2},
    "CompletionReleased": {"tid": 0, "content": 1, "token_count": 2},
    "TokenUsage": {"tid": 0, "prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3},
    # Tool-plan / tool-call input (the proposed command/args), so judges that
    # classify the agent's action can be pre-warmed in the tool phase.
    "ToolPlanned": {"tid": 0, "call_id": 1, "tool": 2, "input": 3},
    "ToolCall": {"tid": 0, "call_id": 1, "tool": 2, "input": 3},
}

_DEFAULT_INPUTS: tuple[dict[str, str], ...] = (
    {"source": "UserMessage", "arg": "content"},
    {"source": "CompletionObserved", "arg": "content"},
)
_JUDGE_ALLOWED_INPUTS: frozenset[tuple[str, str]] = frozenset(
    {
        ("UserMessage", "content"),
        ("CompletionObserved", "content"),
        ("ToolPlanned", "input"),
        ("ToolCall", "input"),
    }
)

# Matches the simple guard shape we recognise without a real MFOTL parser:
#   SettingBool(t, "name", 0)   or   SettingBool(t, "name", 1)
# (Also accepts the legacy v3 name SwitchBool for older policy files.)
_GUARD_RE = re.compile(
    r"(?:Setting|Switch)Bool\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*,\s*\"([^\"]+)\"\s*,\s*([01])\s*\)"
)


@dataclass(frozen=True)
class PreEvaluation:
    """One predicate result pre-computed for an event argument."""

    event_name: str
    predicate: str
    arg_sources: tuple[str, ...]
    content_preview: str
    raw_score: float
    cache_hit: bool


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def pre_evaluate(
    events: list[Event],
    calls: Any | None = None,
) -> list[PreEvaluation]:
    """Pre-compute supported judge calls according to the active strategy.

    The ``calls`` argument is retained for backward compatibility with the
    proxy plumbing and is currently ignored by every strategy except
    ``active_policy``-with-static-narrowing (kept for tests). Strategies
    select tasks from the persisted state plus the events of this phase.
    """

    strategy_id, call_mode = _runtime_options()
    selector = _SELECTORS.get(strategy_id, _select_active_policy)
    planned = selector(events, calls)
    if not planned:
        return []

    judge_results = predicates.pre_evaluate_judges(
        [task for *_, task in planned],
        call_mode=call_mode,
    )
    results: list[PreEvaluation] = []
    for (arg_sources, content, task), result in zip(planned, judge_results, strict=True):
        predicates.trace_pre_evaluation(
            task.predicate_name,
            content,
            result,
            {
                "arg_sources": list(arg_sources),
                "judge_strategy": strategy_id,
                "judge_call_mode": call_mode,
            },
        )
        # ``event_name`` is the first source for back-compat. For multi-arg
        # predicates, ``arg_sources`` carries the full list.
        first_source, _, _ = (arg_sources[0] if arg_sources else "").partition(".")
        results.append(
            PreEvaluation(
                event_name=first_source,
                predicate=task.predicate_name,
                arg_sources=tuple(arg_sources),
                content_preview=content[:80],
                raw_score=result.raw_score,
                cache_hit=result.cache_hit,
            )
        )
    return results


# ---------------------------------------------------------------------------
# Strategy implementations
# ---------------------------------------------------------------------------


PlannedTask = tuple[tuple[str, ...], str, predicates.JudgeBatchTask]
"""``(arg_sources, content, task)`` — arg_sources carries one entry per
predicate argument, formatted ``"EventName.arg"``. Single-arg predicates
have a one-element tuple; multi-arg predicates carry one entry per
declared YAML input."""


def _select_off(
    events: list[Event],
    calls: Any | None,
) -> list[PlannedTask]:
    """``off`` — no pre-evaluation; EnfGuard's subprocess does the work."""

    return []


def _select_all_firing(
    events: list[Event],
    calls: Any | None,
) -> list[PlannedTask]:
    """``all_firing`` — every judge × every input source, no filtering."""

    return _build_tasks(events, _all_judge_inputs(filter_active=False))


def _select_active_policy(
    events: list[Event],
    calls: Any | None,
) -> list[PlannedTask]:
    """``active_policy`` — only judges referenced by an active policy.

    When the proxy passes a static-analysis ``calls`` map, we narrow
    further: a (predicate, source, arg) triple is kept only if static
    analysis also recognised it. This preserves the prior behaviour for
    tests that exercise the legacy plumbing.
    """

    pairs = _all_judge_inputs(filter_active=True)
    static_allowed = _static_allowed_inputs(calls)
    if static_allowed is not None:
        pairs = [
            (name, ref)
            for name, ref in pairs
            if (name, ref["source"], ref["arg"]) in static_allowed
        ]
    return _build_tasks(events, pairs)


def _select_guard_aware(
    events: list[Event],
    calls: Any | None,
) -> list[PlannedTask]:
    """``guard_aware`` — ``active_policy`` minus unsatisfied switch guards."""

    pairs = _all_judge_inputs(filter_active=True)
    switch_state_map = _switch_bool_state()
    predicate_to_clauses = _predicate_clauses_for_active_policies()
    survivors: list[tuple[str, dict[str, str]]] = []
    for predicate_name, ref in pairs:
        clauses = predicate_to_clauses.get(predicate_name, ())
        if not clauses:
            # Predicate isn't tied to any active policy clause we can
            # see — fall back to keeping it (matches active_policy).
            survivors.append((predicate_name, ref))
            continue
        if any(_clause_guards_satisfied(clause, switch_state_map) for clause in clauses):
            survivors.append((predicate_name, ref))
    return _build_tasks(events, survivors)


_SELECTORS: dict[str, Any] = {
    "off": _select_off,
    "all_firing": _select_all_firing,
    "active_policy": _select_active_policy,
    "guard_aware": _select_guard_aware,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _runtime_options() -> tuple[str, str]:
    runtime = predicates._state().get("runtime")
    if not isinstance(runtime, dict):
        return ("active_policy", "batched")
    strategy = str(runtime.get("judge_strategy", "active_policy") or "active_policy").lower()
    call_mode = str(runtime.get("judge_call_mode", "batched") or "batched").lower()
    return strategy, call_mode


def _build_tasks(
    events: list[Event],
    pairs: Iterable[tuple[str, dict[str, str]]],
) -> list[PlannedTask]:
    """Materialise the list of pre-eval tasks from `(predicate, input_source)` pairs.

    Pairs come in flat from the strategy selectors. We group them back
    by predicate so a predicate with N declared ``inputs`` becomes ONE
    task carrying all N argument values, formatted exactly the same
    way the runtime path's ``_format_predicate_args`` produces — that
    way the cache key the proxy-side pre-eval writes lines up with the
    one EnfGuard's subprocess looks up later.

    For multi-arg predicates the policy is "first event of each
    declared source". If any source has no event in this phase we skip
    the predicate (we can't materialise a partial argument list). True
    cross-products (e.g. every UserMessage × every AssistantHistory) are
    not yet supported — most real predicates take "the latest" of each
    source, which the first-of-each rule covers.
    """

    inputs_by_predicate: dict[str, list[dict[str, str]]] = {}
    for predicate_name, ref in pairs:
        inputs_by_predicate.setdefault(predicate_name, []).append(ref)

    planned: list[PlannedTask] = []
    seen: set[tuple[str, str]] = set()
    event_values = _event_values(events)

    for predicate_name, refs in inputs_by_predicate.items():
        arg_specs = _arg_specs_for(predicate_name)
        # Dispatch on the predicate's *function signature*, not the
        # number of declared input sources. A single-arg predicate with
        # two declared sources means "try each — they're alternatives";
        # a two-arg predicate with two sources means "fill arg 0 and
        # arg 1 positionally — both required".
        if len(arg_specs) <= 1:
            for ref in refs:
                event_name = ref["source"]
                arg_name = ref["arg"]
                for content in event_values.get((event_name, arg_name), ()):
                    _emit_task(
                        predicate_name,
                        arg_specs,
                        [content],
                        (f"{event_name}.{arg_name}",),
                        planned,
                        seen,
                    )
        else:
            if len(refs) < len(arg_specs):
                LOGGER.warning(
                    "skipping multi-arg predicate %s: declared %d args but only "
                    "%d inputs in YAML",
                    predicate_name,
                    len(arg_specs),
                    len(refs),
                )
                continue
            used_refs = refs[: len(arg_specs)]
            arg_values: list[str] = []
            arg_sources: list[str] = []
            missing = False
            for ref in used_refs:
                event_name = ref["source"]
                arg_name = ref["arg"]
                values = event_values.get((event_name, arg_name), ())
                if not values:
                    missing = True
                    break
                arg_values.append(values[0])
                arg_sources.append(f"{event_name}.{arg_name}")
            if missing:
                continue
            _emit_task(
                predicate_name,
                arg_specs,
                arg_values,
                tuple(arg_sources),
                planned,
                seen,
            )
    return planned


def _emit_task(
    predicate_name: str,
    arg_specs: tuple[dict[str, str], ...],
    arg_values: list[str],
    arg_sources: tuple[str, ...],
    planned: list[PlannedTask],
    seen: set[tuple[str, str]],
) -> None:
    """Format the multi-arg content, dedupe, plan the judge call, append."""

    content = _format_arg_content(arg_specs, arg_values)
    dedupe_key = (predicate_name, content)
    if dedupe_key in seen:
        return
    seen.add(dedupe_key)
    plan = predicates.judge_plan(predicate_name, content)
    if plan is None:
        return
    system_prompt, cache_extra = plan
    planned.append(
        (
            arg_sources,
            content,
            predicates.JudgeBatchTask(
                predicate_name=predicate_name,
                system_prompt=system_prompt,
                content=content,
                cache_extra=cache_extra,
            ),
        )
    )


def _arg_specs_for(predicate_name: str) -> tuple[dict[str, str], ...]:
    """Look up the persisted arg specs for ``predicate_name``.

    Mirrors ``predicates._predicate_arg_specs`` but reads from the
    ``user_predicates`` slice of ``active_policies.json``. Returns the
    ``(content: string)`` default for predicates whose YAML omits
    ``args`` entirely so single-arg pre-eval keeps producing the same
    raw-string content the runtime path expects.
    """

    for spec in predicates._user_predicate_specs():
        if str(spec.get("name", "") or "") != predicate_name:
            continue
        args = spec.get("args")
        if not isinstance(args, list) or not args:
            return ({"name": "content", "type": "string"},)
        out: list[dict[str, str]] = []
        for item in args:
            if not isinstance(item, dict):
                continue
            out.append(
                {
                    "name": str(item.get("name", "arg") or "arg"),
                    "type": str(item.get("type", "string") or "string"),
                }
            )
        return tuple(out) or ({"name": "content", "type": "string"},)
    return ({"name": "content", "type": "string"},)


def _format_arg_content(
    arg_specs: tuple[dict[str, str], ...],
    values: list[str],
) -> str:
    """Match ``predicates._format_predicate_args`` so cache keys align.

    Single-arg → the raw value string.
    Multi-arg  → one ``"<name>: <value>"`` line per spec, joined by
                 newlines, in the order the spec declares.
    """

    if len(arg_specs) <= 1:
        return values[0] if values else ""
    lines: list[str] = []
    for index, spec in enumerate(arg_specs):
        value = values[index] if index < len(values) else ""
        lines.append(f"{spec['name']}: {value}")
    return "\n".join(lines)


def _all_judge_inputs(filter_active: bool) -> list[tuple[str, dict[str, str]]]:
    """Return all (predicate_name, input_source) pairs the strategies need.

    With ``filter_active=True`` we drop predicates whose declared owning
    policies are all disabled (the ``active_policy`` selection rule).
    With ``filter_active=False`` we keep everything (the ``all_firing``
    rule). Predicates that have no judge plan (deterministic builtins
    like ``model_blocklist``) are dropped in either case — there is
    nothing to pre-warm.
    """

    state = predicates._state()
    active = {str(item) for item in state.get("active", []) if str(item)}
    predicate_policies = state.get("predicate_policies")
    if not isinstance(predicate_policies, dict):
        predicate_policies = {}

    out: list[tuple[str, dict[str, str]]] = []
    for spec in predicates._user_predicate_specs():
        name = str(spec.get("name", "") or "")
        if not name:
            continue
        if filter_active:
            owners = predicate_policies.get(name)
            if isinstance(owners, list) and owners and not (
                {str(item) for item in owners} & active
            ):
                continue
        if predicates.judge_plan(name, "") is None:
            continue
        inputs = spec.get("inputs")
        raw_inputs = inputs if isinstance(inputs, list) and inputs else list(_DEFAULT_INPUTS)
        for item in raw_inputs:
            if not isinstance(item, dict):
                continue
            source = str(item.get("source", "") or "")
            arg = str(item.get("arg", "content") or "content")
            if not source or not arg:
                continue
            if (source, arg) not in _JUDGE_ALLOWED_INPUTS:
                LOGGER.warning(
                    "skipping llm_judge predicate %s input %s.%s: judge inputs are limited "
                    "to current UserMessage.content, CompletionObserved.content, or "
                    "ToolPlanned.input / ToolCall.input",
                    name,
                    source,
                    arg,
                )
                continue
            out.append((name, {"source": source, "arg": arg}))
    return out


def _switch_bool_state() -> dict[str, str]:
    """Return ``{switch_id: "0"|"1"}`` for every boolean switch.

    Reads from the persisted switch list in ``active_policies.json``.
    Choice/int/float switches are out of scope for guard parsing — only
    boolean guards are recognised by the regex above.
    """

    state = predicates._state()
    switches = state.get("switches")
    if not isinstance(switches, list):
        return {}
    out: dict[str, str] = {}
    for entry in switches:
        if not isinstance(entry, dict):
            continue
        kind = str(entry.get("kind", "") or "").lower()
        if kind != "boolean":
            continue
        sid = str(entry.get("id", "") or "")
        if not sid:
            continue
        # `current` is set by the runtime; YAML-loaded entries may only
        # have `default`. Either is fine for the guard check.
        raw = entry.get("current")
        if raw is None:
            raw = entry.get("default")
        normalised = "1" if str(raw).strip().lower() in {"true", "1", "yes", "on"} else "0"
        out[sid] = normalised
    return out


def _predicate_clauses_for_active_policies() -> dict[str, list[str]]:
    """Map predicate name → list of clause texts from currently-active policies.

    A predicate's clause(s) are the snippets we'll inspect for switch
    guards. We only include clauses from policies whose `enabled` flag
    is true in the runtime state — disabled policies don't contribute.
    """

    state = predicates._state()
    policies = state.get("policies")
    active = {str(item) for item in state.get("active", []) if str(item)}
    out: dict[str, list[str]] = {}
    if not isinstance(policies, list):
        return out
    for entry in policies:
        if not isinstance(entry, dict):
            continue
        pid = str(entry.get("id", "") or "")
        if pid not in active:
            continue
        mfotl = str(entry.get("mfotl", "") or "")
        if not mfotl:
            continue
        for spec in predicates._user_predicate_specs():
            name = str(spec.get("name", "") or "")
            if not name:
                continue
            if re.search(rf"\b{re.escape(name)}\s*\(", mfotl):
                out.setdefault(name, []).append(mfotl)
    return out


def _clause_guards_satisfied(clause: str, switch_state_map: dict[str, str]) -> bool:
    """Return True if every ``SwitchBool(t, name, value)`` guard in the clause matches."""

    for match in _GUARD_RE.finditer(clause):
        switch_id = match.group(1)
        required = match.group(2)
        actual = switch_state_map.get(switch_id)
        # If we don't know the current value, be conservative and keep
        # the predicate (don't drop calls based on missing state).
        if actual is None:
            continue
        if actual != required:
            return False
    return True


def _static_allowed_inputs(calls: Any | None) -> set[tuple[str, str, str]] | None:
    if not isinstance(calls, dict):
        return None
    allowed: set[tuple[str, str, str]] = set()
    for fallback_event_name, call_list in calls.items():
        if not isinstance(call_list, list):
            continue
        for call in call_list:
            predicate_name = str(getattr(call, "predicate", "") or "")
            event_name = str(getattr(call, "event_name", "") or fallback_event_name)
            for arg_source in getattr(call, "arg_sources", ()) or ():
                source, _, arg = str(arg_source).partition(".")
                if not source or not arg:
                    continue
                allowed.add((predicate_name, source, arg))
                if source != event_name:
                    allowed.add((predicate_name, event_name, arg))
    return allowed


def _event_values(events: list[Event]) -> dict[tuple[str, str], list[str]]:
    values: dict[tuple[str, str], list[str]] = {}
    for event in events:
        arg_index = _EVENT_ARG_INDEX.get(event.name, {})
        for arg_name, index in arg_index.items():
            if index >= len(event.args):
                continue
            values.setdefault((event.name, arg_name), []).append(_string_arg(event.args[index]))
    return values


def _string_arg(value: Any) -> str:
    return str(value if value is not None else "")
