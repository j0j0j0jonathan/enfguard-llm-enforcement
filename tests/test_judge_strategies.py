"""Unit tests for the judge-batching strategy selectors and call modes.

Each strategy is exercised on a fixed in-memory state with two LLM-judge
predicates, and we observe which tasks the selector emits. The actual
upstream calls are stubbed out so the tests run offline.
"""

from __future__ import annotations

import time

import batch_judge
import predicates
from instrlib import Event


def _state(strategy: str, *, call_mode: str = "batched", switches=None, policies=None):
    """Return a runtime state dict shaped like ``active_policies.json``."""

    return {
        "active": ["allow_emojis_policy", "private_info_policy"],
        "predicate_policies": {
            "emojis_in_output": ["allow_emojis_policy"],
            "private_info": ["private_info_policy"],
        },
        "user_predicates": [
            {
                "name": "emojis_in_output",
                "kind": "llm_judge",
                "system_prompt": "score emojis",
                "inputs": [{"source": "CompletionObserved", "arg": "content"}],
            },
            {
                "name": "private_info",
                "kind": "llm_judge",
                "system_prompt": "score pii",
                "inputs": [{"source": "UserMessage", "arg": "content"}],
            },
        ],
        "switches": switches or [],
        "policies": policies
        or [
            {
                "id": "allow_emojis_policy",
                "enabled": True,
                "mfotl": (
                    "ALWAYS (FORALL t, c, n. "
                    "(PolicyActive(t, \"allow_emojis_policy\") "
                    "AND Completion(t, c, n) "
                    "AND SettingBool(t, \"allow_emojis\", 0) "
                    "AND emojis_in_output(c) > 0.5) "
                    "IMPLIES Block(t, \"response\", \"style\", \"emoji\"))"
                ),
            },
            {
                "id": "private_info_policy",
                "enabled": True,
                "mfotl": (
                    "ALWAYS (FORALL t, c, n. "
                    "(PolicyActive(t, \"private_info_policy\") "
                    "AND Message(t, \"user\", c, n) "
                    "AND private_info(c) > 0.5) "
                    "IMPLIES Warn(t, \"request\", \"privacy\", \"pii\"))"
                ),
            },
        ],
        "runtime": {
            "judge_strategy": strategy,
            "judge_call_mode": call_mode,
        },
    }


def _patch_state(monkeypatch, state):
    monkeypatch.setattr(predicates, "_state", lambda: state)
    monkeypatch.setattr(predicates, "_user_predicate_specs", lambda: state["user_predicates"])


def _patch_judges(monkeypatch, batches):
    """Stub ``judge_plan`` (always plans) and ``pre_evaluate_judges`` (records tasks)."""

    monkeypatch.setattr(
        predicates,
        "judge_plan",
        lambda name, content: (f"system {name}", ()),
    )
    monkeypatch.setattr(predicates, "trace_pre_evaluation", lambda *a, **kw: None)

    def fake_pre_eval(tasks, *, call_mode="batched"):
        batches.append(
            {
                "call_mode": call_mode,
                "tasks": tuple((t.predicate_name, t.content) for t in tasks),
            }
        )
        return [predicates.JudgeResult(raw_score=0.0, reason="ok", reasons=("ok",)) for _ in tasks]

    monkeypatch.setattr(predicates, "pre_evaluate_judges", fake_pre_eval)


# ---------------------------------------------------------------------------
# Strategy: off
# ---------------------------------------------------------------------------


def test_strategy_off_returns_no_pre_evaluations(monkeypatch):
    batches = []
    _patch_state(monkeypatch, _state("off"))
    _patch_judges(monkeypatch, batches)

    results = batch_judge.pre_evaluate(
        [Event("UserMessage", 1, "hello", 1), Event("CompletionObserved", 1, "hi", 1)]
    )

    assert results == []
    assert batches == []  # no upstream call at all


# ---------------------------------------------------------------------------
# Strategy: all_firing
# ---------------------------------------------------------------------------


def test_strategy_all_firing_evaluates_every_input_source_present(monkeypatch):
    batches = []
    state = _state("all_firing")
    # Add a third predicate that's NOT in any active policy. all_firing should
    # still pre-evaluate it because it's declared.
    state["user_predicates"].append(
        {
            "name": "religion_classifier",
            "kind": "llm_judge",
            "system_prompt": "score religion",
            "inputs": [{"source": "UserMessage", "arg": "content"}],
        }
    )
    _patch_state(monkeypatch, state)
    _patch_judges(monkeypatch, batches)

    batch_judge.pre_evaluate(
        [Event("UserMessage", 1, "hello", 1), Event("CompletionObserved", 1, "hi", 1)]
    )

    fired = batches[0]["tasks"]
    names = {name for name, _ in fired}
    assert names == {"emojis_in_output", "private_info", "religion_classifier"}


# ---------------------------------------------------------------------------
# Strategy: active_policy
# ---------------------------------------------------------------------------


def test_strategy_active_policy_skips_predicates_with_no_active_owner(monkeypatch):
    batches = []
    state = _state("active_policy")
    state["user_predicates"].append(
        {
            "name": "religion_classifier",
            "kind": "llm_judge",
            "system_prompt": "score religion",
            "inputs": [{"source": "UserMessage", "arg": "content"}],
        }
    )
    # `religion_classifier` is owned by a policy that is NOT in `active`.
    state["predicate_policies"]["religion_classifier"] = ["religion_policy"]
    _patch_state(monkeypatch, state)
    _patch_judges(monkeypatch, batches)

    batch_judge.pre_evaluate(
        [Event("UserMessage", 1, "hello", 1), Event("CompletionObserved", 1, "hi", 1)]
    )

    fired = batches[0]["tasks"]
    names = {name for name, _ in fired}
    assert names == {"emojis_in_output", "private_info"}


# ---------------------------------------------------------------------------
# Strategy: guard_aware
# ---------------------------------------------------------------------------


def test_strategy_guard_aware_drops_unsatisfied_switch_guard(monkeypatch):
    batches = []
    state = _state(
        "guard_aware",
        switches=[
            # `allow_emojis` is currently ON. The clause requires == 0,
            # so the emoji policy can't fire — drop the judge call.
            {"id": "allow_emojis", "kind": "boolean", "current": "true"},
        ],
    )
    _patch_state(monkeypatch, state)
    _patch_judges(monkeypatch, batches)

    batch_judge.pre_evaluate(
        [Event("UserMessage", 1, "hello", 1), Event("CompletionObserved", 1, "hi", 1)]
    )

    fired = batches[0]["tasks"]
    names = {name for name, _ in fired}
    assert names == {"private_info"}


def test_strategy_guard_aware_keeps_predicate_when_guard_matches(monkeypatch):
    batches = []
    state = _state(
        "guard_aware",
        switches=[
            {"id": "allow_emojis", "kind": "boolean", "current": "false"},
        ],
    )
    _patch_state(monkeypatch, state)
    _patch_judges(monkeypatch, batches)

    batch_judge.pre_evaluate(
        [Event("UserMessage", 1, "hello", 1), Event("CompletionObserved", 1, "hi", 1)]
    )

    fired = batches[0]["tasks"]
    names = {name for name, _ in fired}
    assert names == {"emojis_in_output", "private_info"}


# ---------------------------------------------------------------------------
# Call mode propagation
# ---------------------------------------------------------------------------


def test_call_mode_propagates_to_pre_evaluate_judges(monkeypatch):
    batches = []
    state = _state("active_policy", call_mode="parallel")
    _patch_state(monkeypatch, state)
    _patch_judges(monkeypatch, batches)

    batch_judge.pre_evaluate(
        [Event("UserMessage", 1, "hello", 1), Event("CompletionObserved", 1, "hi", 1)]
    )

    assert batches[0]["call_mode"] == "parallel"


# ---------------------------------------------------------------------------
# Parallel dispatcher actually runs concurrently
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Multi-arg predicates
# ---------------------------------------------------------------------------


def _multi_arg_state(strategy: str = "all_firing"):
    """Same shape as ``_state`` but the predicate is two-arg."""

    return {
        "active": ["respects_system_prompt_policy"],
        "predicate_policies": {
            "respects_system_prompt": ["respects_system_prompt_policy"],
        },
        "user_predicates": [
            {
                "name": "respects_system_prompt",
                "kind": "llm_judge",
                "system_prompt": "score whether completion violates request",
                "args": [
                    {"name": "request", "type": "string"},
                    {"name": "completion", "type": "string"},
                ],
                "inputs": [
                    {"source": "UserMessage", "arg": "content"},
                    {"source": "CompletionObserved", "arg": "content"},
                ],
            },
        ],
        "switches": [],
        "policies": [
            {
                "id": "respects_system_prompt_policy",
                "enabled": True,
                "mfotl": "ALWAYS (... AND respects_system_prompt(p, c) > 0.5) IMPLIES BlockResponse(...)",
            },
        ],
        "runtime": {"judge_strategy": strategy, "judge_call_mode": "batched"},
    }


def test_multi_arg_pre_eval_emits_one_task_with_named_arg_block(monkeypatch):
    batches = []
    state = _multi_arg_state("all_firing")
    _patch_state(monkeypatch, state)
    _patch_judges(monkeypatch, batches)

    batch_judge.pre_evaluate(
        [
            Event("UserMessage", 1, "Be polite.", 3),
            Event("CompletionObserved", 1, "FU", 1),
        ]
    )

    assert len(batches) == 1, batches
    tasks = batches[0]["tasks"]
    assert len(tasks) == 1, tasks
    name, content = tasks[0]
    assert name == "respects_system_prompt"
    # The content must match _format_predicate_args exactly so the cache
    # key the pre-evaluator writes lines up with the runtime path's.
    assert content == "request: Be polite.\ncompletion: FU"


def test_multi_arg_pre_eval_skips_when_a_source_has_no_event(monkeypatch):
    """If any declared input source has no event in this phase, drop the task."""

    batches = []
    state = _multi_arg_state("all_firing")
    _patch_state(monkeypatch, state)
    _patch_judges(monkeypatch, batches)

    # Only a UserMessage event — CompletionObserved is missing.
    batch_judge.pre_evaluate([Event("UserMessage", 1, "Be polite.", 3)])

    # Nothing planned because we can't materialise the second arg.
    assert batches == []


def test_multi_arg_pre_eval_warns_when_inputs_shorter_than_args(monkeypatch, caplog):
    """Misconfigured YAML (args=2 but inputs=1) is logged + skipped."""

    batches = []
    state = _multi_arg_state("all_firing")
    state["user_predicates"][0]["inputs"] = [
        {"source": "UserMessage", "arg": "content"},
    ]
    _patch_state(monkeypatch, state)
    _patch_judges(monkeypatch, batches)

    import logging

    with caplog.at_level(logging.WARNING, logger="batch_judge"):
        batch_judge.pre_evaluate(
            [
                Event("UserMessage", 1, "Be polite.", 3),
                Event("CompletionObserved", 1, "FU", 1),
            ]
        )

    assert batches == []
    assert any("multi-arg" in rec.message for rec in caplog.records)


def test_llm_judge_pre_eval_skips_history_inputs_from_stale_state(monkeypatch, caplog):
    """Stale persisted state cannot feed assistant history into judge prompts."""

    batches = []
    state = {
        "active": ["p"],
        "predicate_policies": {"history_judge": ["p"]},
        "user_predicates": [
            {
                "name": "history_judge",
                "kind": "llm_judge",
                "system_prompt": "history",
                "inputs": [
                    {"source": "AssistantHistory", "arg": "content"},
                ],
            },
        ],
        "switches": [],
        "policies": [{"id": "p", "enabled": True, "mfotl": "history_judge(c)"}],
        "runtime": {"judge_strategy": "all_firing", "judge_call_mode": "batched"},
    }
    _patch_state(monkeypatch, state)
    _patch_judges(monkeypatch, batches)

    import logging

    with caplog.at_level(logging.WARNING, logger="batch_judge"):
        results = batch_judge.pre_evaluate(
            [
                Event("UserMessage", 1, "ask", 1),
                Event("AssistantHistory", 1, "prior", 1),
            ]
        )

    assert results == []
    assert batches == []
    assert any("AssistantHistory.content" in rec.message for rec in caplog.records)


# ---------------------------------------------------------------------------
# Parallel dispatcher actually runs concurrently
# ---------------------------------------------------------------------------


def test_parallel_dispatcher_runs_judges_concurrently(monkeypatch):
    """Three sleepy single-task judges should finish faster in parallel mode."""

    monkeypatch.setattr(
        predicates,
        "_judge_config",
        lambda name: ("openai", "gpt-4o-mini", 5000),
    )
    monkeypatch.setattr(
        predicates,
        "_cached_judge_result",
        lambda key, sid: None,
    )
    monkeypatch.setattr(predicates, "_current_sid", lambda: "s-parallel")

    def slow_judge(name, system_prompt, content, cache_extra=()):
        time.sleep(0.1)  # 100ms per call
        return predicates.JudgeResult(
            raw_score=0.0,
            reason="ok",
            reasons=("ok",),
            latency_ms=100,
        )

    monkeypatch.setattr(predicates, "_judge", slow_judge)

    tasks = [
        predicates.JudgeBatchTask(predicate_name=f"p{i}", system_prompt="s", content="c", cache_extra=())
        for i in range(3)
    ]
    started = time.monotonic()
    results = predicates.pre_evaluate_judges(tasks, call_mode="parallel")
    elapsed = time.monotonic() - started

    assert len(results) == 3
    # Sequential would be ~300ms; parallel should land closer to 100ms.
    # We allow 250ms to tolerate slow CI.
    assert elapsed < 0.25, f"parallel mode took {elapsed:.3f}s, expected <0.25s"
