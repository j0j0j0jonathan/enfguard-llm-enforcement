"""Tests for ClockTick events, the wall_ms_within builtin, and EnfGuard latency."""

from __future__ import annotations

from dataclasses import replace
from queue import Queue
from threading import Event as ThreadEvent

import pytest

import predicates
import proxy
from instrlib import Event
from instrlib.enforcer import Enforcer
from instrlib.event import TimedTuple


def test_clock_tick_event_carries_wall_ms_in_milliseconds(monkeypatch):
    monkeypatch.setattr(proxy.time, "time", lambda: 1714680000.123)

    events = proxy._clock_events(7, "request")

    assert len(events) == 1
    event = events[0]
    assert event.name == "Clock"
    assert event.args[0] == 7
    assert event.args[1] == "request"
    # `time.time() * 1000 = 1714680000123`. We allow a 1ms tolerance because
    # the production code computes ms inside the helper, not from a frozen
    # value.
    assert abs(event.args[2] - 1714680000123) <= 1


def test_enforcer_logical_time_mode_preserves_tid_timestamp():
    enforcer = Enforcer("bin", "sig", "formula", time_mode="logical")

    assert enforcer._trace_timestamp(7, None) == 7
    assert Enforcer._format([Event("Turn", 7, "req-7", "s")], 7).startswith(b"@7 ")


def test_enforcer_wall_seconds_separates_trace_time_from_tid():
    ticks = iter([1_714_680_000.9, 1_714_680_000.9])
    enforcer = Enforcer(
        "bin",
        "sig",
        "formula",
        time_mode="wall_seconds",
        clock=lambda: next(ticks),
    )

    assert enforcer._trace_timestamp(7, None) == 1_714_680_000
    assert enforcer._trace_timestamp(8, None) == 1_714_680_000
    line = Enforcer._format([Event("Turn", 8, "req-8", "s")], 1_714_680_000)
    assert line.startswith(b"@1714680000 ")
    assert b"Turn(8," in line


def test_enforcer_wall_seconds_never_moves_backwards():
    ticks = iter([2_000.9, 1_999.1, 2_001.0])
    enforcer = Enforcer(
        "bin",
        "sig",
        "formula",
        time_mode="wall_seconds",
        clock=lambda: next(ticks),
    )

    assert [enforcer._trace_timestamp(tid, None) for tid in (1, 2, 3)] == [
        2_000,
        2_000,
        2_001,
    ]


def test_timed_out_waiter_is_removed_from_response_queue():
    enforcer = Enforcer("bin", "sig", "formula")
    stale_flag = ThreadEvent()
    current_flag = ThreadEvent()
    enforcer._read_queue.put(
        TimedTuple(8, (stale_flag, Queue(), b"@8 stale;", 8, False))
    )
    enforcer._read_queue.put(
        TimedTuple(9, (current_flag, Queue(), b"@9 current;", 9, False))
    )

    assert enforcer._remove_pending_waiter(stale_flag) is True
    assert enforcer._read_queue.qsize() == 1
    assert enforcer._read_queue.get_nowait().event_tuple[0] is current_flag
    assert enforcer._remove_pending_waiter(stale_flag) is False


def test_metric_formula_enables_wall_seconds_heartbeat(tmp_path):
    formula = tmp_path / "metric.mfotl"
    formula.write_text("ALWAYS (ONCE [0, 120] P())\n", encoding="utf-8")

    enforcer = Enforcer(
        "bin",
        "sig",
        str(formula),
        time_mode="wall_seconds",
    )

    assert enforcer._heartbeat_enabled() is True


def test_plain_past_formula_does_not_enable_heartbeat(tmp_path):
    formula = tmp_path / "plain.mfotl"
    formula.write_text("ALWAYS (ONCE P())\n", encoding="utf-8")

    enforcer = Enforcer(
        "bin",
        "sig",
        str(formula),
        time_mode="wall_seconds",
    )

    assert enforcer._heartbeat_enabled() is False


def test_wall_ms_within_returns_one_when_inside_threshold():
    assert predicates.wall_ms_within(1_000_000, 999_500, 1_000) == 1.0


def test_wall_ms_within_returns_zero_when_outside_threshold():
    assert predicates.wall_ms_within(1_000_000, 998_000, 1_000) == 0.0


def test_wall_ms_within_clamps_negative_difference_to_zero():
    # then_ms in the future. Difference < 0 → clamped to 0 → within threshold.
    assert predicates.wall_ms_within(1_000_000, 1_000_500, 100) == 1.0


def test_wall_ms_within_returns_zero_for_non_numeric_inputs():
    assert predicates.wall_ms_within("nope", 0, 100) == 0.0
    assert predicates.wall_ms_within(0, 0, "nope") == 0.0


def test_wall_ms_within_is_a_known_builtin():
    """The YAML loader must accept ``kind: builtin`` for wall_ms_within."""

    from yaml_loader import _BUILTIN_PREDICATE_NAMES

    assert "wall_ms_within" in _BUILTIN_PREDICATE_NAMES


def test_wall_ms_within_default_args_are_three_ints(tmp_path):
    """When the user declares ``kind: builtin`` for wall_ms_within without
    an explicit ``args`` list, the loader must synthesize the correct
    three-arg signature so the generated `.sig` is valid."""

    from config import CONFIG
    from yaml_loader import load

    state_dir = tmp_path / "state"
    logs_dir = tmp_path / "logs"
    builtin = tmp_path / "builtin.mfotl"
    builtin_sig = tmp_path / "builtin.sig"
    builtin.write_text("ALWAYS TRUE\n", encoding="utf-8")
    builtin_sig.write_text(
        "PolicyActive(tid:int, policy_id:string)\n"
        "Turn(tid:int, sid:string)\n"
        "Clock(tid:int, phase:string, ms:int)\n"
        "Block(tid:int, phase:string, category:string, reason:string)+\n",
        encoding="utf-8",
    )
    runtime = replace(
        CONFIG,
        base_dir=tmp_path,
        state_dir=state_dir,
        logs_dir=logs_dir,
        yaml_file=tmp_path / "enfguard.yaml",
        signature_file=builtin_sig,
        composite_signature_file=state_dir / "enfguard_composite.sig",
        default_policy_file=builtin,
        composite_policy_file=state_dir / "enfguard_composite.mfotl",
        current_context_file=state_dir / "current_context.json",
        trace_log_file=logs_dir / "trace.log",
        trace_store_file=logs_dir / "trace_store.jsonl",
        sessions_dir=state_dir / "sessions",
    )
    runtime.yaml_file.write_text(
        """
predicates:
  - name: wall_ms_within
    kind: builtin
""".strip()
        + "\n",
        encoding="utf-8",
    )

    loaded = load(runtime.yaml_file, runtime)
    spec = next(s for s in loaded.predicates if s.name == "wall_ms_within")
    assert tuple(arg.name for arg in spec.args) == ("now_ms", "then_ms", "threshold_ms")
    assert tuple(arg.type for arg in spec.args) == ("int", "int", "int")

    sig_text = loaded.merged_sig_path.read_text(encoding="utf-8")
    assert "fun wall_ms_within(now_ms:int, then_ms:int, threshold_ms:int) : float" in sig_text


@pytest.mark.anyio
async def test_phase1_returns_enfguard_ms(monkeypatch):
    """The new third return value should be a non-negative int."""

    class FakeLogger:
        def log(self, events, tid):
            return False, False, {}, {}

    monkeypatch.setattr(proxy, "pre_evaluate", lambda *a, **kw: None)
    monkeypatch.setattr(proxy, "write_current_context", lambda **kw: None)
    monkeypatch.setattr(proxy, "_logger", lambda: FakeLogger())
    monkeypatch.setattr(proxy, "_dry_run_enabled", lambda: False)
    monkeypatch.setattr(proxy, "_aggressive_batching_enabled", lambda: False)
    monkeypatch.setattr(proxy, "_read_trace_reasons", lambda *args: {})
    monkeypatch.setattr(proxy.state, "predicate_calls", {"UserMessage": []})
    monkeypatch.setattr(proxy.state, "predicate_policies", {})

    cau, reasons, enfguard_ms = await proxy._phase1_enforce(
        99,
        "s",
        [Event("UserMessage", 99, "hello", 1)],
    )

    assert cau == {}
    assert reasons == {}
    assert isinstance(enfguard_ms, int)
    assert enfguard_ms >= 0


def test_session_record_carries_per_phase_enfguard_ms():
    record = proxy._session_record(
        tid=11,
        provider="openai",
        action="allowed",
        inbound_events=[Event("UserMessage", 11, "hi", 1)],
        outbound_events=[Event("CompletionObserved", 11, "hi back", 2)],
        verdict_events=[Event("RequestAllowed", 11)],
        enfguard_ms_in=12,
        enfguard_ms_out=7,
        upstream_ms=321,
    )
    assert record["enfguard_ms"] == {"inbound": 12, "outbound": 7}
    assert record["upstream_ms"] == 321


def test_summarise_phases_splits_judge_and_enfguard_time():
    rows = [
        {"phase": "inbound", "predicate": "p", "score": 1.0, "raw_score": 0.9, "reason": "x", "latency_ms": 200},
        {"phase": "outbound", "predicate": "q", "score": 0.0, "raw_score": 0.1, "reason": "", "latency_ms": 50},
    ]
    session_records = [
        {
            "action": "allowed",
            "verdicts": [],
            "enfguard_ms": {"inbound": 30, "outbound": 5},
            "upstream_ms": 400,
        },
    ]
    summary = proxy._summarise_phases(rows, session_records)
    inbound = next(p for p in summary if p["phase"] == "inbound")
    outbound = next(p for p in summary if p["phase"] == "outbound")
    assert inbound["judge_ms"] == 200
    assert inbound["enfguard_ms"] == 30
    assert inbound["wall_ms"] == 230
    assert outbound["judge_ms"] == 50
    assert outbound["enfguard_ms"] == 5
    assert outbound["upstream_ms"] == 400
    assert outbound["wall_ms"] == 455


def test_summarise_phases_counts_shared_batch_latency_once():
    rows = [
        {
            "phase": "outbound",
            "predicate": "a",
            "score": 0.0,
            "raw_score": 0.0,
            "reason": "",
            "latency_ms": 2500,
            "batch_id": "batch-1",
        },
        {
            "phase": "outbound",
            "predicate": "b",
            "score": 0.0,
            "raw_score": 0.0,
            "reason": "",
            "latency_ms": 2500,
            "batch_id": "batch-1",
        },
        {
            "phase": "outbound",
            "predicate": "c",
            "score": 0.0,
            "raw_score": 0.0,
            "reason": "",
            "latency_ms": 100,
            "batch_id": "",
        },
    ]

    summary = proxy._summarise_phases(rows, [{"action": "allowed"}])
    outbound = next(p for p in summary if p["phase"] == "outbound")

    assert outbound["judge_row_ms"] == 5100
    assert outbound["judge_ms"] == 2600
    assert outbound["wall_ms"] == 2600
