"""Tests for ingest-judge call capture (instrlib/judge_capture.py) and the
tool_judge -> capture wiring (2026-06-17).

Capture is what lets a judges-on run show WHAT each gated ingest judge was asked
and WHAT it answered, so a ``no_match`` is attributable to prompt vs cache vs
model limitation (docs/handover/2026-06-16-handover.md section 7 item 3). These
tests pin: the per-tid accumulator + context manager, the no-op-without-context
gate, that ``_dispatch`` records on both success and error, and that a real
adapter call through ``map_tool_call`` is captured under the tid.

Run from code/EnfGuardV2/:

    python -m pytest tests/test_judge_capture_2026_06_17.py -q
"""

from __future__ import annotations

import instrlib.tool_judge as tj
from instrlib import judge_capture
from instrlib.tool_mapper import map_tool_call, register_unknown_tool_classifier


def test_record_noop_without_tid_context():
    # No capturing() active -> record is a silent no-op (so direct unit-test
    # calls to a judge adapter are never captured).
    judge_capture.record("unknown_tool", "sys", "in", "reply", ms=1.0)
    assert judge_capture.pop_judge_calls(999999) == []


def test_capturing_records_and_pop_clears():
    tid = 4242
    with judge_capture.capturing(tid):
        judge_capture.record("unknown_tool", "system-text", "the-input", '{"x":1}', ms=2.5)
        judge_capture.record("secret_material", "sys2", "in2", "benign", cache_hit=False, ms=0.1)
    rows = judge_capture.pop_judge_calls(tid)
    assert len(rows) == 2
    r0 = rows[0]
    assert r0["adapter"] == "unknown_tool"
    assert r0["input"] == "the-input"
    assert r0["reply"] == '{"x":1}'
    assert r0["cache_hit"] is False
    assert isinstance(r0["ms"], float)
    assert len(r0["prompt_sha8"]) == 8
    # pop clears
    assert judge_capture.pop_judge_calls(tid) == []


def test_capturing_restores_previous_tid():
    with judge_capture.capturing(1):
        with judge_capture.capturing(2):
            judge_capture.record("a", "s", "i", "r")
        judge_capture.record("b", "s", "i", "r")
    assert len(judge_capture.pop_judge_calls(2)) == 1
    assert len(judge_capture.pop_judge_calls(1)) == 1


def test_dispatch_records_real_adapter_call(monkeypatch):
    monkeypatch.setenv("ENFGUARD_TOOL_JUDGE", "1")
    monkeypatch.delenv("ENFGUARD_TOOL_JUDGE_BACKEND", raising=False)
    reply = '{"dim":"action_class","level":"persistence"}'
    monkeypatch.setattr(tj, "_call_openai", lambda *a, **k: reply)
    tid = 7
    with judge_capture.capturing(tid):
        out = tj.classify_unknown_tool("weird_tool", {"command": "do-x"})
    assert out == ("action_class", "persistence")
    rows = judge_capture.pop_judge_calls(tid)
    assert len(rows) == 1
    row = rows[0]
    assert row["adapter"] == "unknown_tool"
    assert row["reply"] == reply
    assert "weird_tool" in row["input"]
    assert row["cache_hit"] is False
    assert len(row["prompt_sha8"]) == 8
    assert "error" not in row


def test_dispatch_records_on_error(monkeypatch):
    monkeypatch.setenv("ENFGUARD_TOOL_JUDGE", "1")
    monkeypatch.delenv("ENFGUARD_TOOL_JUDGE_BACKEND", raising=False)

    def boom(*a, **k):
        raise RuntimeError("network down")

    monkeypatch.setattr(tj, "_call_openai", boom)
    tid = 8
    with judge_capture.capturing(tid):
        out = tj.classify_unknown_tool("weird_tool", {"command": "do-x"})
    assert out is None  # fail-open
    rows = judge_capture.pop_judge_calls(tid)
    assert len(rows) == 1
    assert rows[0]["reply"] == ""
    assert "network down" in rows[0].get("error", "")


def test_map_tool_call_captures_unknown_tool_judge(monkeypatch):
    # End-to-end through the mapper: an unknown tool triggers the unknown-tool
    # judge, and map_tool_call's capturing() wrapper records the call under tid.
    monkeypatch.setenv("ENFGUARD_TOOL_JUDGE", "1")
    monkeypatch.delenv("ENFGUARD_TOOL_JUDGE_BACKEND", raising=False)
    reply = '{"dim":"action_class","level":"exfiltration"}'
    monkeypatch.setattr(tj, "_call_openai", lambda *a, **k: reply)
    register_unknown_tool_classifier(tj.classify_unknown_tool)
    try:
        tid = 555
        map_tool_call(tid, "call-1", "totally_unknown_tool", {"foo": "bar"})
        rows = judge_capture.pop_judge_calls(tid)
        assert len(rows) == 1
        assert rows[0]["adapter"] == "unknown_tool"
        assert rows[0]["reply"] == reply
    finally:
        register_unknown_tool_classifier(None)


def test_uncertain_action_judge_captured(monkeypatch):
    # The uncertain-action judge (the adapter that returns no_match on the open
    # PERSIST-HARD-04 case) is captured too, with its distinct adapter label.
    monkeypatch.setenv("ENFGUARD_TOOL_JUDGE", "1")
    monkeypatch.delenv("ENFGUARD_TOOL_JUDGE_BACKEND", raising=False)
    reply = '{"dim":"no_match","level":"no_match"}'
    monkeypatch.setattr(tj, "_call_openai", lambda *a, **k: reply)
    tid = 99
    with judge_capture.capturing(tid):
        out = tj.classify_uncertain_action("bash", {"command": "weird"})
    assert out is None
    rows = judge_capture.pop_judge_calls(tid)
    assert len(rows) == 1
    assert rows[0]["adapter"] == "uncertain_action"
    assert rows[0]["reply"] == reply
