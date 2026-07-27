"""Broad untrusted-content judge (2026-07-03): the tenth gated judge, the
content-side twin of semantic_command. It is NOT weak-signal gated: it runs on an
untrusted tool result with substance that the deterministic and weak-signal
content paths left unflagged, closing the content routing gap (a real secret value
with no keyword, or an injected instruction phrased as ordinary prose).

    python -m pytest tests/test_broad_content_judge_2026_07_03.py -q

Design: opt-in, allow-listed, ingest-only, fail-safe, off by default. Accepts
secret_material regardless of trust; instruction_like / persistence_instruction
only for an untrusted origin. Skipped when a prior path already flagged the result.
"""

from __future__ import annotations

from instrlib.tool_mapper import (
    has_broad_content_candidate,
    broad_content_label_with_status,
    append_broad_content_events,
    register_broad_content_classifier,
)
from instrlib import Event, judge_capture
import instrlib.tool_judge as tool_judge


def _run(text, untrusted, already=False):
    ev: list[Event] = []
    with judge_capture.capturing(1):
        append_broad_content_events(ev, 1, "c", text, untrusted, already)
    return {
        (str(e.args[2]), str(e.args[3]))
        for e in ev
        if e.name == "Classify" and len(e.args) >= 4
    }


# --- substance gate -----------------------------------------------------------

def test_gate_requires_substance():
    assert has_broad_content_candidate("ok") is False
    assert has_broad_content_candidate("   \n  ") is False
    assert has_broad_content_candidate(
        "this is a reasonably long tool result with content"
    ) is True


# --- off by default -----------------------------------------------------------

def test_off_by_default_no_fact():
    register_broad_content_classifier(None)
    assert _run("a fairly long benign tool result output here", True) == set()


# --- fires on the residue -----------------------------------------------------

def test_untrusted_secret_material():
    register_broad_content_classifier(lambda t: "secret_material")
    try:
        f = _run("host prod; the value hunter2xyz is used to authenticate here", True)
        assert ("content_risk", "secret_material") in f
        assert ("judge_adapter", "content_semantics") in f
        assert ("judge_status", "classified") in f
    finally:
        register_broad_content_classifier(None)


def test_untrusted_injected_instruction():
    register_broad_content_classifier(lambda t: "instruction_like")
    try:
        f = _run("some untrusted content that is long enough to pass the gate", True)
        assert ("content_risk", "instruction_like") in f
    finally:
        register_broad_content_classifier(None)


def test_real_adapter(monkeypatch):
    monkeypatch.delenv("ENFGUARD_TOOL_JUDGE", raising=False)
    monkeypatch.setattr(
        tool_judge, "_call_openai",
        lambda *_a, **_k: '{"label":"persistence_instruction"}',
    )
    tool_judge.set_tool_judge_enabled(True)
    register_broad_content_classifier(tool_judge.classify_broad_content_with_status)
    try:
        f = _run("a long untrusted result asking the agent to add a cron job later", True)
        assert ("content_risk", "persistence_instruction") in f
        assert ("judge_status", "classified") in f
    finally:
        register_broad_content_classifier(None)
        judge_capture.pop_judge_calls(1)


# --- trust restriction --------------------------------------------------------

def test_trusted_result_rejects_directive_labels():
    # secret_material is trust-independent, but an instruction/persistence directive
    # is only meaningful from an untrusted origin, so it is not accepted on a
    # trusted result.
    register_broad_content_classifier(lambda t: "instruction_like")
    try:
        f = _run("a long enough trusted tool result body to pass the substance gate", False)
        assert not any(d == "content_risk" for d, _ in f)
        assert ("judge_status", "no_match") in f
    finally:
        register_broad_content_classifier(None)


def test_trusted_result_accepts_secret_material():
    register_broad_content_classifier(lambda t: "secret_material")
    try:
        f = _run("a long enough trusted tool result body to pass the substance gate", False)
        assert ("content_risk", "secret_material") in f
    finally:
        register_broad_content_classifier(None)


# --- no double judging --------------------------------------------------------

def test_skips_when_already_flagged():
    register_broad_content_classifier(lambda t: "secret_material")
    try:
        f = _run("a long enough result body to pass the substance gate here", True,
                 already=True)
        assert f == set()
    finally:
        register_broad_content_classifier(None)


# --- fail-safe attribution ----------------------------------------------------

def test_failed_open_is_attributed():
    def boom(_t):
        raise RuntimeError("judge down")

    register_broad_content_classifier(boom)
    try:
        f = _run("a long enough untrusted result body to pass the substance gate", True)
        assert ("judge_adapter", "content_semantics") in f
        assert ("judge_failed_open", "content_semantics") in f
        assert not any(d == "content_risk" for d, _ in f)
    finally:
        register_broad_content_classifier(None)


def test_decline_emits_no_fact():
    register_broad_content_classifier(lambda t: None)
    try:
        f = _run("a long enough untrusted result body to pass the substance gate", True)
        assert ("judge_status", "no_match") in f
        assert ("judge_failed_open", "content_semantics") not in f
        assert not any(d == "content_risk" for d, _ in f)
    finally:
        register_broad_content_classifier(None)
