"""Per-judge model override (2026-07-06).

The judge model is global (``ENFGUARD_TOOL_JUDGE_MODEL``). The final external
AgentHazard run wants gpt-4o-mini for every judge except ``semantic_command``,
which recovers obfuscated/reconstructed commands better on gpt-4o (44 vs 15
percent exact recovery in the two-strength study). These tests pin the additive
``ENFGUARD_TOOL_JUDGE_MODEL_<ADAPTER>`` override: it selects a per-adapter model,
is fail-safe when unset or blank, does not affect other adapters, and the backend
caller still falls back to the global when no override is passed.

Run from code/EnfGuardV2/:

    python -m pytest tests/test_per_judge_model_2026_07_06.py -q
"""
from __future__ import annotations

import instrlib.tool_judge as tj


def test_resolve_model_unset_returns_none(monkeypatch):
    monkeypatch.delenv("ENFGUARD_TOOL_JUDGE_MODEL_SEMANTIC_COMMAND", raising=False)
    assert tj._resolve_model("semantic_command") is None


def test_resolve_model_blank_returns_none(monkeypatch):
    monkeypatch.setenv("ENFGUARD_TOOL_JUDGE_MODEL_SEMANTIC_COMMAND", "   ")
    assert tj._resolve_model("semantic_command") is None


def test_resolve_model_reads_per_adapter(monkeypatch):
    monkeypatch.setenv("ENFGUARD_TOOL_JUDGE_MODEL_SEMANTIC_COMMAND", "gpt-4o")
    assert tj._resolve_model("semantic_command") == "gpt-4o"
    # a different adapter is unaffected by the semantic_command override
    monkeypatch.delenv("ENFGUARD_TOOL_JUDGE_MODEL_UNKNOWN_TOOL", raising=False)
    assert tj._resolve_model("unknown_tool") is None


def test_dispatch_passes_override_model_for_semantic_command(monkeypatch):
    monkeypatch.setenv("ENFGUARD_TOOL_JUDGE", "1")
    monkeypatch.delenv("ENFGUARD_TOOL_JUDGE_BACKEND", raising=False)
    monkeypatch.setenv("ENFGUARD_TOOL_JUDGE_MODEL", "gpt-4o-mini")
    monkeypatch.setenv("ENFGUARD_TOOL_JUDGE_MODEL_SEMANTIC_COMMAND", "gpt-4o")
    captured = {}

    def fake_call(user_msg, timeout_s, system=None, model=None):
        captured["model"] = model
        return '{"dim":"action_class","level":"persistence"}'

    monkeypatch.setattr(tj, "_call_openai", fake_call)
    tj.classify_semantic_command("bash", {"command": "echo hi"})
    assert captured["model"] == "gpt-4o"


def test_dispatch_no_override_passes_none_for_other_adapter(monkeypatch):
    monkeypatch.setenv("ENFGUARD_TOOL_JUDGE", "1")
    monkeypatch.delenv("ENFGUARD_TOOL_JUDGE_BACKEND", raising=False)
    # semantic_command override set, but a different adapter must not inherit it
    monkeypatch.setenv("ENFGUARD_TOOL_JUDGE_MODEL_SEMANTIC_COMMAND", "gpt-4o")
    monkeypatch.delenv("ENFGUARD_TOOL_JUDGE_MODEL_UNKNOWN_TOOL", raising=False)
    captured = {}

    def fake_call(user_msg, timeout_s, system=None, model=None):
        captured["model"] = model
        return '{"dim":"action_class","level":"exfiltration"}'

    monkeypatch.setattr(tj, "_call_openai", fake_call)
    tj.classify_unknown_tool("weird_tool", {"command": "do-x"})
    assert captured["model"] is None  # falls back to the global inside _call_openai


def test_call_openai_falls_back_to_global_and_override_wins(monkeypatch):
    monkeypatch.setenv("ENFGUARD_TOOL_JUDGE_OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("ENFGUARD_TOOL_JUDGE_MODEL", "gpt-4o-mini")
    monkeypatch.delenv("ENFGUARD_TOOL_JUDGE_OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    captured = {}

    class FakeResp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"choices": [{"message": {"content": "{}"}}]}

    def fake_post(url, headers=None, json=None, timeout=None):
        captured["model"] = json["model"]
        return FakeResp()

    monkeypatch.setattr(tj.httpx, "post", fake_post)

    tj._call_openai("hi", 4.0, model=None)
    assert captured["model"] == "gpt-4o-mini"  # global fallback

    tj._call_openai("hi", 4.0, model="gpt-4o")
    assert captured["model"] == "gpt-4o"  # explicit per-judge override wins
