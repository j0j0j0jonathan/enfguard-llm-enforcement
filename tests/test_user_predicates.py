import json

import predicates


def test_user_python_predicate_wrapper_calls_custom_function(tmp_path, monkeypatch):
    custom = tmp_path / "custom_predicates.py"
    custom.write_text(
        "def has_magic_word(content):\n"
        "    return 1.0 if 'magic' in content else 0.0\n",
        encoding="utf-8",
    )
    trace_index_dir = tmp_path / "traces"
    monkeypatch.setattr(predicates, "TRACE_INDEX_DIR", trace_index_dir)
    monkeypatch.setattr(predicates, "_TRACE_DEDUPE_SEEN", set())
    monkeypatch.setattr(predicates, "_TRACE_DEDUPE_ORDER", [])
    monkeypatch.setattr(
        predicates,
        "_current_context",
        lambda: {"tid": 42, "sid": "s-test", "phase": "inbound", "dry_run": 0},
    )

    wrapper = predicates._make_user_python_predicate(
        {
            "name": "has_magic_word",
            "kind": "python",
            "path": str(custom),
            "args": [{"name": "content", "type": "string"}],
        }
    )

    assert wrapper("magic phrase") == 1.0
    row = json.loads((trace_index_dir / "tid_42.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert row["predicate"] == "has_magic_word"
    assert row["score"] == 1.0
    assert row["user_predicate_kind"] == "python"


def test_predicate_short_circuits_when_all_owning_policies_are_inactive(tmp_path, monkeypatch):
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    active_state = state_dir / "active_policies.json"
    active_state.write_text(
        '{"active": [], "predicate_policies": {"custom": ["custom_policy"]}}\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        predicates,
        "_STATE_CACHE",
        predicates._MtimeCache(active_state, {}, predicates._load_json),
    )
    monkeypatch.setattr(predicates, "_trace_emit", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("inactive predicate should not trace")))

    result = predicates._score(
        "custom",
        "content",
        predicates.JudgeResult(raw_score=1.0, reason="matched", reasons=("matched",)),
    )

    assert result == 0.0


def test_user_llm_predicate_wrapper_uses_declared_system_prompt(monkeypatch):
    calls = []

    def fake_judge(name, system_prompt, content, cache_extra=()):
        calls.append((name, system_prompt, content, cache_extra))
        return predicates.JudgeResult(raw_score=1.0, reason="matched", reasons=("matched",))

    monkeypatch.setattr(predicates, "_judge", fake_judge)
    monkeypatch.setattr(predicates, "_score", lambda name, content, result, extra=None: result.raw_score)

    wrapper = predicates._make_user_llm_judge(
        {
            "name": "contains_pii",
            "kind": "llm_judge",
            "system_prompt": "classify pii",
            "args": [{"name": "content", "type": "string"}],
        }
    )

    assert wrapper("my phone is 123") == 1.0
    assert calls[0][0] == "contains_pii"
    assert calls[0][1] == "classify pii"
    assert calls[0][2] == "my phone is 123"
