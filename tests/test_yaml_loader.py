import json
import subprocess
from dataclasses import replace

import pytest

from config import CONFIG
from yaml_loader import load


def _runtime(tmp_path):
    state_dir = tmp_path / "state"
    logs_dir = tmp_path / "logs"
    builtin = tmp_path / "builtin.mfotl"
    builtin_sig = tmp_path / "builtin.sig"
    builtin.write_text("ALWAYS TRUE\n", encoding="utf-8")
    builtin_sig.write_text(
        "PolicyActive(tid:int, policy_id:string)\n"
        "Message(tid:int, role:string, content:string, token_count:int)\n"
        "Block(tid:int, phase:string, category:string, reason:string)+\n",
        encoding="utf-8",
    )
    return replace(
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


def test_yaml_loader_accepts_temporal_policy(tmp_path):
    """A user-authored MFOTL clause with nested ONCE windows lands in the composite."""

    runtime = _runtime(tmp_path)
    runtime.signature_file.write_text(
        "PolicyActive(tid:int, policy_id:string)\n"
        "Turn(tid:int, sid:string)\n"
        "Message(tid:int, role:string, content:string, token_count:int)\n"
        "Block(tid:int, phase:string, category:string, reason:string)+\n",
        encoding="utf-8",
    )
    runtime.yaml_file.write_text(
        """
policies:
  - id: rate_limit_3_per_5
    enabled: true
    mfotl: |
      ALWAYS (FORALL t, s.
        (PolicyActive(t, "rate_limit_3_per_5")
         AND Turn(t, s)
         AND ONCE [1, 4] (EXISTS t1. Turn(t1, s)
                          AND PolicyActive(t1, "rate_limit_3_per_5")
                          AND ONCE [1, 3] (EXISTS t2. Turn(t2, s)
                                           AND PolicyActive(t2, "rate_limit_3_per_5"))))
        IMPLIES Block(t, \"request\", "rate_limit", "max 3 requests per 5 turns"))
""",
        encoding="utf-8",
    )

    loaded = load(runtime.yaml_file, runtime)
    composite = loaded.merged_mfotl_path.read_text(encoding="utf-8")

    assert any(p.id == "rate_limit_3_per_5" for p in loaded.policies)
    # Composite must carry the temporal operators we wrote, character-for-character.
    assert "ONCE [1, 4]" in composite
    assert "ONCE [1, 3]" in composite
    # Provenance is recorded in the sidecar map so the formula body stays
    # parser-neutral.
    mapping = json.loads((loaded.merged_mfotl_path.with_suffix(".mfotl.map.json")).read_text(encoding="utf-8"))
    assert mapping["entries"][0]["id"] == "rate_limit_3_per_5"


def test_yaml_loader_writes_state_and_composite_policy(tmp_path):
    runtime = _runtime(tmp_path)
    custom_predicate = tmp_path / "custom_predicates.py"
    custom_predicate.write_text("def is_weekday():\n    return 1.0\n", encoding="utf-8")
    runtime.yaml_file.write_text(
        """
backend:
  judge_backend: ollama
  judge_timeout_ms: 250
  judge_fail_mode: warn
model_blocklist:
  - expensive-model
feedback:
  enabled: false
thresholds:
  hard_rules: 0.7
predicates:
  - name: is_weekday
    kind: python
    path: ./custom_predicates.py
  - name: contains_pii
    kind: llm_judge
    system_prompt: classify pii
    on_fail: closed
    inputs:
      - source: Message
        arg: content
policies:
  - id: custom_policy
    enabled: true
    mfotl: |
      ALWAYS (FORALL t, c, n.
        (PolicyActive(t, "custom_policy")
         AND Message(t, \"user\", c, n)
         AND contains_pii(c) > 0.5)
        IMPLIES Block(t, \"request\", "custom", "matched"))
switches:
  - id: enforcement_mode
    kind: choice
    label: Enforcement mode
    options: [audit, warn, enforce]
    default: warn
""",
        encoding="utf-8",
    )

    loaded = load(runtime.yaml_file, runtime)
    state = json.loads((runtime.state_dir / "active_policies.json").read_text(encoding="utf-8"))

    assert loaded.backend.judge_backend == "ollama"
    assert loaded.backend.judge_timeout_ms == 250
    assert state["active"] == ["custom_policy"]
    assert len(state["policies"]) == 1
    persisted = state["policies"][0]
    assert persisted["id"] == "custom_policy"
    assert persisted["enabled"] is True
    # The MFOTL body is now persisted alongside the policy id so runtime
    # strategies (e.g. guard-aware judge selection) can inspect clauses.
    assert "PolicyActive" in persisted["mfotl"]
    # Thresholds are now strictly user-authored — no auto-coupling from
    # policy thresholds to built-in predicates.
    assert state["thresholds"] == {"hard_rules": 0.7}
    assert state["model_blocklist"] == ["expensive-model"]
    assert state["feedback"] == {"enabled": False}
    assert state["judge_fail_mode"] == "warn"
    assert state["judge_fail_modes"] == {"contains_pii": "closed"}
    assert state["user_predicates"][0]["name"] == "is_weekday"
    assert state["user_predicates"][1]["system_prompt"] == "classify pii"
    assert state["user_predicates"][1]["inputs"] == [{"source": "Message", "arg": "content"}]
    assert state["predicate_policies"] == {"contains_pii": ["custom_policy"]}
    # `features.dry_run` is gone — the enforcement_mode switch carries the state now.
    mode_switch = next(s for s in state["switches"] if s["id"] == "enforcement_mode")
    assert mode_switch["default"] == "warn"
    merged_text = loaded.merged_mfotl_path.read_text(encoding="utf-8")
    assert "user policy custom_policy from enfguard.yaml" not in merged_text
    assert 'PolicyActive(t, "custom_policy")' in merged_text
    # No auto-prepended built-in policy file: the composite is just the
    # user's snippet.
    assert "ALWAYS TRUE" not in merged_text
    sig_text = loaded.merged_sig_path.read_text(encoding="utf-8")
    assert "fun contains_pii(content:string) : float" in sig_text
    assert "fun is_weekday(content:string) : float" in sig_text


def test_yaml_loader_warns_when_judge_prompt_defines_output_format(tmp_path):
    runtime = _runtime(tmp_path)
    runtime.yaml_file.write_text(
        """
predicates:
  - name: contains_pii
    kind: llm_judge
    system_prompt: |
      Return JSON with a verdict and reasons when the text contains PII.
policies:
  - id: custom_policy
    enabled: true
    mfotl: |
      ALWAYS (FORALL t, c, n.
        (PolicyActive(t, "custom_policy")
         AND Message(t, \"user\", c, n)
         AND contains_pii(c) > 0.5)
        IMPLIES Block(t, \"request\", "custom", "matched"))
""",
        encoding="utf-8",
    )

    with pytest.warns(UserWarning, match="EnfGuard owns the judge JSON/label/reason contract"):
        load(runtime.yaml_file, runtime)


def test_yaml_loader_rejects_llm_judge_bound_to_disallowed_event(tmp_path):
    """v4: judges may only bind to Message.content or Completion.content.

    The v3 signature had separate ``UserMessage`` / ``AssistantHistory`` /
    ``SystemPrompt`` events, and the loader rejected ``AssistantHistory.content``
    explicitly. In v4 the role distinction lives on the ``Message.role`` field,
    so role-specific filtering is a policy concern. The loader still rejects
    judge inputs that point at events outside the allow-set (e.g. ``Untrusted``).
    """

    runtime = _runtime(tmp_path)
    runtime.signature_file.write_text(
        "PolicyActive(tid:int, policy_id:string)\n"
        "Message(tid:int, role:string, content:string, token_count:int)\n"
        "Untrusted(tid:int, source:string)\n"
        "Block(tid:int, phase:string, category:string, reason:string)+\n",
        encoding="utf-8",
    )
    runtime.yaml_file.write_text(
        """
predicates:
  - name: contains_pii
    kind: llm_judge
    system_prompt: classify pii
    inputs:
      - source: Untrusted
        arg: source
policies:
  - id: custom_policy
    enabled: true
    mfotl: |
      ALWAYS (FORALL t, c, n.
        (PolicyActive(t, "custom_policy")
         AND Message(t, \"user\", c, n)
         AND contains_pii(c) > 0.5)
        IMPLIES Block(t, \"request\", "custom", "matched"))
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Untrusted.source is not allowed"):
        load(runtime.yaml_file, runtime)


def test_yaml_loader_rejects_llm_judge_policy_bound_outside_allowlist(tmp_path):
    """v4: a policy that binds an LLM judge to an event outside the allow-set
    (Message.content, Completion.content) must be rejected during load."""

    runtime = _runtime(tmp_path)
    runtime.signature_file.write_text(
        "PolicyActive(tid:int, policy_id:string)\n"
        "Untrusted(tid:int, source:string)\n"
        "Block(tid:int, phase:string, category:string, reason:string)+\n",
        encoding="utf-8",
    )
    runtime.yaml_file.write_text(
        """
predicates:
  - name: contains_pii
    kind: llm_judge
    system_prompt: classify pii
policies:
  - id: custom_policy
    enabled: true
    mfotl: |
      ALWAYS (FORALL t, src.
        (PolicyActive(t, "custom_policy")
         AND Untrusted(t, src)
         AND contains_pii(src) > 0.5)
        IMPLIES Block(t, \"request\", "custom", "matched"))
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="bound to Untrusted.source"):
        load(runtime.yaml_file, runtime)


def test_yaml_loader_merges_live_policy_overlay(tmp_path):
    runtime = _runtime(tmp_path)
    runtime.state_dir.mkdir(parents=True)
    runtime.yaml_file.write_text(
        """
policies:
  - id: yaml_policy
    enabled: true
    mfotl: |
      ALWAYS (FORALL t, c, n.
        (PolicyActive(t, "yaml_policy")
         AND Message(t, \"user\", c, n)
         AND n > 100)
        IMPLIES Block(t, \"request\", "yaml", "yaml policy"))
""",
        encoding="utf-8",
    )
    (runtime.state_dir / "live_policies.json").write_text(
        json.dumps(
            {
                "policies": [
                    {
                        "id": "live_block_long_prompt",
                        "enabled": False,
                        "mfotl": (
                            'ALWAYS (FORALL t, c, n. (PolicyActive(t, "live_block_long_prompt") '
                            'AND Message(t, \"user\", c, n) AND n > 40) '
                            'IMPLIES Block(t, \"request\", "live", "live policy"))'
                        ),
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    loaded = load(runtime.yaml_file, runtime)
    state = json.loads((runtime.state_dir / "active_policies.json").read_text(encoding="utf-8"))
    composite = loaded.merged_mfotl_path.read_text(encoding="utf-8")

    assert [policy.id for policy in loaded.policies] == ["yaml_policy", "live_block_long_prompt"]
    assert state["active"] == ["yaml_policy"]
    assert state["policies"][1]["source"] == "live"
    assert 'PolicyActive(t, "live_block_long_prompt")' in composite
    # Live overlays default to scope="session" when the JSON omits the field.
    assert state["policies"][1]["scope"] == "session"
    # YAML-sourced policies are always persistent.
    assert state["policies"][0]["scope"] == "persistent"


def test_yaml_loader_loads_multiple_live_policies_with_distinct_ids(tmp_path):
    runtime = _runtime(tmp_path)
    runtime.state_dir.mkdir(parents=True)
    runtime.yaml_file.write_text("policies: []\n", encoding="utf-8")
    (runtime.state_dir / "live_policies.json").write_text(
        json.dumps(
            {
                "policies": [
                    {
                        "id": "live_policy_1",
                        "enabled": True,
                        "scope": "session",
                        "mfotl": (
                            'ALWAYS (FORALL t, c, n. (PolicyActive(t, "live_policy_1") '
                            'AND Message(t, \"user\", c, n) AND n > 5) '
                            'IMPLIES Block(t, \"request\", "live", "first"))'
                        ),
                    },
                    {
                        "id": "live_policy_2",
                        "enabled": True,
                        "scope": "persistent",
                        "mfotl": (
                            'ALWAYS (FORALL t, c, n. (PolicyActive(t, "live_policy_2") '
                            'AND Message(t, \"user\", c, n) AND n > 50) '
                            'IMPLIES Block(t, \"request\", "live", "second"))'
                        ),
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    loaded = load(runtime.yaml_file, runtime)
    state = json.loads((runtime.state_dir / "active_policies.json").read_text(encoding="utf-8"))

    assert [policy.id for policy in loaded.policies] == ["live_policy_1", "live_policy_2"]
    assert state["active"] == ["live_policy_1", "live_policy_2"]
    scopes = {entry["id"]: entry["scope"] for entry in state["policies"]}
    assert scopes == {"live_policy_1": "session", "live_policy_2": "persistent"}


def test_yaml_loader_rejects_unknown_live_policy_scope(tmp_path):
    runtime = _runtime(tmp_path)
    runtime.state_dir.mkdir(parents=True)
    runtime.yaml_file.write_text("policies: []\n", encoding="utf-8")
    (runtime.state_dir / "live_policies.json").write_text(
        json.dumps(
            {
                "policies": [
                    {
                        "id": "live_unknown_scope",
                        "enabled": True,
                        "scope": "forever",
                        "mfotl": (
                            'ALWAYS (FORALL t, c, n. (PolicyActive(t, "live_unknown_scope") '
                            'AND Message(t, \"user\", c, n)) IMPLIES Block(t, \"request\", "live", "x"))'
                        ),
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unsupported scope"):
        load(runtime.yaml_file, runtime)


def test_yaml_loader_accepts_settings_before_policies(tmp_path):
    runtime = _runtime(tmp_path)
    runtime.yaml_file.write_text(
        """
backend:
  judge_backend: ollama
feedback:
  enabled: false
runtime:
  judge_batching: aggressive
  trace_assistant_content: false
model_blocklist:
  - blocked-model
switches:
  - id: allow_output
    kind: boolean
    default: true
human_approval:
  enabled: true
  timeout_seconds: 12
  on_timeout: allow
predicates:
  - name: hard_rules
    kind: builtin
policies:
  - id: hard_safety
    enabled: true
    mfotl: |
      ALWAYS (FORALL t, c, n.
        (PolicyActive(t, "hard_safety")
         AND Message(t, \"user\", c, n)
         AND hard_rules(c) > 0.5)
        IMPLIES Block(t, \"request\", "safety", "blocked"))
""",
        encoding="utf-8",
    )

    loaded = load(runtime.yaml_file, runtime)
    state = json.loads((runtime.state_dir / "active_policies.json").read_text(encoding="utf-8"))

    assert [policy.id for policy in loaded.policies] == ["hard_safety"]
    assert state["active"] == ["hard_safety"]
    assert state["feedback"] == {"enabled": False}
    assert state["runtime"] == {
        "judge_batching": "aggressive",
        "trace_assistant_content": False,
        "judge_strategy": "active_policy",
        "judge_call_mode": "batched",
    }
    assert state["model_blocklist"] == ["blocked-model"]
    assert state["human_approval"] == {
        "enabled": True,
        "timeout_seconds": 12,
        "on_timeout": "allow",
    }
    assert {entry["id"] for entry in state["switches"]} == {"allow_output", "enforcement_mode"}


def test_yaml_loader_supports_kind_builtin(tmp_path):
    runtime = _runtime(tmp_path)
    runtime.yaml_file.write_text(
        """
predicates:
  - name: hard_rules
    kind: builtin
policies:
  - id: hard_safety
    enabled: true
    mfotl: |
      ALWAYS (FORALL t, c, n.
        (PolicyActive(t, "hard_safety")
         AND Message(t, \"user\", c, n)
         AND hard_rules(c) > 0.5)
        IMPLIES Block(t, \"request\", "safety", "blocked"))
""",
        encoding="utf-8",
    )

    loaded = load(runtime.yaml_file, runtime)

    sig_text = loaded.merged_sig_path.read_text(encoding="utf-8")
    assert "fun hard_rules(content:string) : float" in sig_text
    assert loaded.predicates[0].kind == "builtin"


def test_yaml_loader_supports_independent_ingest_judge_switches(tmp_path):
    runtime = _runtime(tmp_path)
    runtime.yaml_file.write_text(
        """
backend:
  unknown_tool_judge: true
  ingest_judges:
    enabled: true
    unknown_tool: false
    unknown_tool_allow_threshold: 0.97
    url_risk: true
    persistence_instruction: true
    secret_material: false
    uncertain_action: true
    package_name: false
    webshell: true
predicates: []
policies: []
""",
        encoding="utf-8",
    )

    loaded = load(runtime.yaml_file, runtime)
    judges = loaded.backend.ingest_judges
    state = json.loads(
        (runtime.state_dir / "active_policies.json").read_text(encoding="utf-8")
    )

    assert judges.enabled is True
    assert judges.unknown_tool is False
    assert judges.unknown_tool_allow_threshold == 0.97
    assert judges.url_risk is True
    assert judges.persistence_instruction is True
    assert judges.secret_material is False
    assert judges.uncertain_action is True
    assert judges.package_name is False
    assert judges.webshell is True
    # content_disclosure / semantic_command / content_semantics / memory_poison /
    # authored_capability are unspecified, so they default to master.
    assert judges.content_disclosure is True
    assert judges.semantic_command is True
    assert judges.content_semantics is True
    assert judges.memory_poison is True
    assert judges.authored_capability is True
    assert state["ingest_judges"] == {
        "enabled": True,
        "unknown_tool": False,
        "unknown_tool_allow_threshold": 0.97,
        "url_risk": True,
        "persistence_instruction": True,
        "secret_material": False,
        "uncertain_action": True,
        "package_name": False,
        "webshell": True,
        "content_disclosure": True,
        "semantic_command": True,
        "content_semantics": True,
        "memory_poison": True,
        "authored_capability": True,
    }


def test_yaml_loader_legacy_unknown_tool_judge_disables_all_ingest_judges(tmp_path):
    runtime = _runtime(tmp_path)
    runtime.yaml_file.write_text(
        """
backend:
  unknown_tool_judge: false
predicates: []
policies: []
""",
        encoding="utf-8",
    )

    judges = load(runtime.yaml_file, runtime).backend.ingest_judges

    assert judges.enabled is False
    assert not any(
        (
            judges.unknown_tool,
            judges.url_risk,
            judges.persistence_instruction,
            judges.secret_material,
            judges.uncertain_action,
            judges.package_name,
            judges.webshell,
            judges.content_disclosure,
            judges.semantic_command,
            judges.content_semantics,
            judges.memory_poison,
            judges.authored_capability,
        )
    )


def test_yaml_loader_rejects_unknown_builtin(tmp_path):
    runtime = _runtime(tmp_path)
    runtime.yaml_file.write_text(
        """
predicates:
  - name: not_a_real_helper
    kind: builtin
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="not a known helper"):
        load(runtime.yaml_file, runtime)


def test_yaml_loader_empty_yaml_yields_fallback_composite(tmp_path):
    runtime = _runtime(tmp_path)
    runtime.yaml_file.write_text("policies: []\npredicates: []\n", encoding="utf-8")

    loaded = load(runtime.yaml_file, runtime)
    state = json.loads((runtime.state_dir / "active_policies.json").read_text(encoding="utf-8"))

    assert state["active"] == []
    merged_text = loaded.merged_mfotl_path.read_text(encoding="utf-8")
    assert "ALWAYS TRUE" in merged_text


def test_yaml_loader_rejects_invalid_predicate_path(tmp_path):
    runtime = _runtime(tmp_path)
    runtime.yaml_file.write_text(
        """
predicates:
  - name: bad
    kind: python
    path: ./missing.py
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="does not exist"):
        load(runtime.yaml_file, runtime)


def test_yaml_loader_rejects_custom_policy_without_policy_active_gate(tmp_path):
    runtime = _runtime(tmp_path)
    runtime.yaml_file.write_text(
        """
policies:
  - id: custom_policy
    enabled: true
    mfotl: |
      ALWAYS TRUE
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="PolicyActive"):
        load(runtime.yaml_file, runtime)


def test_yaml_loader_ignores_deterministic_builtin_fail_mode_overrides(tmp_path):
    runtime = _runtime(tmp_path)
    runtime.yaml_file.write_text(
        """
backend:
  judge_timeout_ms: 2500
  judge_fail_mode: closed
judge_fail_modes:
  hard_rules: closed
""",
        encoding="utf-8",
    )

    load(runtime.yaml_file, runtime)
    state = json.loads((runtime.state_dir / "active_policies.json").read_text(encoding="utf-8"))

    assert state["judge_fail_mode"] == "closed"
    assert "hard_rules" not in state["judge_fail_modes"]


def test_yaml_loader_rejects_user_predicate_colliding_with_signature(tmp_path):
    """v4: predicates whose names collide with proxy event names are rejected.
    The collision check is against the v4 signature (Message, Completion,
    ToolCall, ...), not the v3 names (UserMessage, AssistantHistory, ...)."""

    runtime = _runtime(tmp_path)
    runtime.yaml_file.write_text(
        """
predicates:
  - name: Message
    kind: llm_judge
    system_prompt: bad namespace
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="collides with a proxy event"):
        load(runtime.yaml_file, runtime)


def test_yaml_loader_validates_custom_mfotl_with_enfguard(tmp_path, monkeypatch):
    runtime = _runtime(tmp_path)
    custom_predicate = tmp_path / "custom_predicates.py"
    custom_predicate.write_text("def has_magic_word(content):\n    return 0.0\n", encoding="utf-8")
    runtime.yaml_file.write_text(
        """
predicates:
  - name: has_magic_word
    kind: python
    path: ./custom_predicates.py
policies:
  - id: custom_policy
    enabled: true
    mfotl: |
      ALWAYS (FORALL t, c, n.
        (PolicyActive(t, "custom_policy")
         AND Message(t, \"user\", c, n)
         AND has_magic_word(c) > 0.5)
        IMPLIES Block(t, \"request\", "custom", "matched"))
""",
        encoding="utf-8",
    )
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(cmd, 0, stdout=b"ok")

    monkeypatch.setattr("yaml_loader.subprocess.run", fake_run)

    load(runtime.yaml_file, runtime)

    assert len(calls) == 2
    cmd, kwargs = calls[0]
    assert "-sig" in cmd
    assert "-formula" in cmd
    assert kwargs["input"] == b""
    assert kwargs["timeout"] == 5
    assert calls[1][0][calls[1][0].index("-formula") + 1].endswith(
        "enfguard_composite.mfotl.candidate"
    )


def test_yaml_loader_reports_invalid_custom_mfotl(tmp_path, monkeypatch):
    runtime = _runtime(tmp_path)
    runtime.yaml_file.write_text(
        """
policies:
  - id: custom_policy
    enabled: true
    mfotl: |
      ALWAYS (FORALL t, c, n.
        (PolicyActive(t, "custom_policy")
         AND Message(t, \"user\", c, n))
        IMPLIES Block(t, \"request\", "custom", "matched"))
""",
        encoding="utf-8",
    )

    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 2, stdout=b"parse error near IMPLIES")

    monkeypatch.setattr("yaml_loader.subprocess.run", fake_run)

    with pytest.raises(ValueError, match="custom_policy.*invalid MFOTL.*parse error"):
        load(runtime.yaml_file, runtime)


def test_yaml_loader_does_not_promote_invalid_composite(tmp_path, monkeypatch):
    runtime = _runtime(tmp_path)
    runtime.state_dir.mkdir(parents=True, exist_ok=True)
    active_path = runtime.state_dir / "active_policies.json"
    active_path.write_text('{"active": ["P1"]}\n', encoding="utf-8")
    runtime.composite_policy_file.write_text("OLD COMPOSITE\n", encoding="utf-8")
    runtime.yaml_file.write_text(
        """
policies:
  - id: custom_policy
    enabled: true
    mfotl: |
      ALWAYS (FORALL t, c, n.
        (PolicyActive(t, "custom_policy")
         AND Message(t, \"user\", c, n))
        IMPLIES Block(t, \"request\", "custom", "matched"))
""",
        encoding="utf-8",
    )
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if len(calls) == 1:
            return subprocess.CompletedProcess(cmd, 0, stdout=b"snippet ok")
        return subprocess.CompletedProcess(cmd, 2, stdout=b"composite parse error")

    monkeypatch.setattr("yaml_loader.subprocess.run", fake_run)

    with pytest.raises(ValueError, match="composite.*invalid MFOTL.*composite parse error"):
        load(runtime.yaml_file, runtime)

    assert json.loads(active_path.read_text(encoding="utf-8")) == {"active": ["P1"]}
    assert runtime.composite_policy_file.read_text(encoding="utf-8") == "OLD COMPOSITE\n"
