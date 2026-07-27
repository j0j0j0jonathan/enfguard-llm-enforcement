"""Tests for switch state, YAML parsing, and proxy approval lifecycle."""

import json
from dataclasses import replace

import pytest

import proxy
from switch_state import (
    ENFORCEMENT_MODE_SWITCH_ID,
    SwitchSpec,
    SwitchState,
    default_enforcement_mode_spec,
)


def _runtime(tmp_path):
    """Mirror the runtime helper from ``test_yaml_loader.py``."""

    from config import CONFIG

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


def test_switch_state_emits_typed_events_per_kind():
    state = SwitchState()
    state.install(
        [
            SwitchSpec(id="max_tokens", kind="number", default=1000, min_value=100, max_value=8000),
            SwitchSpec(id="tone", kind="choice", default="technical", options=("formal", "casual", "technical")),
            SwitchSpec(id="dry_run", kind="boolean", default=False),
        ]
    )

    events = state.emit_events(7)
    serialized = [(e.name, e.args) for e in events]
    assert ("SettingInt", (7, "max_tokens", 1000)) in serialized
    assert ("SettingString", (7, "tone", "technical")) in serialized
    assert ("SettingBool", (7, "dry_run", 0)) in serialized


def test_switch_state_synthesises_enforcement_mode_when_user_omits_it():
    state = SwitchState()
    state.install([SwitchSpec(id="max_tokens", kind="number", default=200)])

    assert state.has(ENFORCEMENT_MODE_SWITCH_ID)
    assert state.get_value(ENFORCEMENT_MODE_SWITCH_ID) == "enforce"


def test_switch_state_set_value_validates_per_kind():
    state = SwitchState()
    state.install(
        [
            SwitchSpec(id="max_tokens", kind="number", default=1000, min_value=100, max_value=8000),
            SwitchSpec(id="tier", kind="choice", default="all", options=("all", "anthropic-only")),
            SwitchSpec(id="dry_run", kind="boolean", default=False),
        ]
    )

    assert state.set_value("max_tokens", 2000) == "2000"
    with pytest.raises(ValueError, match="below the configured minimum"):
        state.set_value("max_tokens", 50)
    with pytest.raises(ValueError, match="above the configured maximum"):
        state.set_value("max_tokens", 10_000)
    assert state.set_value("dry_run", "yes") == "true"
    with pytest.raises(ValueError, match="requires a boolean"):
        state.set_value("dry_run", "maybe")
    assert state.set_value("tier", "anthropic-only") == "anthropic-only"
    with pytest.raises(ValueError, match="requires one of"):
        state.set_value("tier", "no-gpt4")


def test_default_enforcement_mode_spec_is_enforce_choice():
    spec = default_enforcement_mode_spec()
    assert spec.id == ENFORCEMENT_MODE_SWITCH_ID
    assert spec.kind == "choice"
    assert spec.default == "enforce"
    assert spec.options == ("audit", "warn", "enforce")


def test_yaml_loader_parses_switches_block(tmp_path):
    from yaml_loader import load

    runtime = _runtime(tmp_path)
    runtime.yaml_file.write_text(
        """
switches:
  - id: max_tokens
    kind: number
    label: Max tokens per turn
    default: 1500
    min: 100
    max: 8000
  - id: tier
    kind: choice
    label: Allowed model tier
    options: [all, anthropic-only]
    default: all
human_approval:
  enabled: true
  timeout_seconds: 30
  on_timeout: warn
""".strip()
        + "\n",
        encoding="utf-8",
    )

    loaded = load(runtime.yaml_file, runtime)

    by_id = {spec.id: spec for spec in loaded.switches}
    # `kind: number` is a back-compat alias the loader normalises to `int`.
    assert by_id["max_tokens"].kind == "int"
    assert by_id["max_tokens"].min_value == 100
    assert by_id["max_tokens"].max_value == 8000
    assert by_id["max_tokens"].default == 1500
    assert by_id["tier"].kind == "choice"
    assert by_id["tier"].options == ("all", "anthropic-only")
    # enforcement_mode was synthesised because the user didn't declare it.
    assert by_id["enforcement_mode"].kind == "choice"

    assert loaded.human_approval.enabled is True
    assert loaded.human_approval.timeout_seconds == 30
    assert loaded.human_approval.on_timeout == "warn"

    persisted = json.loads((runtime.state_dir / "active_policies.json").read_text("utf-8"))
    assert {entry["id"] for entry in persisted["switches"]} == {"max_tokens", "tier", "enforcement_mode"}
    assert persisted["human_approval"]["enabled"] is True


def test_yaml_loader_rejects_default_outside_min_max(tmp_path):
    from yaml_loader import load

    runtime = _runtime(tmp_path)
    runtime.yaml_file.write_text(
        """
switches:
  - id: max_tokens
    kind: number
    default: 9999
    min: 100
    max: 8000
""".strip()
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="above max"):
        load(runtime.yaml_file, runtime)


def test_yaml_loader_rejects_unknown_switch_kind(tmp_path):
    from yaml_loader import load

    runtime = _runtime(tmp_path)
    runtime.yaml_file.write_text(
        """
switches:
  - id: foo
    kind: weird
""".strip()
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unsupported kind"):
        load(runtime.yaml_file, runtime)


def test_yaml_loader_choice_switch_requires_options(tmp_path):
    from yaml_loader import load

    runtime = _runtime(tmp_path)
    runtime.yaml_file.write_text(
        """
switches:
  - id: tier
    kind: choice
""".strip()
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="non-empty `options` list"):
        load(runtime.yaml_file, runtime)


def test_yaml_loader_rejects_features_block(tmp_path):
    """`features:` is gone entirely. Users must put runtime knobs in switches."""

    from yaml_loader import load

    runtime = _runtime(tmp_path)
    runtime.yaml_file.write_text(
        """
features:
  dry_run: true
""".strip()
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="`features:` block is no longer used"):
        load(runtime.yaml_file, runtime)


def test_proxy_dry_run_reads_from_switch_state(monkeypatch):
    monkeypatch.setattr(proxy.state, "switches", SwitchState())
    proxy.state.switches.install([default_enforcement_mode_spec("warn")])

    assert proxy._dry_run_enabled() is True

    proxy.state.switches.set_value("enforcement_mode", "enforce")
    assert proxy._dry_run_enabled() is False


def test_proxy_switch_updates_are_mirrored_for_judge_strategy_selectors(tmp_path, monkeypatch):
    runtime = _runtime(tmp_path)
    monkeypatch.setattr(proxy.state, "config", runtime)
    (runtime.state_dir / "active_policies.json").parent.mkdir(parents=True, exist_ok=True)
    (runtime.state_dir / "active_policies.json").write_text(
        json.dumps(
            {
                "runtime": {
                    "judge_strategy": "active_policy",
                    "judge_call_mode": "batched",
                },
                "switches": [
                    {
                        "id": "judge_strategy",
                        "kind": "choice",
                        "default": "active_policy",
                    },
                    {
                        "id": "allow_emojis",
                        "kind": "boolean",
                        "default": False,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    proxy._sync_switch_value_to_policy_state("judge_strategy", "off")
    proxy._sync_switch_value_to_policy_state("allow_emojis", "true")

    persisted = json.loads((runtime.state_dir / "active_policies.json").read_text("utf-8"))
    assert persisted["runtime"]["judge_strategy"] == "off"
    by_id = {entry["id"]: entry for entry in persisted["switches"]}
    assert by_id["judge_strategy"]["current"] == "off"
    assert by_id["allow_emojis"]["current"] == "true"


@pytest.mark.anyio
async def test_resolve_approvals_blocks_when_disabled(monkeypatch):
    """If human_approval.enabled is false, Approve becomes a hard block."""

    from yaml_loader import HumanApprovalConfig

    monkeypatch.setattr(proxy.state, "human_approval", HumanApprovalConfig(enabled=False))
    cau = {
        "Approve": [(5, "secrets-detected")],
    }
    result = await proxy._resolve_approvals(5, "s-test", cau, "inbound")
    assert "Approve" not in result
    assert result["BlockRequest"][0][1] == "approval"
    assert "secrets-detected" in result["BlockRequest"][0][2]


@pytest.mark.anyio
async def test_resolve_approvals_dry_run_auto_approves(monkeypatch):
    """When dry-run is on, the approval clears without suspending."""

    from yaml_loader import HumanApprovalConfig

    monkeypatch.setattr(proxy.state, "human_approval", HumanApprovalConfig(enabled=True))
    monkeypatch.setattr(proxy, "_dry_run_enabled", lambda: True)

    logged = []

    class FakeLogger:
        def log_only(self, events, tid):
            logged.extend((e.name, e.args) for e in events)

    monkeypatch.setattr(proxy, "_logger", lambda: FakeLogger())
    cau = {"Approve": [(7, "Approve write to ~/notes.md?")]}
    result = await proxy._resolve_approvals(7, "s", cau, "inbound")
    assert "Approve" not in result
    assert "BlockRequest" not in result
    assert any(name == "UserFeedback" for name, _ in logged)


@pytest.mark.anyio
async def test_resolve_approvals_pauses_and_resumes(monkeypatch):
    """An approve decision delivered via _resolve_pending_approval clears the block."""

    import asyncio

    from yaml_loader import HumanApprovalConfig

    monkeypatch.setattr(
        proxy.state, "human_approval", HumanApprovalConfig(enabled=True, timeout_seconds=5, on_timeout="block")
    )
    monkeypatch.setattr(proxy, "_dry_run_enabled", lambda: False)
    proxy.state.pending_approvals.clear()
    cau = {"Approve": [(11, "Approve action?")]}

    async def deliver():
        await asyncio.sleep(0.05)
        proxy._resolve_pending_approval(11, "approve", "")

    result_task = asyncio.create_task(
        proxy._resolve_approvals(11, "s", cau, "inbound")
    )
    deliver_task = asyncio.create_task(deliver())
    result = await asyncio.wait_for(result_task, timeout=2.0)
    await deliver_task

    assert "BlockRequest" not in result
    assert "Approve" not in result
    # Pending registry was cleaned up.
    assert 11 not in proxy.state.pending_approvals


@pytest.mark.anyio
async def test_resolve_approvals_timeout_falls_back_to_block(monkeypatch):
    from yaml_loader import HumanApprovalConfig

    monkeypatch.setattr(
        proxy.state,
        "human_approval",
        HumanApprovalConfig(enabled=True, timeout_seconds=0.05, on_timeout="block"),
    )
    monkeypatch.setattr(proxy, "_dry_run_enabled", lambda: False)
    proxy.state.pending_approvals.clear()
    cau = {"Approve": [(13, "Approve?")]}

    result = await proxy._resolve_approvals(13, "s", cau, "inbound")
    assert "Approve" not in result
    assert result["BlockRequest"][0][1] == "approval"
    assert 13 not in proxy.state.pending_approvals


def test_normalize_approval_decision_only_accepts_explicit_kinds():
    assert proxy._normalize_approval_decision("approve") == "approve"
    assert proxy._normalize_approval_decision("DENY") == "deny"
    assert proxy._normalize_approval_decision("approve_block") == ""
    assert proxy._normalize_approval_decision("freeform") == ""


def test_summarise_phases_groups_rows_and_attributes_verdicts():
    rows = [
        {"phase": "inbound", "predicate": "hard_rules", "score": 1.0, "raw_score": 0.9, "reason": "x", "latency_ms": 80},
        {"phase": "outbound", "predicate": "contains_secrets", "score": 0.0, "raw_score": 0.1, "reason": "", "latency_ms": 5},
    ]
    session_records = [
        {"action": "request_blocked", "verdicts": [{"action": "BlockRequest"}]},
        {"action": "allowed", "verdicts": []},
    ]
    summary = proxy._summarise_phases(rows, session_records)
    assert {p["phase"] for p in summary} == {"inbound", "outbound"}
    inbound = next(p for p in summary if p["phase"] == "inbound")
    assert inbound["action"] == "request_blocked"
    assert inbound["fired_predicates"][0]["predicate"] == "hard_rules"
    assert inbound["wall_ms"] == 80


def test_switch_state_kind_int_rejects_fractional_values():
    state = SwitchState()
    state.install([SwitchSpec(id="max_tokens", kind="int", default=100)])
    with pytest.raises(ValueError, match="int switch requires an integer"):
        state.set_value("max_tokens", 2.5)


def test_yaml_loader_kind_int_rejects_fractional_default(tmp_path):
    from yaml_loader import load

    runtime = _runtime(tmp_path)
    runtime.yaml_file.write_text(
        """
switches:
  - id: t
    kind: int
    default: 0.75
""".strip()
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="int switches require integer"):
        load(runtime.yaml_file, runtime)


@pytest.mark.anyio
async def test_resolve_approvals_phase2_maps_to_block_response(monkeypatch):
    """A Approve verdict in Phase 2 must map deny → BlockResponse."""

    import asyncio

    from yaml_loader import HumanApprovalConfig

    monkeypatch.setattr(
        proxy.state, "human_approval", HumanApprovalConfig(enabled=True, timeout_seconds=5, on_timeout="block")
    )
    monkeypatch.setattr(proxy, "_dry_run_enabled", lambda: False)
    proxy.state.pending_approvals.clear()
    cau = {"Approve": [(21, "Release this completion?")]}

    async def deny_after():
        await asyncio.sleep(0.05)
        proxy._resolve_pending_approval(21, "deny", "")

    result_task = asyncio.create_task(
        proxy._resolve_approvals(21, "s", cau, "outbound")
    )
    deny_task = asyncio.create_task(deny_after())
    result = await asyncio.wait_for(result_task, timeout=2.0)
    await deny_task

    assert "Approve" not in result
    assert "BlockResponse" in result
    assert "BlockRequest" not in result
    assert result["BlockResponse"][0][1] == "approval"


@pytest.mark.anyio
async def test_resolve_approvals_phase2_disabled_uses_block_response(monkeypatch):
    from yaml_loader import HumanApprovalConfig

    monkeypatch.setattr(proxy.state, "human_approval", HumanApprovalConfig(enabled=False))
    cau = {"Approve": [(22, "label")]}
    result = await proxy._resolve_approvals(22, "s", cau, "outbound")
    assert "BlockResponse" in result
    assert "BlockRequest" not in result


@pytest.mark.anyio
async def test_resolve_approvals_phase2_timeout_warn(monkeypatch):
    from yaml_loader import HumanApprovalConfig

    monkeypatch.setattr(
        proxy.state,
        "human_approval",
        HumanApprovalConfig(enabled=True, timeout_seconds=0.05, on_timeout="warn"),
    )
    monkeypatch.setattr(proxy, "_dry_run_enabled", lambda: False)
    proxy.state.pending_approvals.clear()
    cau = {"Approve": [(23, "label")]}
    result = await proxy._resolve_approvals(23, "s", cau, "outbound")
    assert "WarnResponse" in result
    assert "BlockResponse" not in result


@pytest.mark.anyio
async def test_resolve_approvals_tool_approve_allows(monkeypatch):
    import asyncio

    from yaml_loader import HumanApprovalConfig

    monkeypatch.setattr(
        proxy.state, "human_approval", HumanApprovalConfig(enabled=True, timeout_seconds=5, on_timeout="block")
    )
    monkeypatch.setattr(proxy, "_dry_run_enabled", lambda: False)
    proxy.state.pending_approvals.clear()
    cau = {"Approve": [(31, "Allow tool use?")]}

    async def approve_after():
        await asyncio.sleep(0.05)
        proxy._resolve_pending_approval(31, "approve", "")

    result_task = asyncio.create_task(
        proxy._resolve_approvals(31, "s", cau, "tool")
    )
    approve_task = asyncio.create_task(approve_after())
    result = await asyncio.wait_for(result_task, timeout=2.0)
    await approve_task

    assert "Approve" not in result
    assert "BlockToolCall" not in result
    assert "WarnToolCall" not in result
    assert result == {}


@pytest.mark.anyio
async def test_resolve_approvals_tool_deny_blocks_tool(monkeypatch):
    import asyncio

    from yaml_loader import HumanApprovalConfig

    monkeypatch.setattr(
        proxy.state, "human_approval", HumanApprovalConfig(enabled=True, timeout_seconds=5, on_timeout="block")
    )
    monkeypatch.setattr(proxy, "_dry_run_enabled", lambda: False)
    proxy.state.pending_approvals.clear()
    cau = {"Approve": [(32, "Allow tool use?")]}

    async def deny_after():
        await asyncio.sleep(0.05)
        proxy._resolve_pending_approval(32, "deny", "")

    result_task = asyncio.create_task(
        proxy._resolve_approvals(32, "s", cau, "tool")
    )
    deny_task = asyncio.create_task(deny_after())
    result = await asyncio.wait_for(result_task, timeout=2.0)
    await deny_task

    assert "Approve" not in result
    assert "BlockToolCall" in result
    assert "BlockRequest" not in result
    assert result["BlockToolCall"][0][1] == "approval"


@pytest.mark.anyio
async def test_resolve_approvals_tool_disabled_blocks_tool(monkeypatch):
    from yaml_loader import HumanApprovalConfig

    monkeypatch.setattr(proxy.state, "human_approval", HumanApprovalConfig(enabled=False))
    cau = {"Approve": [(33, "Allow tool use?")]}
    result = await proxy._resolve_approvals(33, "s", cau, "tool")
    assert "BlockToolCall" in result
    assert "BlockRequest" not in result


def test_summarise_batches_aggregates_by_batch_id():
    rows = [
        {"predicate": "a", "batch_id": "abc", "latency_ms": 120},
        {"predicate": "b", "batch_id": "abc", "latency_ms": 120},
        {"predicate": "c", "batch_id": "", "latency_ms": 30},
    ]
    summary = proxy._summarise_batches(rows)
    assert "abc" in summary
    assert summary["abc"]["latency_ms"] == 120
    assert sorted(summary["abc"]["predicates"]) == ["a", "b"]
    assert "" not in summary
