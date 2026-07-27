"""Config-driven agent-state control artifacts (config / skill tampering), 2026-06-30.

The classifier no longer hard-codes one framework's directory layout. The harness
adapter declares where the agent keeps its own private state (skills, config,
memory) via ENFGUARD_AGENT_STATE_ROOTS, and a WRITE under that root to the skill
store or the config / settings is self-tampering: the mapper emits
Classify(control_artifact_write, "agent_skill" | "agent_config"), which the
provenance_v1 pack hard-blocks. First-class config-mutation tools (set_config /
update_config) emit the same fact by name. Configuration Tampering is thus closed
deterministically, not only by the soft coverage tier.

False-positive guards verified here:
- a config READ (cat / get_config / read_config) is never flagged,
- an ordinary project config OUTSIDE the declared agent-state root
  (tsconfig.json, package.json) is never flagged,
- with NO root declared the behaviour is unchanged (default-empty roots).

    python -m pytest tests/test_tool_mapper_agent_state_artifacts_2026_06_30.py -q
"""

from __future__ import annotations

import importlib

import pytest

import instrlib.tool_mapper as tm


@pytest.fixture()
def declared_root(monkeypatch):
    """Declare an agent-state root, the way the Tier B proxy launch does."""
    monkeypatch.setenv("ENFGUARD_AGENT_STATE_ROOTS", "~/.openclaw,.openclaw")
    yield


def _caw(name, inp):
    """control_artifact_write levels emitted for a tool call."""
    evs = tm.map_tool_call(1, "c", name, inp)
    return [
        e.args[3]
        for e in evs
        if e.name == "Classify" and len(e.args) >= 4 and e.args[2] == "control_artifact_write"
    ]


# --- Configuration Tampering: shell, file tool, first-class tool ----------------

def test_config_write_shell_redirect(declared_root):
    assert "agent_config" in _caw("bash", {"command": "echo 'auto_approve: true' > ~/.openclaw/config.json"})


def test_config_write_sed_inplace(declared_root):
    assert "agent_config" in _caw("bash", {"command": "sed -i 's/sandbox: on/sandbox: off/' ~/.openclaw/settings.yaml"})


def test_config_write_file_tool(declared_root):
    assert "agent_config" in _caw("write_file", {"path": "~/.openclaw/config.json", "content": "auto_approve: true"})


@pytest.mark.parametrize("name", ["set_config", "update_config", "config_set", "disable_config", "settings_update"])
def test_config_first_class_tool(declared_root, name):
    assert "agent_config" in _caw(name, {"key": "sandbox", "value": "off"})


# --- Malicious Skill: write into the declared skill store -----------------------

def test_skill_store_write_shell(declared_root):
    assert "agent_skill" in _caw("bash", {"command": "cp /tmp/evil/SKILL.md ~/.openclaw/workspace/skills/evil/SKILL.md"})


def test_skill_store_write_file_tool(declared_root):
    assert "agent_skill" in _caw("write_file", {"path": "~/.openclaw/workspace/skills/evil/SKILL.md", "content": "x"})


# --- benign: reads and ordinary project config stay clean ----------------------

def test_config_read_shell_not_flagged(declared_root):
    assert _caw("bash", {"command": "cat ~/.openclaw/config.json"}) == []


@pytest.mark.parametrize("name", ["get_config", "read_config", "show_config", "list_config"])
def test_config_read_tool_not_flagged(declared_root, name):
    assert _caw(name, {"path": "~/.openclaw/config.json"}) == []


def test_project_config_outside_root_not_flagged(declared_root):
    # ordinary project config, NOT under the agent-state root
    assert _caw("write_file", {"path": "/tmp/project/tsconfig.json", "content": "{}"}) == []
    assert _caw("write_file", {"path": "/tmp/project/settings.json", "content": "{}"}) == []


# --- no declared root: behaviour unchanged (default empty) ----------------------

def test_no_root_declared_config_not_flagged(monkeypatch):
    monkeypatch.delenv("ENFGUARD_AGENT_STATE_ROOTS", raising=False)
    # Without a declared root, a product-specific config path is not the agent's
    # own (we cannot know the layout), so it is not flagged here. The explicit
    # agent-config token still is.
    assert _caw("write_file", {"path": "~/.openclaw/config.json", "content": "x"}) == []
    assert "agent_config" in _caw("bash", {"command": "echo x > /tmp/agent_config"})
