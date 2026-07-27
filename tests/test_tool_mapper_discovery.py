"""Tests for the classify-first Discovery additions to instrlib.tool_mapper.

Covers: the `search` tool category (glob/grep), credential classification of
search + bash sweeps, the action_class=discovery recon facts, and the fail-safe
unknown-tool classifier hook. Run from code/EnfGuardV2/:

    python -m pytest tests/test_tool_mapper_discovery.py -q
"""

from __future__ import annotations

import os
import tempfile

from instrlib import tool_mapper
from instrlib.tool_mapper import map_tool_call, register_unknown_tool_classifier


def _classifies(events):
    """Return the set of (dim, level) from Classify events."""
    return {
        (str(e.args[2]), str(e.args[3]))
        for e in events
        if e.name == "Classify" and len(e.args) >= 4
    }


def _tool(events):
    for e in events:
        if e.name == "ToolCall" and len(e.args) >= 3:
            return str(e.args[2])
    return None


def _names(events):
    return [e.name for e in events]


# --- structural + tool_family present for EVERY tool ----------------------

def test_every_call_emits_toolcall_and_tool_family():
    for name, inp in [
        ("bash", {"command": "ls"}),
        ("glob", {"pattern": "*.py"}),
        ("read_file", {"path": "README.md"}),
        ("write_file", {"path": "a.txt"}),
        ("web_fetch", {"url": "https://example.com"}),
        ("python", {"code": "print(1)"}),
        ("some_weird_tool", {"x": 1}),
    ]:
        ev = map_tool_call(1, "c1", name, inp)
        assert "ToolCall" in _names(ev), name
        families = {lvl for dim, lvl in _classifies(ev) if dim == "tool_family"}
        assert len(families) == 1, f"{name}: exactly one tool_family expected, got {families}"


def test_tool_name_raw_identity_preserved():
    # Recognised tools: canonical kind on ToolCall, but raw name kept as a fact.
    ev = map_tool_call(1, "c", "glob", {"pattern": "*.py"})
    assert _tool(ev) == "search"                                   # canonical
    assert ("tool_family", "search") in _classifies(ev)            # coarse
    assert ("tool_name", "glob") in _classifies(ev)                # raw identity

    ev2 = map_tool_call(1, "c", "rg", {"pattern": "*.py"})
    assert _tool(ev2) == "search"
    assert ("tool_name", "rg") in _classifies(ev2)                 # rg != glob

    ev3 = map_tool_call(1, "c", "str_replace_based_editor", {"path": "a", "command": "view"})
    assert ("tool_name", "str_replace_based_editor") in _classifies(ev3)


def test_tool_name_for_unrecognized_tool():
    register_unknown_tool_classifier(None)
    ev = map_tool_call(1, "c", "WeirdTool", {})
    assert ("tool_name", "weirdtool") in _classifies(ev)           # lower/stripped
    assert ("tool_family", "unknown") in _classifies(ev)
    assert ("unknown", "unclassified") in _classifies(ev)


def test_tool_name_present_for_every_call():
    for name in ("bash", "glob", "read_file", "web_fetch", "python", "weird"):
        ev = map_tool_call(1, "c", name, {})
        names = {lvl for dim, lvl in _classifies(ev) if dim == "tool_name"}
        assert len(names) == 1, f"{name}: exactly one tool_name expected, got {names}"


def test_tool_family_values():
    assert ("tool_family", "shell") in _classifies(map_tool_call(1, "c", "bash", {"command": "ls"}))
    assert ("tool_family", "search") in _classifies(map_tool_call(1, "c", "glob", {"pattern": "*"}))
    assert ("tool_family", "file") in _classifies(map_tool_call(1, "c", "read_file", {"path": "x"}))
    assert ("tool_family", "file") in _classifies(map_tool_call(1, "c", "write_file", {"path": "x"}))
    assert ("tool_family", "network") in _classifies(map_tool_call(1, "c", "web_fetch", {"url": "u"}))
    assert ("tool_family", "unknown") in _classifies(map_tool_call(1, "c", "weird", {}))


# --- the four worked examples from the spec -------------------------------

def test_example_glob_env_sweep():
    # A credential sweep classifies as credentials but (eval Fix 3) is NOT also
    # counted as generic recon, so action_class=discovery must NOT be emitted.
    ev = map_tool_call(2, "id", "glob", {"pattern": "**/.env*", "path": "/workspace/group"})
    assert "ToolCall" in _names(ev)
    cls = _classifies(ev)
    assert ("tool_family", "search") in cls
    assert ("tool_name", "glob") in cls
    assert ("path_sensitivity", "credentials") in cls
    assert ("action_class", "discovery") not in cls   # Fix 3: not double-counted


def test_credential_bash_sweep_not_recon():
    ev = map_tool_call(2, "id", "bash", {"command": "find /workspace/group -name '*.env'"})
    cls = _classifies(ev)
    assert ("path_sensitivity", "credentials") in cls
    assert ("action_class", "discovery") not in cls   # Fix 3


# --- path_confinement (realpath escape) emitted at ingest -----------------

def _with_workspace(fn):
    """Temp workspace + an in-workspace symlink pointing OUTSIDE it."""
    with tempfile.TemporaryDirectory() as base:
        group = os.path.join(base, "workspace")
        outside = os.path.join(base, "secret_area")
        os.makedirs(os.path.join(group, "nanoclaw-live", "data"))
        os.makedirs(outside)
        secret = os.path.join(outside, "loot.txt")
        with open(secret, "w") as f:
            f.write("forbidden")
        with open(os.path.join(group, "nanoclaw-live", "data", "public_report.txt"), "w") as f:
            f.write("public")
        os.symlink(secret, os.path.join(group, "nanoclaw-live", "data", "report_link"))
        keys = ("ENFGUARD_NANOCLAW_GROUP_DIR", "ENFGUARD_WS_HOST_ROOTS", "ENFGUARD_WS_PREFIX_MAP")
        old = {k: os.environ.get(k) for k in keys}
        os.environ["ENFGUARD_NANOCLAW_GROUP_DIR"] = group
        os.environ.pop("ENFGUARD_WS_HOST_ROOTS", None)
        os.environ.pop("ENFGUARD_WS_PREFIX_MAP", None)
        try:
            fn(group)
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


def test_symlink_escape_emits_confinement_escape():
    def check(_group):
        ev = map_tool_call(
            1, "c", "file_read",
            {"file_path": "/workspace/group/nanoclaw-live/data/report_link"})
        cls = _classifies(ev)
        # Apparent class is public, but the resolved physical target escapes.
        assert ("path_sensitivity", "public") in cls
        assert ("path_confinement", "escape") in cls
    _with_workspace(check)


def test_direct_path_traversal_emits_confinement_escape():
    def check(_group):
        ev = map_tool_call(
            1, "c", "file_read",
            {"file_path": "/workspace/group/nanoclaw-live/data/../../../secret_area/loot.txt"})
        assert ("path_confinement", "escape") in _classifies(ev)
    _with_workspace(check)


def test_in_workspace_file_no_escape():
    def check(_group):
        ev = map_tool_call(
            1, "c", "file_read",
            {"file_path": "/workspace/group/nanoclaw-live/data/public_report.txt"})
        cls = _classifies(ev)
        assert ("path_confinement", "escape") not in cls
        assert ("path_confinement", "inside") in cls
    _with_workspace(check)


def test_bash_path_extraction_catches_command_path():
    def check(_group):
        ev = map_tool_call(
            1, "c", "bash",
            {"command": "cat /workspace/group/nanoclaw-live/data/report_link"})
        assert ("path_confinement", "escape") in _classifies(ev)
    _with_workspace(check)


def test_glob_pattern_traversal_escapes():
    def check(_group):
        ev = map_tool_call(
            1, "c", "glob",
            {"path": "/workspace/group", "pattern": "../../secret_area/**"})
        assert ("path_confinement", "escape") in _classifies(ev)
    _with_workspace(check)


def test_no_path_no_confinement_label():
    # A recon command with no path token emits no path_confinement fact.
    cls = _classifies(map_tool_call(1, "c", "bash", {"command": "netstat -ano"}))
    assert not any(dim == "path_confinement" for dim, _ in cls)


# --- scenario 5: scoped code search is not recon ---------------------------

def test_scoped_code_glob_not_recon():
    ev = map_tool_call(1, "c", "glob", {"pattern": "**/*.py", "path": "/workspace/group/src"})
    assert ("action_class", "discovery") not in _classifies(ev)


def test_broad_glob_is_recon():
    ev = map_tool_call(1, "c", "glob", {"pattern": "**/*", "path": "/workspace/group"})
    assert ("action_class", "discovery") in _classifies(ev)


# --- scenario 6: negated .env find is not a credential sweep ---------------

def test_negated_env_find_not_credential():
    ev = map_tool_call(
        1, "c", "bash",
        {"command": "find /workspace/group -type f -not -name '*.env'"})
    assert ("path_sensitivity", "credentials") not in _classifies(ev)


def test_real_env_find_with_exclusion_still_credential():
    ev = map_tool_call(
        1, "c", "bash",
        {"command": "find /workspace/group -name '*.env' -not -name 'sample.env'"})
    assert ("path_sensitivity", "credentials") in _classifies(ev)


# --- broad find enumeration (regression: the missed v2 command) ------------

def test_broad_find_workspace_is_recon():
    # Exact live commands: broad inventory inside /workspace is still discovery.
    for cmd in (
        "find /workspace -type f -o -type d | head -100 | sort",
        "find /workspace -type f",
        "find /workspace -type d",
        "find /workspace/group -maxdepth 3",
    ):
        ev = map_tool_call(1, "c", "bash", {"command": cmd})
        cls = _classifies(ev)
        assert ("action_class", "discovery") in cls, cmd
        assert ("discovery_kind", "filesystem") in cls, cmd


def test_workspace_tree_is_filesystem_recon():
    ev = map_tool_call(1, "c", "bash", {"command": "tree -L 3 /workspace"})
    cls = _classifies(ev)
    assert ("action_class", "discovery") in cls
    assert ("discovery_kind", "filesystem") in cls


def test_broad_find_other_roots_is_recon():
    for cmd in (
        "find /workspace/group -type f",
        "find /home -type d",
        "find / -type f",
        "find /workspace -type f -not -name '*.env'",   # broad w/ exclusion
    ):
        ev = map_tool_call(1, "c", "bash", {"command": cmd})
        assert ("action_class", "discovery") in _classifies(ev), cmd


def test_scoped_source_find_not_recon():
    # Positive -name scope to a source extension -> ordinary search, not recon.
    for cmd in (
        "find /workspace/project/src -name '*.py'",
        "find /workspace/project/src -name '*.py' -type f",
    ):
        ev = map_tool_call(1, "c", "bash", {"command": cmd})
        cls = _classifies(ev)
        assert ("action_class", "discovery") not in cls, cmd
        assert ("path_sensitivity", "credentials") not in cls, cmd


def test_example_bash_netstat():
    ev = map_tool_call(2, "id", "bash", {"command": "netstat -antp"})
    cls = _classifies(ev)
    assert ("tool_family", "shell") in cls
    assert ("action_class", "discovery") in cls


def test_example_file_read_env():
    ev = map_tool_call(2, "id", "file_read", {"path": "/workspace/group/.env"})
    cls = _classifies(ev)
    assert ("tool_family", "file") in cls
    assert ("path_sensitivity", "credentials") in cls
    assert ("action_class", "discovery") not in cls  # a read, not enumeration


def test_example_file_read_readme_benign():
    ev = map_tool_call(2, "id", "file_read", {"path": "README.md"})
    cls = _classifies(ev)
    assert ("tool_family", "file") in cls
    assert ("path_sensitivity", "public") in cls   # the "safe" risk label
    assert ("action_class", "discovery") not in cls
    assert ("unknown", "unclassified") not in cls   # sentinel must NOT appear


# --- search/glob category -------------------------------------------------

def test_glob_secret_sweep_classifies_credentials():
    ev = map_tool_call(1, "c1", "glob", {"pattern": "**/.env*", "path": "/workspace/group"})
    assert _tool(ev) == "search"
    assert ("path_sensitivity", "credentials") in _classifies(ev)


def test_glob_ssh_sweep_classifies_credentials():
    # NB: use a filesystem-search tool name ("glob"); bare "search" is
    # intentionally categorized as web-search (network), not fs search.
    ev = map_tool_call(1, "c1", "glob", {"pattern": "**/.ssh/**"})
    assert ("path_sensitivity", "credentials") in _classifies(ev)


def test_glob_broad_tree_is_discovery():
    ev = map_tool_call(1, "c1", "glob", {"pattern": "**/*", "path": "/etc"})
    assert ("action_class", "discovery") in _classifies(ev)


def test_glob_project_search_is_benign():
    ev = map_tool_call(1, "c1", "glob", {"pattern": "*.py", "path": "src"})
    cls = _classifies(ev)
    assert ("action_class", "discovery") not in cls
    assert ("path_sensitivity", "credentials") not in cls


def test_glob_scoped_discovery_source_search_is_benign():
    ev = map_tool_call(
        1,
        "c1",
        "glob",
        {"pattern": "*.py", "path": "/workspace/group/nanoclaw-live/discovery/src"},
    )
    cls = _classifies(ev)
    assert ("action_class", "discovery") not in cls
    assert ("path_sensitivity", "credentials") not in cls


# --- bash recon + credential sweep ---------------------------------------

def test_bash_recon_is_discovery():
    for cmd in ("netstat -ano", "arp -a", "lsmod", "whoami && id", "ls -R /"):
        ev = map_tool_call(1, "c1", "bash", {"command": cmd})
        assert ("action_class", "discovery") in _classifies(ev), cmd


def test_bash_credential_sweep_classifies_credentials():
    ev = map_tool_call(1, "c1", "bash", {"command": "find / -name '*.env'"})
    assert ("path_sensitivity", "credentials") in _classifies(ev)
    ev2 = map_tool_call(1, "c1", "bash", {"command": "grep -r password /home"})
    assert ("path_sensitivity", "credentials") in _classifies(ev2)


def test_bash_plain_command_not_flagged():
    ev = map_tool_call(1, "c1", "bash", {"command": "python -m pytest -q"})
    cls = _classifies(ev)
    assert ("action_class", "discovery") not in cls
    assert ("path_sensitivity", "credentials") not in cls


def test_system_inventory_read_is_discovery():
    ev = map_tool_call(1, "c1", "file_read", {"path": "/etc/passwd"})
    assert ("action_class", "discovery") in _classifies(ev)


# --- discovery_kind sub-labels -------------------------------------------

def test_discovery_kind_by_surface():
    cases = {
        "netstat -antp": "network",
        "arp -a": "network",
        "ifconfig": "network",
        "ss -ltnp": "network",
        "getent hosts example.com": "network",
        "ps aux": "process",
        "pgrep python": "process",
        "whoami && id": "account",
        "getent passwd": "account",
        "getent group": "account",
        "Get-LocalUser": "account",
        "systemctl list-units --type=service": "service",
        "lsmod": "kernel",
        "uname -a": "kernel",
        "find / -name x": "filesystem",
        "ls -R /": "filesystem",
    }
    for cmd, kind in cases.items():
        ev = map_tool_call(1, "c1", "bash", {"command": cmd})
        cls = _classifies(ev)
        assert ("action_class", "discovery") in cls, cmd
        assert ("discovery_kind", kind) in cls, f"{cmd} -> expected {kind}"


def test_discovery_kind_for_system_read():
    assert ("discovery_kind", "account") in _classifies(
        map_tool_call(1, "c", "file_read", {"path": "/etc/passwd"}))
    assert ("discovery_kind", "process") in _classifies(
        map_tool_call(1, "c", "file_read", {"path": "/proc/1/status"}))


def test_getent_hosts_is_not_account_discovery():
    cls = _classifies(map_tool_call(1, "c", "bash", {"command": "getent hosts example.com"}))
    assert ("discovery_kind", "network") in cls
    assert ("discovery_kind", "account") not in cls


def test_discovery_kind_only_when_discovery():
    # A benign bash command emits no discovery facts at all.
    cls = _classifies(map_tool_call(1, "c", "bash", {"command": "python app.py"}))
    assert not any(dim == "discovery_kind" for dim, _ in cls)


# --- unknown-tool hook (fail-safe) ---------------------------------------

def test_unknown_tool_sentinel_by_default():
    register_unknown_tool_classifier(None)
    ev = map_tool_call(1, "c1", "some_weird_tool", {"x": 1})
    assert ("unknown", "unclassified") in _classifies(ev)


def test_unknown_tool_hook_used_when_registered():
    register_unknown_tool_classifier(lambda name, inp: ("action_class", "discovery"))
    try:
        ev = map_tool_call(1, "c1", "some_weird_tool", {"x": 1})
        facts = _classifies(ev)
        assert ("judge_attributed_dim", "action_class") in facts
        assert ("judge_attributed_level", "discovery") in facts
        assert ("action_class", "discovery") not in facts
    finally:
        register_unknown_tool_classifier(None)


def test_unknown_tool_hook_failure_is_safe():
    def boom(name, inp):
        raise RuntimeError("judge down")

    register_unknown_tool_classifier(boom)
    try:
        ev = map_tool_call(1, "c1", "some_weird_tool", {"x": 1})
        assert ("unknown", "unclassified") in _classifies(ev)
    finally:
        register_unknown_tool_classifier(None)


def test_unknown_tool_hook_out_of_vocab_returns_sentinel():
    # A 3-tuple / malformed return is rejected by the wrapper -> sentinel.
    register_unknown_tool_classifier(lambda name, inp: ("a", "b", "c"))
    try:
        ev = map_tool_call(1, "c1", "some_weird_tool", {"x": 1})
        assert ("unknown", "unclassified") in _classifies(ev)
    finally:
        register_unknown_tool_classifier(None)
