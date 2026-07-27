"""Regression tests for the false positives found by the independent FP probe
(scripts/fp_independent_corpus.py, defense Q9). Each was a legitimate dev/agent
action that received a verdict-relevant label.

See wiki/outputs/2026-06-11-independent-fp-corpus.md.
"""
from instrlib.tool_mapper import (
    map_tool_call,
    classify_resdev_kind,
    classify_recon_kind,
    is_credential_search_command,
)


def _classifies(events):
    return {(e.args[2], e.args[3]) for e in events if e.name == "Classify"}


# --- L14: docker pull of a standard Hub image was blocked (tag read as host) ---

def test_docker_pull_hub_image_with_tag_is_trusted():
    # `node:20` / `ubuntu:22.04`: the `:` is an image TAG, not a host:port.
    for cmd in ["docker pull node:20", "docker pull ubuntu:22.04",
                "docker pull library/redis:7", "docker pull redis",
                "docker pull docker.io/library/nginx:1"]:
        assert classify_resdev_kind(cmd) == "container_pull", cmd


def test_docker_pull_nonhub_registry_still_untrusted():
    for cmd in ["docker pull ghcr.io/me/app:1",
                "docker pull registry.evil.com:5000/x",
                "docker pull 10.0.0.5:5000/x",
                "docker run localhost:5000/y"]:
        assert classify_resdev_kind(cmd) == "untrusted_install", cmd


# --- L12: chmod on ~/.ssh/config was labelled reconnaissance/network_info -----

def test_permission_op_on_topology_file_is_not_recon():
    for cmd in ["chmod 600 ~/.ssh/config", "chown me /etc/hosts",
                "sudo chmod 644 /etc/resolv.conf", "ln -s /etc/hosts /tmp/h"]:
        assert classify_recon_kind(cmd) is None, cmd


def test_reading_topology_file_is_still_recon():
    for cmd in ["cat ~/.ssh/config", "less /etc/resolv.conf"]:
        assert classify_recon_kind(cmd) == "network_info", cmd


def test_permission_op_with_active_probe_is_still_recon():
    assert classify_recon_kind("chmod 600 ~/.ssh/config && netstat -tlnp") == "network_info"


# --- L08: grep for a credential keyword in a project subtree was a Block sweep -

def test_keyword_grep_in_project_subtree_is_not_a_sweep():
    for cmd in ['grep -rn "API_KEY" src/', "grep -r token ./config",
                "grep -rn AWS_SECRET lib/"]:
        assert is_credential_search_command(cmd) is False, cmd
        assert ("path_sensitivity", "credentials") not in _classifies(
            map_tool_call(1, "c", "bash", {"command": cmd})), cmd


def test_keyword_grep_over_home_or_system_root_is_still_a_sweep():
    for cmd in ["grep -r password /home", "grep -rni secret $HOME/notes",
                "grep -r private_key /etc"]:
        assert is_credential_search_command(cmd) is True, cmd


def test_recursive_grep_for_secret_file_is_still_a_sweep():
    # strong file/path indicator: a sweep regardless of root
    assert is_credential_search_command('grep -r "" ~/.ssh') is True
