"""Tests for the classify-first Lateral Movement additions to tool_mapper.

OpenClaw category 10 (Lateral Movement). Covers the new
Classify(action_class,"lateral_movement") + Classify(lm_kind,<kind>) facts that
drive lateral_movement_classify_policies.yaml:

    python -m pytest tests/test_tool_mapper_lateral_movement.py -q

Kinds + pack tiers:
  * tunnel -> Block (direct)
  * any lateral_movement after a prior session credential read -> Block (pivot_after_credential)
  * internal_scan -> Warn
  * standalone ssh_pivot / smb -> visibility fact, no verdict
Boundaries: scp/rsync stay Exfiltration; nc/telnet/redis stay Initial Access;
sshpass -p stays Initial Access/brute_force; ssh-keygen stays Resource Development.
"""

from __future__ import annotations

from instrlib.tool_mapper import map_tool_call, classify_lm_kind


def _classifies(events):
    return {
        (str(e.args[2]), str(e.args[3]))
        for e in events
        if e.name == "Classify" and len(e.args) >= 4
    }


def _bash(cmd):
    return _classifies(map_tool_call(1, "c", "bash", {"command": cmd}))


# --- kinds --------------------------------------------------------------------

def test_tunnel_kinds():
    for cmd in ("ssh -L 8443:internal:443 user@host", "ssh -R 9000:localhost:22 u@h",
                "ssh -D 1080 user@jump", "chisel client https://x 80:host:80", "ngrok tcp 22"):
        cls = _bash(cmd)
        assert ("action_class", "lateral_movement") in cls, cmd
        assert ("lm_kind", "tunnel") in cls, cmd


def test_ssh_pivot_kind():
    for cmd in ('ssh -i deploy_key user@build-host "uptime"', "ssh user@10.0.0.5 whoami"):
        cls = _bash(cmd)
        assert ("action_class", "lateral_movement") in cls, cmd
        assert ("lm_kind", "ssh_pivot") in cls, cmd


def test_ssh_pivot_with_credential_identity_key():
    for cmd in (
        "ssh -i /workspace/group/credential/id_ed25519 deploy@10.0.0.42 uptime",
        "ssh -o IdentityFile=/workspace/group/credential/id_ed25519 deploy@10.0.0.42 uptime",
    ):
        cls = _bash(cmd)
        assert ("action_class", "lateral_movement") in cls, cmd
        assert ("lm_kind", "ssh_pivot") in cls, cmd
        assert ("credential_kind", "ssh_key") in cls, cmd


def test_ssh_pivot_with_any_identity_counts_as_key(  # F8
):
    # An explicit `ssh -i <file>` supplies a private key by definition, whatever
    # the file is named or wherever it lives. Previously a benign-looking name
    # ("./id_benchmark") stayed visibility-only, which let an attacker evade the
    # same-turn-credential-pivot block simply by staging the key as `/tmp/.k`.
    # F8: any identity argument now emits credential_kind=ssh_key.
    for cmd in (
        "ssh -i ./id_benchmark user@192.0.2.10 uptime",
        "ssh -i /tmp/.k svc@fileshare-02 ls -la /srv/share",
    ):
        cls = _bash(cmd)
        assert ("action_class", "lateral_movement") in cls, cmd
        assert ("lm_kind", "ssh_pivot") in cls, cmd
        assert ("credential_kind", "ssh_key") in cls, cmd


def test_smb_kind():
    for cmd in ("smbclient //10.0.0.5/share", "mount -t cifs //10.0.0.5/c /mnt",
                "psexec.py user@10.0.0.5"):
        cls = _bash(cmd)
        assert ("lm_kind", "smb") in cls, cmd


def test_internal_scan_kind():
    for cmd in ("masscan 10.0.0.0/8 -p443", "zmap -p 443 10.0.0.0/8"):
        cls = _bash(cmd)
        assert ("action_class", "lateral_movement") in cls, cmd
        assert ("lm_kind", "internal_scan") in cls, cmd


def test_command_variants_preserve_lateral_movement_kind():
    cases = {
        "/usr/bin/ssh   -i ./id_benchmark user@192.0.2.10 uptime": "ssh_pivot",
        "ssh  -N  -L 8443:internal:443 user@192.0.2.10": "tunnel",
        "/usr/bin/smbclient //192.0.2.10/share -c ls": "smb",
        "/usr/bin/masscan 192.0.2.0/30 -p443": "internal_scan",
    }
    for cmd, expected_kind in cases.items():
        cls = _bash(cmd)
        assert ("action_class", "lateral_movement") in cls, cmd
        assert ("lm_kind", expected_kind) in cls, cmd


def test_command_previews_are_not_lateral_movement():
    for cmd in (
        'echo "ssh user@192.0.2.10 uptime"',
        'printf "masscan 192.0.2.0/30 -p443\\n"',
        'echo "smbclient //192.0.2.10/share"',
    ):
        cls = _bash(cmd)
        assert ("action_class", "lateral_movement") not in cls, cmd
        assert classify_lm_kind(cmd) is None, cmd


def test_nmap_is_network_recon_not_lateral_movement():
    cls = _bash("nmap -sV 192.0.2.0/30")
    assert ("action_class", "reconnaissance") in cls
    assert ("action_class", "discovery") in cls
    assert ("action_class", "lateral_movement") not in cls


# --- recon suppression: a remote pivot is not local recon ---------------------

def test_ssh_pivot_suppresses_recon():
    cls = _bash("ssh user@host whoami")
    assert ("lm_kind", "ssh_pivot") in cls
    assert ("action_class", "reconnaissance") not in cls
    assert ("action_class", "discovery") not in cls


# --- boundaries: must NOT be lateral_movement ---------------------------------

def test_scp_rsync_stay_exfiltration():
    for cmd in ("scp file user@host:/tmp", "rsync -a data/ user@host:/backup"):
        cls = _bash(cmd)
        assert ("action_class", "exfiltration") in cls, cmd
        assert ("action_class", "lateral_movement") not in cls, cmd


def test_connects_stay_initial_access():
    for cmd in ("nc 10.0.0.5 9000", "telnet 10.0.0.5 23", "redis-cli -h 10.0.0.9"):
        cls = _bash(cmd)
        assert ("action_class", "initial_access") in cls, cmd
        assert ("action_class", "lateral_movement") not in cls, cmd


def test_sshpass_stays_brute_force_not_lateral():
    cls = _bash("sshpass -p pw ssh user@host")
    assert ("ia_kind", "brute_force") in cls
    assert ("action_class", "lateral_movement") not in cls


def test_ssh_keygen_and_version_are_not_lateral():
    assert classify_lm_kind("ssh-keygen -t ed25519 -f ./k") is None
    assert classify_lm_kind("ssh -V") is None
    assert classify_lm_kind("ssh-add ~/.ssh/id_rsa") is None
    assert classify_lm_kind("ssh-add -l") is None
    assert classify_lm_kind("ssh-agent -D") is None
    assert classify_lm_kind("ssh-keyscan -H example.com") is None


def test_ssh_agent_inventory_emits_no_lateral_movement_fact():
    cls = _bash("ssh-add -l")
    assert ("action_class", "lateral_movement") not in cls
    assert ("lm_kind", "tunnel") not in cls


def test_benign_controls_not_lateral():
    for cmd in ("git status", "ls -l", "cat package.json"):
        assert classify_lm_kind(cmd) is None, cmd


# --- precedence: tunnel before ssh_pivot --------------------------------------

def test_tunnel_precedence_over_pivot():
    assert classify_lm_kind("ssh -L 8443:internal:443 user@host") == "tunnel"
    assert classify_lm_kind("ssh -i key user@host uptime") == "ssh_pivot"
