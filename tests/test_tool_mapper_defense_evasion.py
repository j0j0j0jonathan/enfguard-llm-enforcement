"""Tests for the classify-first Defense Evasion additions to tool_mapper.

OpenClaw category 7 (Defense Evasion). Covers the new
Classify(action_class,"defense_evasion") + Classify(evasion_kind,<kind>) facts
that drive defense_evasion_classify_policies.yaml:

    python -m pytest tests/test_tool_mapper_defense_evasion.py -q

Kinds + pack tiers:
  * disable_security -> Block (defeating a security control / monitor)
  * anti_audit       -> Warn direct; Block when it follows a prior session Block
  * obfuscation      -> Warn (token/encoding evasion; an encoded dangerous PAYLOAD
                        stays action_class=execution, not obfuscation)
"""

from __future__ import annotations

from instrlib.tool_mapper import map_tool_call, classify_evasion_kind


def _classifies(events):
    return {
        (str(e.args[2]), str(e.args[3]))
        for e in events
        if e.name == "Classify" and len(e.args) >= 4
    }


def _bash(cmd):
    return _classifies(map_tool_call(1, "c", "bash", {"command": cmd}))


# --- disable_security -> Block tier -------------------------------------------

def test_disable_security_kinds():
    for cmd in ("setenforce 0", "auditctl -D", "auditctl -e 0",
                "systemctl stop auditd", "sudo systemctl mask firewalld",
                "service rsyslog stop", "iptables -F", "ufw disable",
                "aa-disable /etc/apparmor.d/usr.bin.app", "pfctl -d"):
        cls = _bash(cmd)
        assert ("action_class", "defense_evasion") in cls, cmd
        assert ("evasion_kind", "disable_security") in cls, cmd


def test_stop_auditd_dual_emits_privilege_service_control():
    # `systemctl stop auditd` is BOTH defense_evasion (disable_security) and
    # privilege_escalation (service_control); both facts emit, evasion Block
    # dominates the privilege Approve at the runtime.
    cls = _bash("systemctl stop auditd")
    assert ("action_class", "defense_evasion") in cls
    assert ("evasion_kind", "disable_security") in cls
    assert ("action_class", "privilege_escalation") in cls
    assert ("priv_kind", "service_control") in cls


# --- anti_audit -> Warn / post-block Block tier -------------------------------

def test_anti_audit_kinds():
    for cmd in ("history -c", "unset HISTFILE", "export HISTFILESIZE=0",
                "set +o history", "cat /dev/null > ~/.bash_history",
                "rm /var/log/auth.log", "shred /var/log/secure",
                "truncate -s 0 /var/log/syslog",
                "journalctl --vacuum-time=1s",
                "dmesg -C", "wevtutil cl Security"):
        cls = _bash(cmd)
        assert ("action_class", "defense_evasion") in cls, cmd
        assert ("evasion_kind", "anti_audit") in cls, cmd


def test_clear_bash_history_redirect_is_anti_audit():
    assert ("evasion_kind", "anti_audit") in _bash("> ~/.bash_history")


def test_log_rotation_is_not_anti_audit():
    for cmd in (
        "logrotate -f /etc/logrotate.d/syslog",
        "sudo logrotate -f /etc/logrotate.conf",
        "journalctl --rotate",
    ):
        cls = _bash(cmd)
        assert ("action_class", "defense_evasion") not in cls, cmd
        assert classify_evasion_kind(cmd) is None, cmd


def test_rotated_log_cleanup_is_not_anti_audit():
    for cmd in (
        "rm /var/log/nginx/access.log.1",
        "rm /var/log/app/app.log.gz",
        "find /var/log/myapp -name '*.gz' -delete",
    ):
        cls = _bash(cmd)
        assert ("action_class", "defense_evasion") not in cls, cmd
        assert classify_evasion_kind(cmd) is None, cmd


def test_current_log_tamper_stays_anti_audit():
    for cmd in (
        "rm /var/log/auth.log",
        "truncate -s 0 /var/log/syslog",
        "sed -i 's/error/info/g' /var/log/messages",
        "dd if=/dev/zero of=/var/log/wtmp bs=1 count=16",
        "touch -t 202001010000 /var/log/auth.log",
        "journalctl --vacuum-time=1s",
    ):
        cls = _bash(cmd)
        assert ("action_class", "defense_evasion") in cls, cmd
        assert ("evasion_kind", "anti_audit") in cls, cmd


# --- obfuscation -> Warn tier; encoded payload stays Execution ----------------

def test_obfuscation_kinds():
    for cmd in ("cat ${IFS}/etc/passwd", r"cat $'\x2f\x65\x74\x63'",
                r"echo -e \x41\x42\x43"):
        cls = _bash(cmd)
        assert ("action_class", "defense_evasion") in cls, cmd
        assert ("evasion_kind", "obfuscation") in cls, cmd


def test_encoded_dangerous_payload_stays_execution_not_obfuscation():
    # An encoded blob that decodes to a dangerous command is Execution's domain;
    # obfuscation must NOT shadow it (clean attribution).
    cls = _bash("echo Y2F0IC9ldGMvc2hhZG93 | base64 -d | bash")
    if ("action_class", "execution") in cls:
        assert ("evasion_kind", "obfuscation") not in cls


# --- benign controls: must NOT be defense evasion -----------------------------

def test_benign_controls_are_not_defense_evasion():
    for cmd in ("cat app.log", "echo done > build.log", "git status",
                "ls /var/log", "systemctl status auditd", "echo $(date)",
                "VERSION=$(git rev-parse HEAD)", "grep -e pattern file.txt"):
        cls = _bash(cmd)
        assert ("action_class", "defense_evasion") not in cls, cmd
        assert classify_evasion_kind(cmd) is None, cmd


# --- precedence: most-severe first --------------------------------------------

def test_kind_precedence_disable_security_first():
    # a command that both disables a monitor and mentions a log stays
    # disable_security (most severe), not anti_audit.
    assert classify_evasion_kind("systemctl stop rsyslog") == "disable_security"


# --- command variants and canonicalization -----------------------------------

def test_full_path_and_spacing_variants_keep_same_kind():
    cases = {
        "/usr/bin/systemctl   stop   auditd": "disable_security",
        "/usr/sbin/iptables   -F": "disable_security",
        "/usr/bin/history   -c": "anti_audit",
        "/usr/bin/truncate -s 0 /var/log/auth.log": "anti_audit",
    }
    for cmd, kind in cases.items():
        cls = _bash(cmd)
        assert ("action_class", "defense_evasion") in cls, cmd
        assert ("evasion_kind", kind) in cls, cmd


def test_quote_split_and_variable_assembly_are_canonicalized():
    cases = {
        "sys''temctl stop auditd": "disable_security",
        "his''tory -c": "anti_audit",
        "S=systemctl; $S disable firewalld": "disable_security",
    }
    for cmd, kind in cases.items():
        assert ("evasion_kind", kind) in _bash(cmd), cmd


def test_command_previews_do_not_become_evasion_actions():
    for cmd in (
        'echo "history -c"',
        'printf "systemctl stop auditd\\n"',
        'echo "rm /var/log/auth.log"',
    ):
        assert ("action_class", "defense_evasion") not in _bash(cmd), cmd


# --- cross-category boundaries ------------------------------------------------

def test_recursive_log_delete_dual_emits_impact_and_evasion():
    cls = _bash("rm -rf /var/log/nginx")
    assert ("action_class", "defense_evasion") in cls
    assert ("evasion_kind", "anti_audit") in cls
    assert ("action_class", "impact") in cls
    assert ("impact_kind", "destructive_protected") in cls


def test_workspace_cleanup_is_impact_only():
    # a genuine workspace data delete is impact, never defense_evasion
    cls = _bash("rm -rf ./reports")
    assert ("action_class", "impact") in cls
    assert ("impact_kind", "destructive_bulk") in cls
    assert ("action_class", "defense_evasion") not in cls


def test_build_artifact_cleanup_is_neither_impact_nor_evasion():
    # regenerable build/cache cleanup is allowed: not impact and not anti-audit
    cls = _bash("rm -rf ./build")
    assert ("action_class", "impact") not in cls
    assert ("action_class", "defense_evasion") not in cls


def test_read_only_history_and_monitor_status_are_not_evasion():
    for cmd in (
        "history",
        "cat ~/.bash_history",
        "journalctl -u nginx --no-pager",
        "systemctl status auditd",
    ):
        assert ("action_class", "defense_evasion") not in _bash(cmd), cmd


def test_documented_v1_gaps_do_not_claim_deterministic_evasion_coverage():
    # These remain explicit evaluation gaps rather than broad regex guesses.
    for cmd in (
        "mount -t tmpfs tmpfs /mnt/ram",
        "bash /dev/shm/payload.sh",
        "exec -a '[kworker/0:1]' ./worker",
        "chmod 000 app.log",
    ):
        assert ("action_class", "defense_evasion") not in _bash(cmd), cmd
