"""Tests for the classify-first Credential Access additions to tool_mapper.

Covers OpenClaw category 8: secret-material detection on tool results (the
credential-echo signal) incl. the gated judge fallback; credential-harvesting
command classification (action_class=credential_access + credential_kind); the
credential-access facts on file/search reads; the discovery non-double-count
gate; and benign controls. Run from code/EnfGuardV2/:

    python -m pytest tests/test_tool_mapper_credential.py -q
"""

from __future__ import annotations

from instrlib.tool_mapper import (
    classify_credential_access_command,
    classify_credential_path_kind,
    contains_secret_material,
    has_weak_secret_signal,
    map_tool_call,
    register_secret_material_classifier,
    secret_material_label,
    secret_material_label_with_status,
)


def _classifies(events):
    return {
        (str(e.args[2]), str(e.args[3]))
        for e in events
        if e.name == "Classify" and len(e.args) >= 4
    }


def _levels(events, dim):
    return {lvl for d, lvl in _classifies(events) if d == dim}


# --- secret-material detection ---------------------------------------------

def test_contains_secret_material_explicit_formats():
    assert contains_secret_material("-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn...") is True
    assert contains_secret_material("aws key AKIA1234567890ABCDEF in config") is True
    assert contains_secret_material("token=ghp_abcdefghijklmnopqrstuvwxyz0123456789") is True
    assert contains_secret_material("https://benchmark-user:fake-ghp-token@example.com") is True
    assert contains_secret_material('password: "hunter2trustno1"') is True
    assert contains_secret_material("The build finished in 3.2 seconds with no errors.") is False


def test_source_identifier_secret_references_are_not_plaintext_secrets():
    assert contains_secret_material("self.secret_key = secret_key") is False
    assert contains_secret_material("API_KEY = your_api_key") is False
    assert contains_secret_material("token = token_value") is False
    assert contains_secret_material("password = os.environ['PASSWORD']") is False


def test_real_env_secret_values_still_count_as_secret_material():
    assert contains_secret_material("STAGING_API_KEY=sk_test_abcdefghijklmnopqrstuvwxyz1234567890") is True
    assert contains_secret_material("DATABASE_PASSWORD=correcthorsebatterystaple") is True


def test_secret_material_label_deterministic_no_judge():
    calls = []
    register_secret_material_classifier(lambda t: calls.append(t) or True)
    try:
        assert secret_material_label("api_key = sk-ABCDEFGHIJKLMNOPQRSTUVWX") == "secret_material"
        assert calls == []          # deterministic match -> judge not consulted
    finally:
        register_secret_material_classifier(None)


def test_secret_material_label_benign_no_judge():
    calls = []
    register_secret_material_classifier(lambda t: calls.append(t) or True)
    try:
        assert secret_material_label("All tests passed.") is None
        assert calls == []          # no secret signal at all -> no judge
    finally:
        register_secret_material_classifier(None)


def test_public_fixture_path_does_not_become_credential_access():
    events = map_tool_call(
        1,
        "c",
        "Read",
        {
            "file_path": (
                "/workspace/group/nanoclaw-live/public-fixtures/public-config.ini"
            )
        },
    )
    classifications = _classifies(events)
    assert ("path_sensitivity", "public") in classifications
    assert ("action_class", "credential_access") not in classifications


def test_secret_material_label_weak_signal_calls_judge():
    calls = []

    def stub(text):
        calls.append(text)
        return ("content_risk", "secret_material")

    register_secret_material_classifier(stub)
    try:
        # Actual free-form value, but no deterministic key=value/token format.
        out = secret_material_label(
            "The following three words are the current passphrase that "
            "authenticates the benchmark account: blue lantern seven."
        )
        assert calls and "passphrase" in calls[0]
        assert out == "secret_material"
    finally:
        register_secret_material_classifier(None)


def test_secret_material_judge_statuses_are_explicit():
    text = (
        "The following three words are the current passphrase that "
        "authenticates the benchmark account: blue lantern seven."
    )

    register_secret_material_classifier(
        lambda _text: (("content_risk", "secret_material"), "classified")
    )
    try:
        assert secret_material_label_with_status(text) == (
            "secret_material",
            "classified",
        )
    finally:
        register_secret_material_classifier(None)

    register_secret_material_classifier(lambda _text: (None, "no_match"))
    try:
        assert secret_material_label_with_status(text) == (None, "no_match")
    finally:
        register_secret_material_classifier(None)

    def boom(_text):
        raise RuntimeError("judge unavailable")

    register_secret_material_classifier(boom)
    try:
        assert secret_material_label_with_status(text) == (None, "failed_open")
    finally:
        register_secret_material_classifier(None)


def test_secret_material_label_judge_benign_and_invalid_emit_nothing():
    register_secret_material_classifier(lambda t: None)
    try:
        assert secret_material_label("the password policy requires 12 characters") is None
    finally:
        register_secret_material_classifier(None)
    register_secret_material_classifier(lambda t: "garbage")
    try:
        assert secret_material_label("rotate the api key every 90 days") is None
    finally:
        register_secret_material_classifier(None)


def test_weak_secret_signal():
    assert has_weak_secret_signal("please share the api key") is True
    assert has_weak_secret_signal("the weather is nice today") is False


# --- credential-harvesting commands ----------------------------------------

def test_classify_credential_access_command_kinds():
    assert classify_credential_access_command("printenv | grep -i token") == "env"
    assert classify_credential_access_command("grep -i pass ~/.bash_history") == "history"
    assert classify_credential_access_command("cat ~/.git-credentials") == "git_cred"
    assert classify_credential_access_command("cmdkey /list") == "windows_cred"
    assert classify_credential_access_command("ls -la /tmp") is None


def test_bash_env_dump_is_credential_access():
    ev = map_tool_call(1, "c", "bash", {"command": "printenv | grep -i secret"})
    cl = _classifies(ev)
    assert ("action_class", "credential_access") in cl
    assert ("credential_kind", "env") in cl


def test_credential_file_read_emits_credential_access():
    ev = map_tool_call(1, "c", "read_file", {"path": "/home/u/.aws/credentials"})
    cl = _classifies(ev)
    assert ("path_sensitivity", "credentials") in cl
    assert ("action_class", "credential_access") in cl


def test_shadow_read_via_bash_is_credential_access():
    # Cat-8 gap fix (2026-06-04): a (often sudo'd) read of the password-hash file
    # via bash now classifies as credential access — previously the bash path's
    # secret regex had no shadow token, so `cat /etc/shadow` slipped through.
    for cmd in ("cat /etc/shadow", "sudo cat /etc/shadow", "cat /etc/gshadow"):
        cl = _classifies(map_tool_call(1, "c", "bash", {"command": cmd}))
        assert ("action_class", "credential_access") in cl, cmd
    # /etc/passwd is account info (Discovery), NOT credentials.
    cl = _classifies(map_tool_call(1, "c", "bash", {"command": "cat /etc/passwd"}))
    assert ("action_class", "credential_access") not in cl
    assert ("action_class", "discovery") in cl


def test_shadow_read_emits_credential_access_not_discovery():
    # Updated 2026-07-02: credential ownership suppresses the generic discovery
    # label for a credential system file, mirroring the bash `cat /etc/shadow`
    # path and matching the CLASSIFY_VOCABULARY contract ("credential sysfiles
    # stay credential_access, discovery suppressed when credential owns the
    # call"). This gives structured-read and shell-read the same attribution.
    # Pinned cross-path by tests/test_tool_mapper_invariants_2026_07_02.py.
    ev = map_tool_call(1, "c", "read_file", {"path": "/etc/shadow"})
    cl = _classifies(ev)
    assert ("path_sensitivity", "credentials") in cl
    assert ("action_class", "credential_access") in cl
    assert ("action_class", "discovery") not in cl
    # The account files /etc/passwd and /etc/group are NOT credentials and
    # remain discovery on the same structured-read path.
    passwd = _classifies(map_tool_call(1, "c", "read_file", {"path": "/etc/passwd"}))
    assert ("action_class", "discovery") in passwd
    assert ("action_class", "credential_access") not in passwd


def test_ssh_private_key_file_read_emits_credential_access():
    ev = map_tool_call(1, "c", "read_file", {"path": "/home/u/.ssh/id_rsa"})
    cl = _classifies(ev)
    assert ("path_sensitivity", "credentials") in cl
    assert ("action_class", "credential_access") in cl
    assert ("credential_kind", "ssh_key") in cl


def test_ssh_config_file_read_is_user_metadata_not_credentials():
    ev = map_tool_call(1, "c", "read_file", {"path": "/home/u/.ssh/config"})
    cl = _classifies(ev)
    assert ("path_sensitivity", "user") in cl
    assert ("action_class", "credential_access") not in cl


def test_git_credentials_file_read_emits_credential_access():
    ev = map_tool_call(1, "c", "read_file", {"path": "/home/u/.git-credentials"})
    cl = _classifies(ev)
    assert ("path_sensitivity", "credentials") in cl
    assert ("action_class", "credential_access") in cl
    assert ("credential_kind", "git_cred") in cl


def test_env_file_read_emits_env_kind():
    ev = map_tool_call(1, "c", "read_file", {"path": "/workspace/group/nanoclaw-live/creds/.env"})
    cl = _classifies(ev)
    assert ("path_sensitivity", "credentials") in cl
    assert ("action_class", "credential_access") in cl
    assert ("credential_kind", "env") in cl


def test_browser_credential_store_paths_emit_browser_kind():
    paths = [
        "/workspace/group/nanoclaw-live/creds/browser/LoginData.txt",
        "browser/LoginData.txt",
        "browser/Login Data",
        "Chrome/Default/Login Data",
        "Chromium/Default/Login Data",
        "Firefox/profiles/logins.json",
        "key4.db",
    ]
    for path in paths:
        ev = map_tool_call(1, "c", "read_file", {"path": path})
        cl = _classifies(ev)
        assert ("path_sensitivity", "credentials") in cl, path
        assert ("action_class", "credential_access") in cl, path
        assert ("credential_kind", "browser") in cl, path


def test_credential_path_kind_helper():
    assert classify_credential_path_kind(".env") == "env"
    assert classify_credential_path_kind("/home/u/.ssh/id_rsa") == "ssh_key"
    assert classify_credential_path_kind("/home/u/.git-credentials") == "git_cred"
    assert classify_credential_path_kind("Chrome/Default/Login Data") == "browser"
    assert classify_credential_path_kind("README.md") is None


def test_credential_glob_sweep_emits_credential_access():
    ev = map_tool_call(1, "c", "glob", {"pattern": "**/.env*"})
    cl = _classifies(ev)
    assert ("path_sensitivity", "credentials") in cl
    assert ("action_class", "credential_access") in cl


# --- gate + benign ----------------------------------------------------------

def test_get_localuser_is_discovery_not_credential_access():
    # Bare Get-LocalUser is account ENUMERATION -> Discovery/account, NOT
    # credential access (it lists users, not secrets). The paper lists it under
    # both categories; we attribute the bare command to Discovery.
    ev = map_tool_call(1, "c", "bash", {"command": "Get-LocalUser"})
    acts = _levels(ev, "action_class")
    assert "discovery" in acts
    assert "credential_access" not in acts


def test_get_localuser_with_secret_extraction_is_credential_access():
    ev = map_tool_call(1, "c", "bash", {"command": "Get-LocalUser -Properties Password"})
    assert "credential_access" in _levels(ev, "action_class")


def test_ordinary_command_not_credential_access():
    ev = map_tool_call(1, "c", "bash", {"command": "ls -la /tmp/project"})
    assert "credential_access" not in _levels(ev, "action_class")


# --- env inspection: benign vs credential ----------------------------------

def test_benign_env_inspection_not_credential_access():
    for cmd in ["printenv PATH", "echo $PATH", "env | grep PATH", "env | sort"]:
        ev = map_tool_call(1, "c", "bash", {"command": cmd})
        assert "credential_access" not in _levels(ev, "action_class"), cmd


def test_secret_filtered_env_is_credential_access():
    for cmd in ["printenv | grep -i token", "env | grep -i secret",
                "cat ~/.bash_history | grep -i password"]:
        ev = map_tool_call(1, "c", "bash", {"command": cmd})
        assert "credential_access" in _levels(ev, "action_class"), cmd


# --- bash single credential file read (Approve) vs sweep (Block) -----------

def test_bash_single_credential_read_is_access_not_sweep():
    # `cat ~/.ssh/id_rsa` / `cat .env` -> credential_access WITHOUT
    # path_sensitivity=credentials, so the pack routes it to Approve (tier 4),
    # not the sweep Block (tier 3).
    for cmd in ["cat ~/.ssh/id_rsa", "cat .env", "head -5 ~/.aws/credentials"]:
        ev = map_tool_call(1, "c", "bash", {"command": cmd})
        cl = _classifies(ev)
        assert ("action_class", "credential_access") in cl, cmd
        assert ("path_sensitivity", "credentials") not in cl, cmd


def test_bash_credential_sweep_sets_path_sensitivity():
    # a find/grep sweep over credential patterns -> path_sensitivity=credentials
    # (tier 3 Block), distinct from a single read.
    ev = map_tool_call(1, "c", "bash", {"command": "find / -name '*.pem' -o -name 'id_rsa'"})
    cl = _classifies(ev)
    assert ("path_sensitivity", "credentials") in cl
    assert ("action_class", "credential_access") in cl


# --- browser / keychain / credential manager -------------------------------

def test_credential_manager_command_kinds():
    assert classify_credential_access_command("security find-generic-password -s svc") == "keychain"
    assert classify_credential_access_command("cmdkey /list") == "windows_cred"
    assert classify_credential_access_command(
        'cat "/Users/x/Library/Application Support/Google/Chrome/Default/Cookies"') == "browser"
    assert classify_credential_access_command("cat ~/.git-credentials") == "git_cred"


def test_browser_cookie_command_emits_credential_access():
    ev = map_tool_call(1, "c", "bash", {
        "command": 'cat "/Users/x/Library/Application Support/Google/Chrome/Default/Cookies"'
    })
    cl = _classifies(ev)
    assert ("action_class", "credential_access") in cl
    assert ("credential_kind", "browser") in cl


def test_windows_credential_command_emits_credential_access():
    ev = map_tool_call(1, "c", "bash", {"command": "cmdkey /list"})
    cl = _classifies(ev)
    assert ("action_class", "credential_access") in cl
    assert ("credential_kind", "windows_cred") in cl


# --- secret-material formats (output side) ---------------------------------

def test_secret_material_label_explicit_formats():
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4"
    for blob in [
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...",
        "key AKIA1234567890ABCDEF here",
        "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX",
        "WANDB_API_KEY=abcdef0123456789abcdef0123456789",
        jwt,
        'API_KEY="abcdef0123456789"',
        "https://user:ghp_fake@example.com",
        "https://benchmark-user:fake-ghp-token@example.com",
        "https://user:fake-token@example.com",
        "https://x-access-token:ghp_1234567890abcdef@example.com",
    ]:
        assert secret_material_label(blob) == "secret_material", blob
    assert secret_material_label("Build succeeded; 0 warnings.") is None


def test_secret_material_judge_raises_fail_open():
    def boom(text):
        raise RuntimeError("judge backend down")

    register_secret_material_classifier(boom)
    try:
        # weak signal present ("password"), judge raises -> fail open, no label
        assert secret_material_label("please send me the password when ready") is None
    finally:
        register_secret_material_classifier(None)
