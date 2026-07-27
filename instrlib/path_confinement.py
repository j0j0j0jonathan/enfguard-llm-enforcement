"""Realpath-aware workspace confinement — shared core.

Single source of truth for "does this tool's path resolve outside the
workspace?", used by:

  * ``instrlib.tool_mapper`` — to emit ``Classify(path_confinement, escape|inside)``
    at ingest (classify-first), and
  * ``bench/.../openclaw_live/discovery_predicates.py`` — whose
    ``resolved_path_outside_workspace`` predicate now delegates here, so the
    risky realpath code lives in exactly one place.

The check resolves the *physical* target with ``os.path.realpath`` and reports
whether it escapes the workspace root — which is what catches a symlink that a
raw-string prefix check would accept. ``path_sensitivity`` (apparent filename
class) and ``path_confinement`` (resolved physical target) are deliberately
separate concepts: a path can look public yet escape via symlink. The symlink
test is the proof both dimensions are needed.

Configuration (env, all optional; defaults reproduce the NanoClaw setup):
  ENFGUARD_NANOCLAW_GROUP_DIR  the group dir ``/workspace/group`` maps to and
                               that is treated as the workspace root.
  ENFGUARD_WS_HOST_ROOTS       comma-separated host roots counted as inside.
  ENFGUARD_WS_PREFIX_MAP       comma-separated ``virtual=host`` prefix pairs.

Fail-open: on any parse/IO error the functions report "inside" / not-escaping,
so a bug here never blocks benign traffic (matching the predicate's contract).
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Optional

_DEFAULT_GROUP_DIR = "/home/agent/workspace"


def _group_dir() -> str:
    return os.environ.get("ENFGUARD_NANOCLAW_GROUP_DIR", _DEFAULT_GROUP_DIR)


def _host_roots() -> list[str]:
    raw = os.environ.get("ENFGUARD_WS_HOST_ROOTS")
    roots = [r.strip() for r in raw.split(",")] if raw else [_group_dir()]
    out: list[str] = []
    for r in roots:
        if not r:
            continue
        try:
            out.append(os.path.realpath(r))
        except OSError:
            out.append(r.rstrip("/"))
    return out or [os.path.realpath(_group_dir())]


def _prefix_map() -> list[tuple[str, str]]:
    raw = os.environ.get("ENFGUARD_WS_PREFIX_MAP")
    if raw:
        pairs = []
        for item in raw.split(","):
            if "=" in item:
                v, h = item.split("=", 1)
                pairs.append((v.strip().rstrip("/"), h.strip().rstrip("/")))
    else:
        group = _group_dir().rstrip("/")
        pairs = [("/workspace/group", group), ("/workspace", group)]
    return sorted(pairs, key=lambda p: len(p[0]), reverse=True)


def _load_input(raw: str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    text = str(raw or "{}").strip()
    candidates = [text]
    if '\\"' in text:
        candidates.append(text.replace('\\"', '"'))
    if text.startswith("input:"):
        candidates.append(text.split("input:", 1)[1].strip())
    for candidate in candidates:
        try:
            data = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except json.JSONDecodeError:
                continue
        if isinstance(data, dict):
            return data
    return {}


def _path_field(raw: str | dict[str, Any]) -> str:
    data = _load_input(raw)
    for key in ("path", "file_path", "filename", "file", "filepath", "target"):
        value = data.get(key)
        if value is not None:
            return str(value)
    return ""


def _command_field(raw: str | dict[str, Any]) -> str:
    data = _load_input(raw)
    value = data.get("command") or data.get("cmd") or data.get("input") or ""
    return str(value)


_PATH_ASSIGN_RE = re.compile(
    r"(?:^|[;&|]|\s)([A-Za-z_]\w*)=((?:'[^']*'|\"[^\"]*\"|[^\s;|&])+)"
)
_PATH_VARREF_RE = re.compile(r"\$\{(\w+)\}|\$(\w+)")
_IFS_REF_RE = re.compile(r"\$\{IFS\}|\$IFS\b")


def _expand_path_vars(command: str) -> str:
    """Best-effort, execution-free expansion of ``VAR=…; … $VAR`` and ``${IFS}``
    so a path assembled into a variable (``P=/etc/passwd; cat $P``) or split with
    ``${IFS}`` is visible to the path tokenizer. Matching-only; never executed."""
    if "$" not in command:
        return command
    s = _IFS_REF_RE.sub(" ", command)
    varmap: dict[str, str] = {}
    for m in _PATH_ASSIGN_RE.finditer(s):
        val = m.group(2)
        if len(val) >= 2 and val[0] in "'\"" and val[-1] == val[0]:
            val = val[1:-1]
        varmap[m.group(1)] = val
    if varmap:
        s = _PATH_VARREF_RE.sub(
            lambda m: varmap.get(m.group(1) or m.group(2), m.group(0)), s
        )
    return s


_OUTPUT_PREVIEW_HEAD_RE = re.compile(r"^\s*(?:echo|printf)\b", re.IGNORECASE)


def _is_static_output_preview(command: str) -> bool:
    """Return True when echo/printf only prints text and performs no shell I/O.

    Operators inside ordinary quotes are literal text. Redirects, pipes,
    chaining, command substitutions, and backticks outside single quotes make
    the command active, so its path tokens must still be confinement-checked.
    """

    if not _OUTPUT_PREVIEW_HEAD_RE.match(command or ""):
        return False

    quote: str | None = None
    escaped = False
    i = 0
    while i < len(command):
        ch = command[i]
        if escaped:
            escaped = False
            i += 1
            continue
        if ch == "\\" and quote != "'":
            escaped = True
            i += 1
            continue
        if quote == "'":
            if ch == "'":
                quote = None
            i += 1
            continue
        if quote == '"':
            if ch == '"':
                quote = None
            elif ch == "`" or (ch == "$" and i + 1 < len(command) and command[i + 1] == "("):
                return False
            i += 1
            continue
        if ch in {"'", '"'}:
            quote = ch
        elif ch in "|;&<>\n`":
            return False
        elif ch == "$" and i + 1 < len(command) and command[i + 1] == "(":
            return False
        i += 1
    return True


_GREP_PATTERN_RE = re.compile(
    r"""\b(?:z?grep|z?egrep|z?fgrep|rg|ripgrep|ag|ack|findstr)\b"""
    r"""(?:\s+-{1,2}[^\s'"]+)*"""            # optional flags
    r"""\s+(?P<q>'[^']*'|"[^"]*")"""          # the quoted PATTERN argument
)


def _mask_grep_patterns(command: str) -> str:
    """Blank out the quoted PATTERN argument of grep-family commands.

    A grep pattern is a string to match, not a path the command opens, so a
    path-looking token inside it (`grep "node /tmp/x"`) must not be treated as a
    workspace access. Replacing the quoted pattern with spaces preserves every
    character position so the caller's index math is unaffected. Only grep
    patterns are masked, a quoted real command (`bash -c "..."`) is left intact.
    """
    out = command
    for gm in _GREP_PATTERN_RE.finditer(command):
        s, e = gm.start("q"), gm.end("q")
        out = out[:s] + (" " * (e - s)) + out[e:]
    return out


def _candidate_paths(tool: str, raw_input: str | dict[str, Any]) -> list[str]:
    """Collect path-like tokens to check, depending on the tool."""

    name = str(tool or "").lower().strip()
    paths: list[str] = []

    direct = _path_field(raw_input)
    if direct:
        paths.append(direct)

    # Search/glob tools: a pattern can carry a traversal prefix that escapes the
    # search root (e.g. "../../etc/**"). Take the literal directory prefix before
    # the first glob wildcard; if it is path-like, check it on its own and joined
    # onto the search root. A normal pattern ("**/.env*", "*.py") has an empty
    # prefix and adds nothing, so this never produces a false escape.
    data = _load_input(raw_input)
    pattern = data.get("pattern") or data.get("glob") or data.get("query") or ""
    if pattern:
        prefix = re.split(r"[*?\[]", str(pattern), 1)[0]
        if prefix and ("/" in prefix or prefix.startswith("..")):
            paths.append(prefix)
            if direct:
                paths.append(os.path.join(str(direct), prefix))

    if name in {"bash", "shell"} or (
        not direct and name not in {"file_read", "file_write", "file_delete", "file"}
    ):
        command = _command_field(raw_input)
        if command:
            command = _expand_path_vars(command)
            if _is_static_output_preview(command):
                return paths
            # A grep/search PATTERN is a string to search FOR, not a path the
            # command accesses, so a path inside it must not be extracted
            # (`ps aux | grep "node /tmp/dist/index.js"` does not touch /tmp).
            # Blank out only the quoted pattern of grep-family commands, so the
            # unquoted-token scans below skip it. A real command in quotes
            # (`bash -c "rm -rf /etc"`) is NOT masked and stays checked.
            scan = _mask_grep_patterns(command)
            for m in re.finditer(r"(?:(?<=\s)|^)((?:\.{0,2}/)[^\s'\";|&<>]+)", scan):
                # A token in COMMAND POSITION (start of a command segment) is the
                # executable being run, not a data file the command accesses, so it
                # is not a workspace escape (`/usr/bin/python3 -m pip …`). An
                # executable's ARGUMENT (`bash /fixtures/cleanup.sh`, `cat /etc/x`)
                # is still extracted.
                before = scan[: m.start(1)].rstrip()
                if before == "" or before.endswith(("|", "&", ";", "(", "`", "{")):
                    continue
                paths.append(m.group(1))
            for token in re.findall(r"(?:(?<=\s)|^)([A-Za-z0-9_.\-]+/[^\s'\";|&<>]+)", scan):
                if not token.startswith(("http://", "https://", "-")):
                    paths.append(token)
            # Quoted path tokens — a quote breaks the whitespace-anchored regexes
            # above, so `cat "/etc/passwd"` would otherwise escape extraction.
            # Pull any quoted absolute/relative path directly.
            for token in re.findall(r"""['"]((?:\.{0,2}/|/|~/)[^'"]+)['"]""", command):
                paths.append(token)

    seen: set[str] = set()
    out: list[str] = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _url_unescape(s: str) -> str:
    """Decode the common percent-encodings used to hide path traversal.

    ``/app/%2e%2e/%2e%2e/etc/passwd`` becomes ``/app/../../etc/passwd`` so the
    realpath check resolves the traversal. Only the dot and slash encodings are
    decoded, which is all that matters for path confinement."""
    for enc, dec in (("%2e", "."), ("%2E", "."), ("%2f", "/"), ("%2F", "/")):
        s = s.replace(enc, dec)
    return s


def _to_host_path(path: str, prefix_map: list[tuple[str, str]], roots: list[str]) -> str:
    clean = _url_unescape(path.strip().strip("'\"").replace("\\", "/"))
    for vprefix, hroot in prefix_map:
        if clean == vprefix:
            return hroot
        if clean.startswith(vprefix + "/"):
            return os.path.join(hroot, clean[len(vprefix) + 1:])
    if clean.startswith("/"):
        return clean
    return os.path.join(roots[0], clean)


def _inside_any_root(resolved: str, roots: list[str]) -> bool:
    for root in roots:
        if resolved == root or resolved.startswith(root + os.sep):
            return True
    return False


# Benign pseudo-devices: I/O sinks/sources that are not workspace files, so
# reading/writing them (`curl -o /dev/null`, `2>/dev/null`, `cat /dev/urandom`)
# is NOT a workspace escape. Real block devices (/dev/sdX, /dev/nvmeX) are NOT
# exempt — their destruction stays caught by Impact + confinement. Mirrors the
# pseudo-device set the Impact classifier already excludes.
_BENIGN_PSEUDO_DEV_RE = re.compile(
    r"^/dev/(?:null|zero|full|random|urandom|stdin|stdout|stderr|tty|fd/\d+"
    r"|tcp/.*|udp/.*)$"
)


def _is_benign_pseudo_device(path: str) -> bool:
    return bool(_BENIGN_PSEUDO_DEV_RE.match((path or "").strip()))


def _escapes_workspace(path: str, prefix_map: list[tuple[str, str]], roots: list[str]) -> bool:
    if _is_benign_pseudo_device(path):
        return False
    try:
        resolved = os.path.realpath(_to_host_path(path, prefix_map, roots))
    except OSError:
        return False
    return not _inside_any_root(resolved, roots)


def path_escapes_workspace(tool: str, raw_input: str | dict[str, Any]) -> bool:
    """True if any referenced path resolves (via realpath) outside the workspace.

    Strict superset of a raw-string prefix check: also true for a plain
    ``/etc/passwd``-style absolute path, but its reason for existing is the
    symlink/``..`` case a string check misses.
    """

    try:
        roots = _host_roots()
        prefix_map = _prefix_map()
        for candidate in _candidate_paths(tool, raw_input):
            if _escapes_workspace(candidate, prefix_map, roots):
                return True
        return False
    except Exception:
        return False


def resolved_target_paths(tool: str, raw_input: str | dict[str, Any]) -> list[str]:
    """Return the realpath-resolved host path for each path-like token.

    Best-effort: resolves every candidate path the same way the confinement
    check does (virtual→host prefix map, then ``os.path.realpath``), so a
    classifier downstream sees where a path *physically* points — which is what
    catches a workspace symlink aimed at a persistence target like
    ``~/.ssh/authorized_keys``. Falls back to the apparent token on per-path
    error and to an empty list on any outer error (fail-open, never raises).
    """

    out: list[str] = []
    try:
        roots = _host_roots()
        prefix_map = _prefix_map()
        for candidate in _candidate_paths(tool, raw_input):
            try:
                out.append(os.path.realpath(_to_host_path(candidate, prefix_map, roots)))
            except OSError:
                out.append(candidate)
    except Exception:
        return out
    return out


def workspace_roots() -> list[str]:
    """Resolved host workspace root(s) that confinement treats as 'inside'."""
    return _host_roots()


def workspace_roots_exist() -> bool:
    """True if at least one configured workspace root exists on disk.

    When this is False, confinement fails OPEN: a ``/workspace/...`` path is
    compared against a root that does not exist, so a symlink escape can go
    undetected. The proxy surfaces this at boot so a misconfigured
    ENFGUARD_NANOCLAW_GROUP_DIR / ENFGUARD_WS_HOST_ROOTS is visible rather than
    silently weakening enforcement.
    """
    try:
        return any(os.path.isdir(r) for r in _host_roots())
    except Exception:
        return False


# ---------------------------------------------------------------------------
# System-info read allowlist
#
# A coding agent legitimately reads a few root-owned, read-only, secret-free
# system files for environment detection (CPU count, RAM, container/OS).  These
# resolve OUTSIDE the workspace, so plain confinement flags them as an escape and
# the policy blocks an otherwise-benign read.  This allowlist exempts an EXACT,
# closed set of such files from the escape→block rule — and nothing else.
#
# Safety invariants (every one is required for an exemption):
#   * EXACT match on the *normalized literal* path (``os.path.normpath`` collapses
#     ``..`` and ``_url_unescape`` decodes %2e/%2f), never a prefix or glob — so a
#     traversal like ``/proc/cpuinfo/../../etc/shadow`` normalizes to ``/etc/shadow``
#     and is NOT exempt.  The entries are root-owned kernel/OS files an unprivileged
#     agent cannot repoint, so a workspace symlink cannot masquerade as one.
#   * A DENY sentinel (checked on the normalized literal) hard-blocks secrets,
#     credentials, env dumps, per-PID and network introspection even if a future
#     edit mistakenly adds them to the allow/warn sets.
#   * READ context only: writes/edits/deletes and redirections INTO the path are
#     never exempt.
#   * If a command references several escaping paths, ALL must be allowlisted —
#     one non-listed escape leaves the whole call an escape (→ block).
# Two tiers: ``allow`` (no recon value) and ``warn`` (mild recon → allow-with-warn).
_SYS_READ_ALLOW = frozenset({
    "/proc/cpuinfo", "/proc/meminfo", "/proc/loadavg", "/proc/uptime",
    "/proc/version", "/proc/stat", "/proc/self/cgroup", "/proc/self/mountinfo",
    "/proc/self/ns",  # namespace listing, containerization info, benign like cgroup
    "/etc/os-release", "/etc/lsb-release", "/etc/debian_version",
    "/etc/alpine-release", "/etc/redhat-release",
})
_SYS_READ_WARN = frozenset({
    "/etc/resolv.conf", "/proc/self/status",
})
# Never exempt, whatever the allow/warn sets say. Matched on the normalized
# literal path: password/secret stores, SSH keys, env dumps (which leak tokens),
# per-PID introspection (read another process), and kernel/network recon.
_SYS_READ_DENY_RE = re.compile(
    r"(?:^|/)(?:shadow|gshadow|sudoers|passwd|group|master\.passwd)$"
    r"|/\.ssh/|id_rsa|id_dsa|id_ecdsa|id_ed25519"
    r"|/environ$"
    r"|/proc/\d+/"
    r"|/proc/net/|/etc/ssh/|/proc/kcore|/proc/kallsyms|/proc/sched_debug"
)
# Pure read verbs: the leading simple-command word for a bash exemption.
_SYS_READ_VERBS = frozenset({
    "cat", "head", "tail", "less", "more", "grep", "egrep", "fgrep", "zgrep",
    "wc", "stat", "file", "od", "xxd", "hexdump", "cut", "awk", "nl", "tac",
    "sort", "uniq", "strings", "readlink", "realpath", "ls", "column", "cmp",
    "diff", "tr", "sed",
})


def _normalize_literal(path: str) -> str:
    """Decode + collapse a path to its normalized ABSOLUTE literal, or '' if it is
    not an absolute path (only absolute system paths are allowlistable)."""
    s = _url_unescape((path or "").strip().strip("'\"").replace("\\", "/"))
    if not s.startswith("/"):
        return ""
    return os.path.normpath(s)


def _bash_reads_path_readonly(command: str, token: str) -> bool:
    """True only if ``command`` is a read of ``token`` (no write/redirect into it
    and the leading verb is a pure reader). Conservative by design."""
    cmd = command or ""
    esc = re.escape(token)
    if re.search(r">>?\s*['\"]?" + esc, cmd):       # redirect INTO the path
        return False
    if re.search(r"\btee\b[^|;&\n]*" + esc, cmd):    # tee writes to it
        return False
    parts = cmd.strip().split()
    if not parts:
        return False
    verb = os.path.basename(parts[0])
    if verb == "sed" and any(a.startswith("-i") for a in parts[1:]):
        return False                                  # in-place edit is a write
    return verb in _SYS_READ_VERBS


def system_read_allow_label(tool: str, raw_input: str | dict[str, Any]) -> Optional[str]:
    """Return ``"allow"`` / ``"warn"`` if EVERY workspace-escaping path in this
    tool call is an exact, read-only, allowlisted system-info file (warn tier wins
    if any is warn); else ``None`` (the escape stands and the policy blocks).

    Fail-closed for the exemption: any uncertainty returns ``None`` so confinement
    is never weakened — at worst a benign system read stays blocked, never the
    reverse."""
    try:
        name = str(tool or "").lower().strip()
        if name in {"file_write", "file_delete", "file_editor"}:
            return None
        roots = _host_roots()
        prefix_map = _prefix_map()
        escaping = [
            p for p in _candidate_paths(tool, raw_input)
            if _escapes_workspace(p, prefix_map, roots)
        ]
        if not escaping:
            return None
        command = _command_field(raw_input)
        is_bash = name in {"bash", "shell"} or bool(command)
        tier = "allow"
        for token in escaping:
            norm = _normalize_literal(token)
            if not norm or _SYS_READ_DENY_RE.search(norm):
                return None
            if norm in _SYS_READ_ALLOW:
                t = "allow"
            elif norm in _SYS_READ_WARN:
                t = "warn"
            else:
                return None                            # an escape that is not allowlisted
            if is_bash:
                if not _bash_reads_path_readonly(command, token):
                    return None
            elif name not in {"file_read", "file", "read"}:
                return None
            if t == "warn":
                tier = "warn"
        return tier
    except Exception:
        return None


def confinement_label(tool: str, raw_input: str | dict[str, Any]) -> Optional[str]:
    """Return ``"escape"`` / ``"inside"`` / ``None``.

    ``None`` means there was no path-like token to check (so the caller should
    emit no ``path_confinement`` fact). ``"escape"`` if any referenced path
    resolves outside the workspace; otherwise ``"inside"``.
    """

    try:
        roots = _host_roots()
        prefix_map = _prefix_map()
        candidates = _candidate_paths(tool, raw_input)
        if not candidates:
            return None
        for candidate in candidates:
            if _escapes_workspace(candidate, prefix_map, roots):
                return "escape"
        return "inside"
    except Exception:
        return None
