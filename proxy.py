"""FastAPI two-phase enforcement proxy for EnfGuard v2.

runnable backend spine: Anthropic Messages,OpenAI-compatible Chat and Ollama, mappings and
handlers only see the two canonical chat formats.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shutil
import threading
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from batch_judge import pre_evaluate
from chat_text import estimate_tokens as _estimate_tokens
from config import (
    CONFIG,
    DEFAULT_ENFGUARD_BIN,
    RuntimeConfig,
    cors_allow_origins,
    ensure_runtime_dirs,
)
from event_schema import build_event_schema
from feedback import make_feedback_event
from handlers import (
    NormalizedResponse,
    handle_block_request,
    handle_block_response,
    handle_warn_request,
    handle_warn_response,
    merge_warning_message,
    normalize_anthropic,
    normalize_openai,
    serialize_anthropic,
    serialize_openai,
    surface_warning_on_block,
    synthetic_anthropic,
    synthetic_openai,
)
from instrlib import PEP, Enforcer, Event, Logger
from instrlib.judge_capture import pop_judge_calls
from instrlib.tool_mapper import (
    _emit_judge_telemetry,
    append_broad_content_events,
    is_instruction_like,
    map_tool_call,
    persistence_instruction_label_with_status,
    pop_classifier_ms,
    secret_material_label_with_status,
)
from mappings import (
    collect_proposing_tools,
    collect_tool_origins,
    extract_inbound_events,
    extract_outbound_events,
    _preview_value,
)
from instrlib.tool_mapper import classify_result_origin
from predicates import override_judge_cache, write_current_context
from static_analysis import (
    PredicateCall,
    extract_predicate_calls,
    extract_predicate_policies,
)
from switch_state import (
    DRY_RUN_SWITCH_ID,
    ENFORCEMENT_MODE_CHOICES,
    ENFORCEMENT_MODE_SWITCH_ID,
    SwitchState,
)
from yaml_loader import HumanApprovalConfig, IngestJudgeConfig, LoadedConfig
from yaml_loader import load as load_yaml_config

_LIVE_POLICY_ID_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_LIVE_POLICIES_FILENAME = "live_policies.json"
_LIVE_POLICY_VALID_SCOPES: frozenset[str] = frozenset({"session", "persistent"})
_LIVE_POLICY_DEFAULT_SCOPE = "session"

JsonObject = dict[str, Any]

_INBOUND_DEMOTE_PREDICATES: dict[str, tuple[str, ...]] = {
    "safety": ("hard_rules",),
    "secrets": ("contains_secrets",),
    "model_policy": ("model_blocklist",),
}
_OUTBOUND_DEMOTE_PREDICATES: dict[str, tuple[str, ...]] = {
    "safety": ("hard_rules",),
}


@dataclass
class PendingApproval:
    """One in-flight ``Approve`` verdict awaiting a UI decision.

    The proxy registers a ``PendingApproval`` when a phase-1 verdict contains
    ``Approve`` and ``human_approval`` is enabled. The enforcement UI
    polls ``GET /pending_approvals`` to discover pending entries and replies
    via ``POST /feedback`` with ``kind`` set to ``approve`` or ``deny``. The
    awaiting coroutine wakes on the asyncio.Event and reads ``decision``.
    """

    tid: int
    sid: str
    label: str
    created_ts: float
    timeout_seconds: int
    on_timeout: str
    phase: str = "inbound"  # "inbound" | "outbound" — drives verdict mapping
    decision: str = ""  # "approve" | "deny" | "timeout" | ""
    payload: str = ""
    event: asyncio.Event = field(default_factory=asyncio.Event)


class ProxyState:
    """Mutable process state owned by the FastAPI lifespan."""

    def __init__(self, config: RuntimeConfig) -> None:
        self.config = config
        self.tid = 0
        self.tid_lock = threading.Lock()
        self.sessions: set[str] = set()
        self.sessions_lock = threading.Lock()
        self.enforcer: Enforcer | None = None
        self.logger: Logger | None = None
        self.http: httpx.AsyncClient | None = None
        self.predicate_calls: dict[str, list[PredicateCall]] = {}
        self.predicate_policies: dict[str, frozenset[str]] = {}
        self.enforcement_lock = asyncio.Lock()
        self.reload_lock = asyncio.Lock()
        self.switches = SwitchState()
        self.human_approval = HumanApprovalConfig()
        self.pending_approvals: dict[int, "PendingApproval"] = {}
        self.pending_approvals_lock = threading.Lock()
        # Per-session map of (call_id -> tool_name) for tool proposals the
        # model emitted in past LLM calls. Used to look up the proposing
        # tool when a ToolCallResult arrives later, so the Untrusted event
        # respects ``backend.trusted_tool_names``.
        self.proposing_tools: dict[str, dict[str, str]] = {}
        self.proposing_tools_lock = threading.Lock()
        # Per-call result ORIGIN (external | local | unknown), recorded at tool
        # proposal/execution time. Source-based Untrusted tagging gates on this;
        # ``trusted_tool_names`` is only the fallback for ``unknown`` origins.
        self.tool_origins: dict[str, dict[str, str]] = {}
        self.tool_origins_lock = threading.Lock()
        # Call ids that EnfGuard has blocked (policy block or approval-deny). When
        # a tool call is blocked the tool never runs, but the runtime still
        # reports a "result" back — the echo of EnfGuard's own denial reason. That
        # text contains policy vocabulary (e.g. "installs a persistence foothold
        # (keys/sudoers/cron/service/import-hook)") and would otherwise be
        # re-ingested as untrusted external content and re-fire content_risk
        # classifiers (persistence_instruction, instruction_like, secret_material),
        # contaminating the same-session provenance window. Keyed globally because
        # the echoed result can arrive under a different/empty session id than the
        # block. Reset per run by _reset_run_scoped_state.
        self.blocked_call_ids: set[str] = set()
        self.blocked_call_ids_lock = threading.Lock()
        # Warnings recorded for WARNED-but-allowed tool calls (call_id -> message).
        # A WarnToolCall returns decision "allow", so the runtime runs the tool and
        # ignores the advisory `warning` field. To make the MODEL aware it is in a
        # flagged/monitored environment, the proxy prepends the warning to that
        # call's tool_result in the request it forwards upstream (added AFTER our
        # own event extraction, so it never re-arms our ingest classifiers). The
        # entry is popped on first injection, so the model sees it once — on the
        # turn immediately after the flagged action. Reset per run.
        self.tool_warnings: dict[str, str] = {}
        self.tool_warnings_lock = threading.Lock()
        # Frozen snapshot of ``backend.trusted_tool_names`` from YAML.
        # Tool results whose proposing tool name is in this set are not
        # paired with an ``Untrusted`` event. Reloaded on every YAML reload.
        self.trusted_tool_names: frozenset[str] = frozenset()
        # Backward-compatible master flag plus independent ingest-judge switches.
        self.unknown_tool_judge: bool = True
        self.ingest_judges = IngestJudgeConfig()
        # Wall-clock time this proxy run started (set by the lifespan after
        # _reset_run_scoped_state). ``tid`` restarts at 1 every run and the
        # per-tid trace files are reused across runs, so the trace list scopes
        # itself to files written at/after this time. 0.0 = unset (no scoping),
        # which keeps unit tests that never run the lifespan unaffected.
        self.run_started_at: float = 0.0

    def next_tid(self) -> int:
        with self.tid_lock:
            self.tid += 1
            return self.tid

    def include_session_start(self, sid: str) -> bool:
        if not sid:
            return False
        with self.sessions_lock:
            if sid in self.sessions:
                return False
            self.sessions.add(sid)
            return True

    def record_proposing_tools(self, sid: str, mapping: dict[str, str]) -> None:
        """Remember which tool name proposed each ``call_id`` in this session."""

        if not sid or not mapping:
            return
        with self.proposing_tools_lock:
            self.proposing_tools.setdefault(sid, {}).update(mapping)

    def snapshot_proposing_tools(self, sid: str) -> dict[str, str]:
        """Return a snapshot of the call_id -> tool_name map for ``sid``."""

        if not sid:
            return {}
        with self.proposing_tools_lock:
            return dict(self.proposing_tools.get(sid, {}))

    def record_tool_origins(self, sid: str, mapping: dict[str, str]) -> None:
        """Remember the result origin (external|local|unknown) per ``call_id``."""

        if not sid or not mapping:
            return
        with self.tool_origins_lock:
            self.tool_origins.setdefault(sid, {}).update(mapping)

    def snapshot_tool_origins(self, sid: str) -> dict[str, str]:
        """Return a snapshot of the call_id -> origin map for ``sid``."""

        if not sid:
            return {}
        with self.tool_origins_lock:
            return dict(self.tool_origins.get(sid, {}))

    def record_blocked_call(self, call_id: str) -> None:
        """Remember a call_id that EnfGuard blocked, so a later echo of our own
        denial reason is not re-ingested as untrusted external content."""

        if not call_id:
            return
        with self.blocked_call_ids_lock:
            self.blocked_call_ids.add(call_id)

    def is_blocked_call(self, call_id: str) -> bool:
        """True if ``call_id`` was blocked earlier this run (denial-echo guard)."""

        if not call_id:
            return False
        with self.blocked_call_ids_lock:
            return call_id in self.blocked_call_ids

    def blocked_call_ids_snapshot(self) -> frozenset[str]:
        """Snapshot of blocked call ids for the chat-request denial-echo guard."""

        with self.blocked_call_ids_lock:
            return frozenset(self.blocked_call_ids)

    def record_tool_warning(self, call_id: str, message: str) -> None:
        """Remember the advisory for a warned-but-allowed tool call so it can be
        surfaced to the model on the next turn."""

        if not call_id or not message:
            return
        with self.tool_warnings_lock:
            self.tool_warnings[call_id] = message

    def pop_tool_warning(self, call_id: str) -> str | None:
        """Return and clear the recorded advisory for ``call_id`` (once-only)."""

        if not call_id:
            return None
        with self.tool_warnings_lock:
            return self.tool_warnings.pop(call_id, None)

    def has_tool_warnings(self) -> bool:
        with self.tool_warnings_lock:
            return bool(self.tool_warnings)


state = ProxyState(CONFIG)


async def _reload_runtime() -> None:
    async with state.reload_lock:
        loaded_config = load_yaml_config(state.config.yaml_file, state.config)
        new_config = _apply_loaded_config(state.config, loaded_config)
        ensure_runtime_dirs(new_config)
        # Fail loudly here rather than letting `Enforcer.start()` raise a
        # cryptic `FileNotFoundError` from `Popen`. Both initial boot and
        # `/admin/reload` go through this path, so a YAML override that
        # points at a missing binary is also caught.
        _ensure_enfguard_binary(new_config.enfguard_bin)
        predicate_calls = extract_predicate_calls(
            new_config.composite_policy_file,
            new_config.composite_signature_file,
        )
        predicate_policies = extract_predicate_policies(
            new_config.composite_policy_file,
            new_config.composite_signature_file,
        )
        new_enforcer = _build_enforcer(new_config)
        new_logger = Logger(pep=PEP(), schema=build_event_schema(), enforcer=new_enforcer)
        new_enforcer.start()

        old_enforcer = state.enforcer
        async with state.enforcement_lock:
            state.config = new_config
            state.predicate_calls = predicate_calls
            state.predicate_policies = predicate_policies
            state.enforcer = new_enforcer
            state.logger = new_logger
            state.switches.install(loaded_config.switches)
            state.human_approval = loaded_config.human_approval
            state.trusted_tool_names = frozenset(loaded_config.backend.trusted_tool_names)
            state.unknown_tool_judge = bool(getattr(loaded_config.backend, "unknown_tool_judge", True))
            state.ingest_judges = getattr(
                loaded_config.backend,
                "ingest_judges",
                IngestJudgeConfig(enabled=state.unknown_tool_judge),
            )
            _invalidate_active_policies_cache()
        # Re-register adapters so /admin/reload applies every YAML switch.
        _configure_ingest_judges()
        if old_enforcer is not None:
            old_enforcer.stop()


def _reset_run_scoped_state() -> None:
    """Start each proxy run at T1 and drop state keyed only by that run's tid."""

    state.tid = 0
    state.sessions = set()
    with state.blocked_call_ids_lock:
        state.blocked_call_ids = set()
    with state.tool_warnings_lock:
        state.tool_warnings = {}
    for path in (
        state.config.state_dir / "pre_eval_results.jsonl",
        state.config.current_context_file,
    ):
        try:
            path.unlink()
        except FileNotFoundError:
            continue
        except OSError:
            continue


def _archive_previous_run_logs() -> None:
    """Move the previous run's tid-keyed trace + session logs aside at boot.

    ``tid`` restarts at 1 every run (see ``_reset_run_scoped_state``) and the
    per-tid trace files (``logs/traces/tid_*.jsonl``) and per-session logs
    (``logs/session_*.jsonl``) are keyed by that reused tid, so a fresh run would
    otherwise append into — and the trace list would surface — turns from the
    previous run (the "stale/wrong traces" bug). We move them into a single
    rolling ``logs/prev_run/`` directory (cleared first, so exactly one previous
    run is retained and disk use stays bounded). History is preserved (moved, not
    deleted) and recoverable from ``logs/prev_run/``.

    Best-effort: any error is swallowed so archiving can never stop the proxy
    from booting. Called once from the lifespan at startup (never from
    ``_reset_run_scoped_state``), so unit tests that exercise the reset directly
    are unaffected.
    """

    logs_dir = state.config.logs_dir
    try:
        traces_dir = logs_dir / "traces"
        sources: list[Path] = []
        if traces_dir.is_dir():
            sources.extend(traces_dir.glob("tid_*.jsonl"))
        sources.extend(logs_dir.glob("session_*.jsonl"))
        legacy = state.config.trace_store_file
        if legacy.exists():
            sources.append(legacy)
        sources = [path for path in sources if path.exists()]
        if not sources:
            return

        archive_dir = logs_dir / "prev_run"
        # Reset the rolling archive so only the most recent previous run is kept.
        if archive_dir.exists():
            shutil.rmtree(archive_dir, ignore_errors=True)
        (archive_dir / "traces").mkdir(parents=True, exist_ok=True)

        moved = 0
        for src in sources:
            # Preserve the traces/ vs top-level layout under the archive.
            dest = (
                archive_dir / "traces" / src.name
                if src.parent.name == "traces"
                else archive_dir / src.name
            )
            try:
                shutil.move(str(src), str(dest))
                moved += 1
            except OSError:
                continue
        if moved:
            print(
                f"[traces] archived {moved} previous-run log file(s) to {archive_dir}",
                flush=True,
            )
    except OSError:
        pass


def _build_enforcer(config: RuntimeConfig) -> Enforcer:
    fun_path = config.predicates_file if config.predicates_file.exists() else None
    return Enforcer(
        binary=str(config.enfguard_bin),
        sig=str(config.composite_signature_file),
        formula=str(config.composite_policy_file),
        env=config.enfguard_env,
        fun=str(fun_path) if fun_path else None,
        trace_path=str(config.trace_log_file),
        time_mode=config.enfguard_time_mode,
    )


def _configure_ingest_judges() -> None:
    """Install or remove each deterministic-first ingest-time judge adapter.

    The YAML block ``backend.ingest_judges`` has a master ``enabled`` switch and
    one switch per adapter. Disabled adapters are unregistered, so they do not
    make an API call or emit judge telemetry. The environment variable
    ``ENFGUARD_TOOL_JUDGE`` remains a global runtime override for registered
    adapters.
    """
    try:
        from instrlib.tool_mapper import (
            register_authored_capability_classifier,
            register_broad_content_classifier,
            register_content_disclosure_classifier,
            register_memory_poison_classifier,
            register_package_name_classifier,
            register_persistence_instruction_classifier,
            register_secret_material_classifier,
            register_semantic_command_classifier,
            register_uncertain_action_classifier,
            register_unknown_tool_classifier,
            register_unknown_tool_review_gate,
            register_url_risk_classifier,
            register_webshell_classifier,
            set_unknown_tool_allow_threshold,
        )
        from instrlib.tool_judge import (
            classify_authored_capability_with_status,
            classify_broad_content_with_status,
            classify_content_disclosure_with_status,
            classify_memory_poison_with_status,
            classify_package_name_with_status,
            classify_persistence_instruction_with_status,
            classify_secret_material_with_status,
            classify_semantic_command,
            classify_uncertain_action,
            classify_unknown_tool,
            classify_unknown_tool_review,
            classify_url_risk_with_status,
            classify_webshell_with_status,
            set_tool_judge_enabled,
        )

        config = getattr(
            state,
            "ingest_judges",
            IngestJudgeConfig(enabled=state.unknown_tool_judge),
        )
        # The environment switch is the evaluation-level override.  Apply it
        # before registering adapters, rather than relying only on the adapter
        # functions to decline calls later.  That makes a judges-off ablation
        # structurally judge-free: no adapter is installed and no telemetry can
        # be emitted by a child process with a mismatched environment.
        judge_override = os.environ.get("ENFGUARD_TOOL_JUDGE", "").strip().lower()
        if judge_override in {"0", "false", "no", "off"}:
            master = False
        elif judge_override in {"1", "true", "yes", "on"}:
            master = bool(config.enabled)
        else:
            master = bool(config.enabled)

        register_unknown_tool_classifier(
            classify_unknown_tool if master and config.unknown_tool else None
        )
        register_unknown_tool_review_gate(
            classify_unknown_tool_review if master and config.unknown_tool else None
        )
        set_unknown_tool_allow_threshold(config.unknown_tool_allow_threshold)
        # Gated URL-risk fallback for ambiguous remote-payload URLs (curl … | sh).
        # Same enable flag / fail-safe contract; the mapper only calls it for an
        # ambiguous "external" URL that is part of a remote_payload exec.
        register_url_risk_classifier(
            classify_url_risk_with_status if master and config.url_risk else None
        )
        # Gated persistence-instruction fallback for ambiguous untrusted content
        # (subtle persistence wording with no explicit target keyword). The mapper
        # only calls it when the deterministic classifier declined AND a weak
        # persistence-intent signal is present.
        register_persistence_instruction_classifier(
            classify_persistence_instruction_with_status
            if master and config.persistence_instruction
            else None
        )
        # Gated secret-material fallback for ambiguous (free-form) secret content
        # in a tool result. The mapper only calls it when the deterministic secret
        # regexes declined AND a weak secret signal is present.
        register_secret_material_classifier(
            classify_secret_material_with_status
            if master and config.secret_material
            else None
        )
        # Gated uncertain-action fallback for a KNOWN tool whose command the
        # deterministic category classifiers did not confidently classify but
        # which looked weakly suspicious (tool_status=uncertain). Distinct from
        # the unknown-tool judge: the tool family is known; only the command's
        # intent is ambiguous. tool_status stays "uncertain"; this supplies a
        # Classify label + judge_status telemetry.
        register_uncertain_action_classifier(
            classify_uncertain_action if master and config.uncertain_action else None
        )
        # Gated package-name fallback (Resource Development): upgrades a trusted-
        # registry install to untrusted_install if the package is a likely typo-
        # squat / malicious dependency — the supply-chain case the registry
        # allowlist cannot catch. Runs only on installs; fail-open (keeps trusted).
        register_package_name_classifier(
            classify_package_name_with_status if master and config.package_name else None
        )
        # Gated webshell fallback (Initial Access): confirms an obfuscated/novel
        # webshell in a web-script file the deterministic signature missed. Runs
        # only on web-extension file writes.
        register_webshell_classifier(
            classify_webshell_with_status if master and config.webshell else None
        )
        # Gated content-disclosure fallback (A3S content-vs-action gap): a LOCAL
        # file write whose CONTENT discloses secret material or the agent's own
        # system prompt, with no dangerous action and no egress. The mapper only
        # calls it when the deterministic secret regexes declined AND a weak
        # signal is present; deterministic secrets fire with no judge.
        register_content_disclosure_classifier(
            classify_content_disclosure_with_status
            if master and config.content_disclosure
            else None
        )
        # Broad semantic-command judge (max-coverage): the one judge NOT gated on
        # deterministic abstention. Runs on a bash/code command carrying a
        # dynamic-execution / reconstruction primitive the deterministic layer
        # could not resolve, closing the semantic-reconstruction routing gap.
        register_semantic_command_classifier(
            classify_semantic_command if master and config.semantic_command else None
        )
        # Broad untrusted-content judge (max-coverage): the content-side twin of the
        # semantic-command judge. Runs on an untrusted tool result the weak-signal
        # content paths left unflagged, closing the content routing gap. Own switch
        # because it can run on nearly every untrusted result.
        register_broad_content_classifier(
            classify_broad_content_with_status
            if master and config.content_semantics
            else None
        )
        # Memory-poisoning content judge: a subtle tampering directive written into
        # the agent's own memory/config that the deterministic poisoning check
        # missed (A3S Memory / Config Tampering residue).
        register_memory_poison_classifier(
            classify_memory_poison_with_status
            if master and config.memory_poison
            else None
        )
        # Authored-capability judge (hybrid, deferred-execution artifacts): a
        # file_write / editor write whose CONTENT is a complete dangerous dataflow
        # (reads a secret and sends it) or a dangerous capability planted in a
        # deferred-execution sink (install hook, import-time module, cron, CI). The
        # deterministic source+sink conjunction fires with no judge; this closes
        # the obfuscated / split / deferred-sink residue (AgentHazard id 7).
        register_authored_capability_classifier(
            classify_authored_capability_with_status
            if master and config.authored_capability
            else None
        )
        set_tool_judge_enabled(master)

        names = (
            "unknown_tool",
            "url_risk",
            "persistence_instruction",
            "secret_material",
            "uncertain_action",
            "package_name",
            "webshell",
            "content_disclosure",
            "semantic_command",
            "content_semantics",
            "memory_poison",
            "authored_capability",
        )
        active = [name for name in names if master and getattr(config, name)]
        print(
            "  ingest judges:    "
            + (", ".join(active) if active else "disabled")
        )
    except Exception as exc:  # pragma: no cover - registration must never crash boot
        print(f"[tool_judge] ingest registration skipped: {exc}")


def _check_confinement_config() -> None:
    """Surface the path_confinement workspace root at boot.

    Confinement fails OPEN when the workspace root does not exist on disk (a
    misconfigured ENFGUARD_NANOCLAW_GROUP_DIR / ENFGUARD_WS_HOST_ROOTS), which
    would silently weaken symlink-escape detection. Printing it at boot makes
    the failure mode visible instead of silent.
    """
    try:
        from instrlib.path_confinement import workspace_roots, workspace_roots_exist

        roots = workspace_roots()
        if workspace_roots_exist():
            print(f"  confinement root: {roots[0] if roots else '(none)'}")
        else:
            print(
                "  [confinement] WARNING: workspace root(s) "
                f"{roots} do not exist on disk — path_confinement fails OPEN "
                "(symlink escapes may go undetected). Set "
                "ENFGUARD_NANOCLAW_GROUP_DIR / ENFGUARD_WS_HOST_ROOTS."
            )
    except Exception as exc:  # pragma: no cover - boot diagnostic must never crash
        print(f"[confinement] config check skipped: {exc}")


async def lifespan(app: FastAPI):
    ensure_runtime_dirs(state.config)
    _ensure_admin_token_policy(state.config)
    # Drop any session-scoped live overlays from the previous proxy run
    # before the first reload so this run boots from pure YAML + persistent
    # overlays only. Persistent live policies (scope == "persistent") stay.
    _purge_session_scoped_live_policies()
    await _reload_runtime()
    _reset_run_scoped_state()
    # Move the previous run's tid-keyed trace + session logs aside so a run that
    # restarts tid at 1 cannot reuse/mix them (the stale-trace bug). Belt-and-
    # suspenders with the run_started_at list filter below.
    _archive_previous_run_logs()
    # Mark the run start AFTER the tid reset so the trace list (which globs the
    # reused per-tid files) only surfaces turns produced by this run.
    state.run_started_at = time.time()
    _check_confinement_config()
    state.http = httpx.AsyncClient(timeout=120.0)
    print(f"EnfGuard proxy ready on {state.config.proxy_host}:{state.config.proxy_port}")
    print(f"  enfguard binary:  {state.config.enfguard_bin}")
    print(f"  trace time mode:  {state.config.enfguard_time_mode}")
    print(f"  yaml file:        {state.config.yaml_file}")
    print(f"  composite sig:    {state.config.composite_signature_file}")
    print(f"  composite mfotl:  {state.config.composite_policy_file}")
    print(f"  cors origins:     {', '.join(_CORS_ALLOW_ORIGINS) or '(none)'}")
    try:
        yield
    finally:
        if state.http is not None:
            await state.http.aclose()
            state.http = None
        if state.enforcer is not None:
            state.enforcer.stop()
            state.enforcer = None
            state.logger = None


app = FastAPI(title="EnfGuard v2 Proxy", lifespan=lifespan)
# CORS allow-origins is resolved at module import from
# ``config.cors_allow_origins`` so the safe defaults (loopback + Vite
# dev server) apply unless the operator explicitly overrides them via
# ``$ENFGUARD_CORS_ALLOW_ORIGINS``. Setting it to ``*`` re-enables the
# permissive default of older builds; do that only when you understand
# the implications, since every admin endpoint accepts the same
# ``X-Admin-Token`` regardless of origin.
_CORS_ALLOW_ORIGINS = cors_allow_origins(CONFIG.proxy_port)
if "*" in _CORS_ALLOW_ORIGINS:
    print(
        "[cors] WARNING: allow_origins includes '*'. Any web page the "
        "user visits can call this proxy. Restrict via "
        "$ENFGUARD_CORS_ALLOW_ORIGINS for any non-local-demo use.",
        flush=True,
    )
app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ALLOW_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
    # Custom response headers must be listed in `expose_headers` for the
    # browser to surface them to JS. Same-origin flows (chat + proxy on
    # 127.0.0.1:9000) work either way; this is for the Vite dev-server
    # flow where the React UI and proxy live on different ports.
    expose_headers=["X-Tid", "X-Enforcement-Action", "X-Enforcement-Reason"],
)
app.mount(
    "/assets",
    StaticFiles(directory=str(state.config.frontend_dist_dir / "assets"), check_dir=False),
    name="frontend-assets",
)


def _ensure_admin_token_policy(config: RuntimeConfig) -> None:
    if os.environ.get("ENFGUARD_ADMIN_TOKEN"):
        return
    raise RuntimeError("ENFGUARD_ADMIN_TOKEN is required for admin and feedback routes")


def _ensure_enfguard_binary(path: Path) -> None:
    """Verify that the resolved EnfGuard binary exists and is executable.

    Called from ``_reload_runtime`` so initial boot and every
    ``/admin/reload`` invocation surface a missing binary as a clear
    ``RuntimeError`` instead of letting ``Enforcer.start()`` raise an
    opaque ``FileNotFoundError`` from ``Popen``. The error message
    re-derives the search trail (env var, ``$PATH`` lookup, fallback)
    so the operator sees exactly which paths were considered.
    """

    candidate = Path(path).expanduser()
    if candidate.exists() and os.access(candidate, os.X_OK):
        return

    env_value = os.environ.get("ENFGUARD_BIN")
    on_path = shutil.which("enfguard") or shutil.which("enfguard.exe")

    lines = [
        f"EnfGuard binary not found or not executable at: {candidate}",
        "",
        "Search trail:",
        f"  $ENFGUARD_BIN: {env_value if env_value else '(not set)'}",
        f"  PATH lookup (enfguard / enfguard.exe): {on_path or '(not found)'}",
        f"  Default fallback: {DEFAULT_ENFGUARD_BIN}",
        "",
        "Fix one of the following:",
        "  1. Install EnfGuard so the binary is on $PATH, or",
        "  2. Set $ENFGUARD_BIN to the absolute binary path before starting the proxy, or",
        "  3. Add `backend.enfguard_bin: /path/to/enfguard.exe` to enfguard.yaml.",
    ]
    raise RuntimeError("\n".join(lines))


def _require_admin(request: Request) -> None:
    token = os.environ.get("ENFGUARD_ADMIN_TOKEN", "")
    if not token:
        raise HTTPException(status_code=503, detail="ENFGUARD_ADMIN_TOKEN is not configured")
    if request.headers.get("x-admin-token") != token:
        raise HTTPException(status_code=401, detail="invalid admin token")


@app.get("/health")
async def health() -> JsonObject:
    """Return a small health payload for smoke tests.

    ``yaml_file`` exposes the path of the policy pack the proxy was
    booted against (the resolved value of ``$ENFGUARD_YAML``). Bench
    harnesses use it to fail fast when the running proxy is loaded with
    a different pack than the prompt suite expects — e.g. running the
    OpenAI Model Spec prompt suite against a proxy that was started
    with the Anthropic Constitution YAML.
    """

    try:
        yaml_path = str(state.config.yaml_file.resolve())
    except OSError:
        yaml_path = str(state.config.yaml_file)
    return {
        "ok": True,
        "enforcer_started": state.enforcer is not None,
        "yaml_file": yaml_path,
    }


@app.get("/admin/policies")
async def admin_get_policies(request: Request) -> JsonObject:
    """Return live policy state for the enforcement UI."""

    _require_admin(request)
    return _read_policy_state()


@app.put("/admin/policies")
async def admin_put_policies(request: Request) -> JsonObject:
    """Replace editable policy state fields."""

    _require_admin(request)
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="policy payload must be an object")
    current = _read_policy_state()
    for key in (
        "active",
        "thresholds",
        "policy_thresholds",
        "model_blocklist",
        "judge_fail_mode",
        "judge_fail_modes",
        "feedback",
        "human_approval",
        "runtime",
    ):
        if key in body:
            current[key] = body[key]
    if "features" in body and isinstance(body["features"], dict):
        features = current.get("features") if isinstance(current.get("features"), dict) else {}
        features.update(body["features"])
        current["features"] = features
    _sync_policy_enabled_flags(current)
    _sync_live_policy_enabled_from_state(current)
    _write_json_atomic(state.config.state_dir / "active_policies.json", current)
    if "human_approval" in body and isinstance(body["human_approval"], dict):
        state.human_approval = _human_approval_from_state(body["human_approval"])
    _invalidate_active_policies_cache()
    return current


@app.post("/admin/live_policy")
async def admin_upsert_live_policy(request: Request) -> JsonObject:
    """Install or update one policy without editing ``enfguard.yaml``."""

    _require_admin(request)
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="live policy payload must be an object")
    policy = _normalize_live_policy_payload(body)
    path = _live_policy_path()
    previous_text = path.read_text(encoding="utf-8") if path.exists() else None
    try:
        policies = _read_live_policy_store(path)
        _write_json_atomic(path, {"policies": _upsert_live_policy(policies, policy)})
        await _reload_runtime()
    except HTTPException:
        raise
    except Exception as exc:
        if previous_text is None:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        else:
            _write_text_atomic(path, previous_text)
        try:
            await _reload_runtime()
        except Exception:
            pass
        raise HTTPException(status_code=422, detail=f"live policy failed validation: {exc}") from exc
    return {"ok": True, "policy": policy, **_read_policy_state()}


@app.delete("/admin/live_policy/{policy_id}")
async def admin_delete_live_policy(policy_id: str, request: Request) -> JsonObject:
    """Remove one live policy by id and reload the runtime.

    Mirrors the rollback pattern used by the upsert route: if the reload
    after the trimmed write fails for any reason, restore the previous
    file contents so the runtime keeps the state it had before the call.
    YAML-sourced policies are not touched, they live in ``enfguard.yaml``
    and can only be removed by editing that file.
    """

    _require_admin(request)
    if not _LIVE_POLICY_ID_RE.match(policy_id or ""):
        raise HTTPException(
            status_code=422,
            detail="live policy id must start with a letter or underscore and contain only letters, numbers, and underscores",
        )
    path = _live_policy_path()
    previous_text = path.read_text(encoding="utf-8") if path.exists() else None
    try:
        policies = _read_live_policy_store(path)
        survivors = [policy for policy in policies if policy.get("id") != policy_id]
        if len(survivors) == len(policies):
            raise HTTPException(status_code=404, detail=f"no live policy with id {policy_id!r}")
        _write_json_atomic(path, {"policies": survivors})
        await _reload_runtime()
    except HTTPException:
        raise
    except Exception as exc:
        if previous_text is None:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        else:
            _write_text_atomic(path, previous_text)
        try:
            await _reload_runtime()
        except Exception:
            pass
        raise HTTPException(
            status_code=422,
            detail=f"live policy delete failed validation: {exc}",
        ) from exc
    return {"ok": True, "removed": policy_id, **_read_policy_state()}


@app.post("/admin/clear_judge_cache")
async def admin_clear_judge_cache(request: Request) -> JsonObject:
    """Clear judge caches across every session.

    Each session's cache lives at ``state/sessions/<sid>/judge_cache.jsonl``;
    this endpoint walks every existing session and drops both the
    in-memory and on-disk entries. Used by the judge-batching bench
    harness so each strategy run starts cold without bouncing the proxy
    (which would also reset switches and break any open chat session).
    For surgical clearing of a single session, use
    ``POST /admin/clear_session/{sid}`` instead. Other caches (per-tid
    trace index, session logs) are intentionally left alone — they're
    still useful to inspect after a bench sweep.
    """

    _require_admin(request)
    import predicates as _predicates  # local import to avoid widening top-level deps

    body: JsonObject = {}
    try:
        raw_body = await request.body()
        if raw_body:
            parsed = json.loads(raw_body)
            if isinstance(parsed, dict):
                body = parsed
    except (json.JSONDecodeError, OSError):
        body = {}

    # Drop every session's in-memory + on-disk cache. The pre-eval
    # replay file is per-tid not per-session, but it's also fully
    # ephemeral so we wipe it too — same semantics as before this
    # refactor: a clear_judge_cache call resets all caches the next
    # request will consult.
    cleared = _predicates.clear_all_session_caches()

    if hasattr(_predicates, "_TRACE_DEDUPE_SEEN"):
        _predicates._TRACE_DEDUPE_SEEN.clear()
    if hasattr(_predicates, "_TRACE_DEDUPE_ORDER"):
        _predicates._TRACE_DEDUPE_ORDER.clear()

    pre_eval_path = getattr(
        _predicates,
        "PRE_EVAL_RESULTS_FILE",
        state.config.state_dir / "pre_eval_results.jsonl",
    )
    try:
        if pre_eval_path.exists():
            pre_eval_path.unlink()
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"failed to remove cache file: {exc}") from exc

    cleared_traces = False
    if _bool_like(body.get("traces", False)):
        cleared_traces = _clear_trace_logs()

    return {
        "ok": True,
        "sessions": cleared,
        "pre_eval_cleared": str(pre_eval_path),
        "cleared_traces": cleared_traces,
    }


@app.post("/admin/clear_session/{sid}")
async def admin_clear_session(sid: str, request: Request) -> JsonObject:
    """Clear one session's judge cache (memory + on-disk file)."""

    _require_admin(request)
    import predicates as _predicates

    return _predicates.clear_session_cache(sid)


@app.post("/admin/dryrun/{mode}")
async def admin_set_dryrun(mode: str, request: Request) -> JsonObject:
    """Back-compat shim: maps old dry-run calls to enforcement_mode."""

    _require_admin(request)
    if mode not in {"on", "off"}:
        raise HTTPException(status_code=400, detail="mode must be 'on' or 'off'")
    enabled = mode == "on"
    if state.switches.has(ENFORCEMENT_MODE_SWITCH_ID):
        state.switches.set_value(ENFORCEMENT_MODE_SWITCH_ID, "warn" if enabled else "enforce")
    if state.switches.has(DRY_RUN_SWITCH_ID):
        state.switches.set_value(DRY_RUN_SWITCH_ID, enabled)
    return {"dry_run": enabled, "enforcement_mode": _enforcement_mode()}


@app.get("/switches")
async def get_switches(request: Request) -> JsonObject:
    """Return the current switch schema plus values for the UI."""

    _require_admin(request)
    return {"switches": state.switches.to_admin_payload()}


@app.post("/switches/{switch_id}")
async def set_switch(switch_id: str, request: Request) -> JsonObject:
    """Update one switch value. Body shape: ``{\"value\": ...}``."""

    _require_admin(request)
    body = await request.json()
    if not isinstance(body, dict) or "value" not in body:
        raise HTTPException(status_code=400, detail="body must be {\"value\": ...}")
    if not state.switches.has(switch_id):
        raise HTTPException(status_code=404, detail=f"unknown switch: {switch_id}")
    try:
        normalized = state.switches.set_value(switch_id, body["value"])
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    _sync_switch_value_to_policy_state(switch_id, normalized)
    return {"id": switch_id, "value": normalized}


@app.post("/admin/reload")
async def admin_reload(request: Request) -> JsonObject:
    _require_admin(request)
    await _reload_runtime()
    return {"ok": True, **_read_policy_state()}


@app.get("/trace/{tid}")
async def get_trace(tid: int, request: Request) -> JsonObject:
    """Return a structured trace bundle for one turn.

    The payload is shaped so the UI can render a collapsed "verdict" line
    plus a drill-down timeline without further client-side reshuffling:

    * ``predicate_rows`` — every per-predicate result row keyed to ``tid``
      (raw, in time order). Includes ``judge_prompt``, ``judge_raw_reply``,
      ``latency_ms``, ``batch_id``, etc.
    * ``session_records`` — the same structured records the proxy already
      writes to ``logs/session_*.jsonl`` (one per turn).
    * ``phases`` — derived view: a per-phase summary with verdict, fired
      predicates, total wall-time, and predicate references.
    * ``batches`` — derived view: ``batch_id → {latency_ms, predicate_count}``
      so the drill-down can collapse N cache-hit rows under one batch entry.
    """

    _require_admin(request)
    rows, session_records = _trace_bundle_for_tid(tid)
    return {
        "tid": tid,
        "predicate_rows": rows,
        "session_records": session_records,
        "phases": _summarise_phases(rows, session_records),
        "batches": _summarise_batches(rows),
    }


@app.get("/traces")
async def list_traces(request: Request) -> JsonObject:
    """Return a recent-first list of traceable turns for the trace tab list."""

    _require_admin(request)
    limit = 50
    try:
        limit_param = int(request.query_params.get("limit", "50"))
        if 1 <= limit_param <= 500:
            limit = limit_param
    except (TypeError, ValueError):
        pass
    return {"traces": _list_recent_traces(limit)}


@app.post("/feedback")
async def post_feedback(request: Request) -> JsonObject:
    _require_admin(request)
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="feedback payload must be an object")
    try:
        tid = int(body.get("tid"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="feedback tid must be an integer") from None
    kind = _limit_text(body.get("kind", "freeform"), 64) or "freeform"
    payload = _limit_text(body.get("payload", ""), 512)

    # If this turn has a pending Approve verdict, an "approve" /
    # "deny" feedback resolves it and unblocks the awaiting coroutine.
    decision = _normalize_approval_decision(kind)
    resolves_approval = bool(decision and _has_pending_approval(tid))
    if not resolves_approval and not _feedback_enabled():
        raise HTTPException(status_code=403, detail="feedback is disabled by enfguard.yaml")

    feedback_event = make_feedback_event(tid, kind, payload)
    if resolves_approval:
        _logger().log_only([feedback_event], tid)
    else:
        _append_feedback_log(feedback_event)
    if resolves_approval:
        _resolve_pending_approval(tid, decision, payload)
    return {"ok": True, "tid": tid, "kind": kind}


@app.post("/admin/judge_override")
async def admin_judge_override(request: Request) -> JsonObject:
    """Override one judge result and log the correction as UserFeedback."""

    _require_admin(request)
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="judge override payload must be an object")
    try:
        tid = int(body.get("tid"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="judge override tid must be an integer") from None
    predicate = _limit_text(body.get("predicate", ""), 128)
    if not predicate:
        raise HTTPException(status_code=400, detail="judge override predicate is required")
    phase = _limit_text(body.get("phase", ""), 32).lower()
    if phase not in {"inbound", "outbound"}:
        raise HTTPException(status_code=400, detail="judge override phase must be inbound or outbound")
    try:
        raw_score = float(body.get("raw_score"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="judge override raw_score must be numeric") from None
    raw_score = max(0.0, min(1.0, raw_score))
    reason = _limit_text(body.get("reason", ""), 512) or "judge override"
    content_preview = str(body.get("content_preview", "") or "")
    content = _resolve_judge_override_content(tid, predicate, phase, content_preview)
    if content is None:
        raise HTTPException(
            status_code=422,
            detail="could not resolve the exact judged content for this trace row",
        )

    override_reason = f"judge override: {reason}"
    result = override_judge_cache(predicate, content, raw_score, override_reason)
    feedback_payload = {
        "predicate": predicate,
        "phase": phase,
        "raw_score": raw_score,
        "reason": reason,
        "content_preview": result.get("content_preview", content_preview),
    }
    _append_feedback_log(
        make_feedback_event(tid, "judge_override", json.dumps(feedback_payload, ensure_ascii=False))
    )
    return {"ok": True, "tid": tid, **result}


@app.get("/pending_approvals")
async def get_pending_approvals(request: Request) -> JsonObject:
    """Return the list of in-flight approval requests for the UI to render."""

    _require_admin(request)
    return {"pending": _pending_approvals_payload()}


@app.get("/admin/session/{sid}/tokens")
async def get_session_tokens(sid: str, request: Request) -> JsonObject:
    _require_admin(request)
    return {"sid": sid, "total_tokens": _session_token_total(sid)}


@app.get("/chat")
async def serve_chat():
    path = state.config.static_dir / "chat.html"
    if not path.exists():
        raise HTTPException(status_code=404, detail="static/chat.html is not built yet")
    return FileResponse(path)


@app.get("/enforcement")
async def serve_enforcement():
    path = state.config.frontend_dist_dir / "index.html"
    if not path.exists():
        return JSONResponse(
            status_code=503,
            content={
                "error": "frontend_not_built",
                "detail": "Run `cd frontend && npm install && npm run build`, then restart the proxy.",
            },
        )
    return FileResponse(path)


@app.post("/v1/messages")
async def anthropic_messages(request: Request):
    """Proxy Anthropic Messages through two-phase enforcement."""

    body = await request.json()
    return await _run_enforced_request(
        request=request,
        body=body,
        api_format="anthropic",
        provider="anthropic",
        upstream_call=lambda: _post_anthropic(request, body),
        normalize=normalize_anthropic,
        serialize=serialize_anthropic,
        synthetic=synthetic_anthropic,
    )


@app.post("/v1/chat/completions")
async def openai_chat_completions(request: Request):
    """Proxy OpenAI-compatible Chat Completions through two-phase enforcement."""

    body = await request.json()
    provider = request.headers.get("x-provider", "openai")
    return await _run_enforced_request(
        request=request,
        body=body,
        api_format="openai",
        provider=provider,
        upstream_call=lambda: _post_openai(request, body),
        normalize=normalize_openai,
        serialize=serialize_openai,
        synthetic=synthetic_openai,
    )


@app.post("/v1/chat/completions/ollama")
async def ollama_chat_completions(request: Request):
    """Proxy Ollama /api/chat while exposing OpenAI-compatible chat JSON."""

    body = await request.json()
    return await _run_enforced_request(
        request=request,
        body=body,
        api_format="openai",
        provider="ollama",
        upstream_call=lambda: _post_ollama(body),
        normalize=normalize_openai,
        serialize=serialize_openai,
        synthetic=synthetic_openai,
    )


@app.post("/v1/tool_execute")
async def tool_execute(request: Request) -> JSONResponse:
    """Gate an agent tool call before the runtime executes it."""

    _require_admin(request)
    body = await request.json()
    tid = _body_tid(body) or state.next_tid()
    sid = str(body.get("sid") or request.headers.get("x-session-id", "") or "")
    call_id = str(body.get("call_id") or "")
    tool_name = str(body.get("tool_name") or "")
    tool_input = body.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}

    active_policies = _active_policies()
    if state.enforcer is not None:
        state.enforcer.trace_request_start(tid)

    rid = _extract_rid(request, tid, body)
    # settings + PolicyActive normally fire at Phase 1 of the LLM
    # call that proposed the tool. The action layer re-anchors the Turn
    # and emits Clock with phase="tool" so policies can reason about
    # action duration if they want.
    mapped_tool_events = map_tool_call(tid, call_id, tool_name, tool_input)
    canonical_tool = tool_name.lower().strip()
    input_preview = _preview_value(tool_input)
    for event in mapped_tool_events:
        if event.name == "ToolCall" and len(event.args) >= 4:
            canonical_tool = str(event.args[2])
            input_preview = str(event.args[3])
            break
    # The direct agent hook may use a different session id from the proxied LLM
    # response (NanoClaw's chat request can be sessionless while tool hooks use
    # the WhatsApp jid). Persist the canonical proposing tool at the authoritative
    # pre-execution boundary so /v1/tool_result can apply trusted_tool_names.
    if sid and call_id:
        state.record_proposing_tools(sid, {call_id: canonical_tool})
        # Record where this call's RESULT bytes will come from, so /v1/tool_result
        # can tag Untrusted by origin (external/local) rather than by tool name.
        state.record_tool_origins(
            sid, {call_id: classify_result_origin(tool_name, tool_input)}
        )
    tool_events = [
        *_clock_events(tid, "tool"),
        *state.switches.emit_events(tid),
        *_policy_active_events(tid, active_policies),
        Event("Turn", tid, rid, sid),
        # The pre-execution hook reports the runtime's planned action with
        # the same canonical tool name and input preview as ToolCall.
        Event("ToolPlanned", tid, call_id, canonical_tool, input_preview),
        *mapped_tool_events,
    ]
    cau, _judge_reasons, enfguard_ms = await _tool_phase_enforce(
        tid,
        sid,
        tool_events,
        call_id,
        suppress_block_events=("ToolCall", "ToolPlanned"),
    )
    policy_decision = _policy_tool_decision(cau)
    cau = await _resolve_approvals(tid, sid, cau, "tool")

    decision, reason, warning = _tool_decision(cau)
    decision_trace = _tool_decision_trace(policy_decision, decision, reason, warning)
    if decision == "block" and call_id:
        # The tool will not run; any later "result" for this call is the runtime
        # echoing EnfGuard's own denial reason. Mark it so /v1/tool_result does
        # not re-ingest our verdict text as untrusted external content.
        state.record_blocked_call(call_id)
    elif warning and call_id:
        # WarnToolCall: allowed but flagged. Record the advisory so the next
        # model turn that carries this call's result sees that it was flagged.
        state.record_tool_warning(call_id, warning)
    _append_session_log(
        sid,
        _session_record(
            tid,
            "tool",
            f"tool_{decision}",
            tool_events,
            verdicts=_verdict_entries(
                cau,
                ("BlockToolCall", "WarnToolCall", "BlockRequest", "WarnRequest"),
            ),
            verdict_events=_tool_verdict_events(tid, cau),
            enfguard_ms_in=enfguard_ms,
            decision_trace=decision_trace,
        ),
    )

    response: JsonObject = {
        "decision": decision,
        "reason": reason,
        "tid": tid,
        "trace_url": f"/trace/{tid}",
    }
    if warning:
        response["warning"] = warning
    if body.get("decision_schema_version") == 1:
        response["decision_trace"] = decision_trace
    return JSONResponse(content=response)


@app.post("/v1/tool_result")
async def tool_result(request: Request) -> JSONResponse:
    """Observe an agent tool result after the runtime executes it."""

    _require_admin(request)
    body = await request.json()
    tid = _body_tid(body) or state.next_tid()
    sid = str(body.get("sid") or request.headers.get("x-session-id", "") or "")
    call_id = str(body.get("call_id") or "")
    tool_response = body.get("tool_response")

    active_policies = _active_policies()
    if state.enforcer is not None:
        state.enforcer.trace_request_start(tid)

    rid = _extract_rid(request, tid, body)
    try:
        exit_code = int(body.get("exit_code", -1))
    except (TypeError, ValueError):
        # A malformed exit_code (non-numeric string, list, None) must not crash
        # the result hook — an uncaught 500 here is a fail-open in practice.
        # Default to -1 (unknown) and continue enforcing on the content.
        exit_code = -1
    proposing = state.snapshot_proposing_tools(sid)
    origins = state.snapshot_tool_origins(sid)
    trusted = _trusted_tool_names()
    result_content = _preview_value(tool_response)
    result_events = [
        *_clock_events(tid, "tool"),
        *state.switches.emit_events(tid),
        *_policy_active_events(tid, active_policies),
        Event("Turn", tid, rid, sid),
        Event("ToolResult", tid, call_id, result_content, exit_code),
    ]
    # Source-based trust: external origin -> untrusted; local -> trusted;
    # unknown origin -> fall back to the tool-name allowlist (legacy).
    _origin = origins.get(call_id, "unknown") if call_id else "unknown"
    if _origin == "external":
        untrusted = True
    elif _origin == "local":
        untrusted = False
    else:
        untrusted = bool(call_id) and proposing.get(call_id, "") not in trusted
    if call_id and state.is_blocked_call(call_id):
        # Denial echo: EnfGuard already blocked this call, so the tool never ran
        # and this "result" is the echo of our own block reason. Do not run the
        # content-risk classifiers (Untrusted / instruction_like /
        # persistence_instruction / secret_material) on our own verdict text —
        # doing so would re-arm the same-session provenance window. The
        # ToolResult event itself is still recorded above for the trace.
        pass
    else:
        result_events.extend(
            _tool_result_content_risk_events(tid, call_id, result_content, bool(untrusted))
        )
    cau, _judge_reasons, enfguard_ms = await _tool_phase_enforce(
        tid,
        sid,
        result_events,
        call_id,
        suppress_block_events=("ToolResult", "Untrusted"),
    )
    policy_decision = _policy_tool_decision(cau)
    cau = await _resolve_approvals(tid, sid, cau, "tool")

    decision, reason, warning = _tool_decision(cau)
    result_gate = _tool_decision_trace(policy_decision, decision, reason, warning)
    tool_execution = body.get("tool_execution")
    if not isinstance(tool_execution, dict):
        tool_execution = {}
    decision_trace: JsonObject = {
        "schema_version": 1,
        "tool_execution": tool_execution,
        "result_gate": result_gate,
    }
    _append_session_log(
        sid,
        _session_record(
            tid,
            "tool",
            f"tool_result_{decision}",
            result_events,
            verdicts=_verdict_entries(
                cau,
                ("BlockToolCall", "WarnToolCall", "BlockRequest", "WarnRequest"),
            ),
            verdict_events=_tool_verdict_events(tid, cau),
            enfguard_ms_in=enfguard_ms,
            decision_trace=decision_trace,
        ),
    )

    response: JsonObject = {
        "decision": decision,
        "reason": reason,
        "tid": tid,
        "trace_url": f"/trace/{tid}",
    }
    if warning:
        response["warning"] = warning
    if body.get("decision_schema_version") == 1:
        response["decision_trace"] = decision_trace
    return JSONResponse(content=response)


_ENFGUARD_ADVISORY_PREFIX = "[EnfGuard advisory]"


def _format_tool_advisory(message: str) -> str:
    return (
        f"{_ENFGUARD_ADVISORY_PREFIX} The previous tool call was flagged by the "
        f"security monitor: {message}. It was allowed to run, but treat this as a "
        f"monitored, potentially sensitive environment and proceed with caution."
    )


def _inject_tool_warning_advisories(body: JsonObject, api_format: str) -> int:
    """Prepend recorded EnfGuard advisories to the matching tool_result in the
    upstream request body (Anthropic content-block or OpenAI role=tool forms).

    Each warning is popped on use, so the model sees the advisory once — on the
    turn that carries the flagged call's result. Must be called AFTER
    ``extract_inbound_events`` so the advisory is never fed to our own ingest
    classifiers. Returns the number of advisories injected.
    """

    messages = body.get("messages")
    if not isinstance(messages, list):
        return 0
    injected = 0
    for message in messages:
        if not isinstance(message, dict):
            continue
        if message.get("role") == "tool":  # OpenAI tool result
            call_id = str(message.get("tool_call_id") or message.get("id") or "")
            warn = state.pop_tool_warning(call_id) if call_id else None
            if not warn:
                continue
            advisory = _format_tool_advisory(warn)
            content = message.get("content")
            message["content"] = (
                advisory + "\n\n" + content
                if isinstance(content, str)
                else advisory + "\n\n" + _preview_value(content)
            )
            injected += 1
            continue
        content = message.get("content")  # Anthropic content blocks
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict) or block.get("type") != "tool_result":
                continue
            call_id = str(block.get("tool_use_id") or block.get("id") or "")
            warn = state.pop_tool_warning(call_id) if call_id else None
            if not warn:
                continue
            advisory = _format_tool_advisory(warn)
            bc = block.get("content")
            if isinstance(bc, str):
                block["content"] = advisory + "\n\n" + bc
            elif isinstance(bc, list):
                bc.insert(0, {"type": "text", "text": advisory})
            else:
                block["content"] = advisory
            injected += 1
    return injected


async def _run_enforced_request(
    request: Request,
    body: JsonObject,
    api_format: str,
    provider: str,
    upstream_call,
    normalize,
    serialize,
    synthetic,
) -> JSONResponse:
    tid = state.next_tid()
    sid = request.headers.get("x-session-id", "")
    active_policies = _active_policies()
    if state.enforcer is not None:
        state.enforcer.trace_request_start(tid)

    rid = _extract_rid(request, tid, body)
    inbound_events = extract_inbound_events(
        tid=tid,
        request=body,
        api_format=api_format,
        sid=sid,
        rid=rid,
        provider=provider,
        active_policies=active_policies,
        include_session_start=state.include_session_start(sid),
        proposing_tool_for_call_id=state.snapshot_proposing_tools(sid),
        trusted_tool_names=_trusted_tool_names(),
        blocked_call_ids=state.blocked_call_ids_snapshot(),
        origin_for_call_id=state.snapshot_tool_origins(sid),
    )
    inbound_events = _clock_events(tid, "request") + state.switches.emit_events(tid) + inbound_events
    # Surface prior tool-call warnings to the model: prepend the advisory to the
    # matching tool_result in the body we forward upstream. Done AFTER
    # extract_inbound_events so the advisory never re-arms our ingest classifiers.
    if state.has_tool_warnings():
        _inject_tool_warning_advisories(body, api_format)
    cau_in, judge_reasons_in, enfguard_ms_in = await _phase1_enforce(tid, sid, inbound_events)

    cau_in = await _resolve_approvals(tid, sid, cau_in, "inbound")

    inbound_warning = ""
    stream_requested = bool(body.get("stream"))

    if "BlockRequest" in cau_in:
        return _blocked_inbound_response(
            tid=tid,
            sid=sid,
            provider=provider,
            api_format=api_format,
            inbound_events=inbound_events,
            cau_in=cau_in,
            judge_reasons_in=judge_reasons_in,
            synthetic=synthetic,
            enfguard_ms_in=enfguard_ms_in,
            stream=stream_requested,
        )

    if "WarnRequest" in cau_in:
        normalized = handle_warn_request(
            NormalizedResponse(api_format=api_format),
            cau_in["WarnRequest"],
            judge_reasons_in,
        )
        inbound_warning = normalized.warn_message

    if stream_requested:
        return await _run_streaming_request(
            request=request,
            body=body,
            tid=tid,
            sid=sid,
            api_format=api_format,
            provider=provider,
            upstream_call=upstream_call,
            normalize=normalize,
            serialize=serialize,
            synthetic=synthetic,
            active_policies=active_policies,
            inbound_events=inbound_events,
            cau_in=cau_in,
            inbound_warning=inbound_warning,
            enfguard_ms_in=enfguard_ms_in,
        )

    # Audit / replay mode: when a caller passes an ``x-synthetic-completion``
    # header (or ``request.metadata.synthetic_completion`` in the body), we
    # skip the upstream chat-model call and feed the supplied text into the
    # outbound enforcement pipeline as if the model had produced it. 
    synthetic_text = _extract_synthetic_completion(request, body)
    if synthetic_text is not None:
        upstream_ms = 0
        raw_response = _build_synthetic_upstream(api_format, synthetic_text, body.get("model"))
    else:
        upstream_started_at = time.monotonic()
        upstream = await upstream_call()
        upstream_ms = int((time.monotonic() - upstream_started_at) * 1000)
        if upstream.status_code < 200 or upstream.status_code >= 300:
            error_body = _response_json_or_text(upstream)
            return JSONResponse(content=error_body, status_code=upstream.status_code)

        raw_response = upstream.json()
    outbound_events = extract_outbound_events(
        tid=tid,
        request=body,
        response=raw_response,
        api_format=api_format,
        active_policies=active_policies,
    )
    state.record_proposing_tools(sid, collect_proposing_tools(outbound_events))
    state.record_tool_origins(sid, collect_tool_origins(outbound_events))
    outbound_events = _clock_events(tid, "response") + state.switches.emit_events(tid) + outbound_events
    preeval_events = inbound_events + outbound_events if _aggressive_batching_enabled() else outbound_events
    cau_out, judge_reasons_out, enfguard_ms_out = await _phase2_enforce(tid, sid, outbound_events, preeval_events)
    cau_out = await _resolve_approvals(tid, sid, cau_out, "outbound")

    normalized, action, reason = _apply_outbound_verdict(
        tid=tid,
        raw_response=raw_response,
        normalize=normalize,
        cau_out=cau_out,
        judge_reasons_out=judge_reasons_out,
        inbound_warning=inbound_warning,
    )
    _finalize_session_record(
        tid,
        sid,
        provider,
        action,
        inbound_events,
        outbound_events,
        cau_in,
        cau_out,
        enfguard_ms_in=enfguard_ms_in,
        enfguard_ms_out=enfguard_ms_out,
        upstream_ms=upstream_ms,
    )
    return JSONResponse(
        content=serialize(normalized),
        headers=_enforcement_headers(action, reason, tid),
    )


async def _phase1_enforce(
    tid: int,
    sid: str,
    inbound_events: list[Event],
) -> tuple[dict[str, list[tuple[Any, ...]]], dict[str, str], int]:
    """Run inbound enforcement and return ``(cau, reasons, enfguard_ms)``.

    ``enfguard_ms`` is the wall-clock time spent inside the
    ``_logger().log`` call alone — i.e. the OCaml binary's evaluation
    cost for this phase. Pre-evaluation (judge HTTP) is excluded; that
    is already attributed to per-predicate ``latency_ms`` rows.
    """

    cau_in, _sup_in, enfguard_ms = await _phase1_enforce_raw(tid, sid, inbound_events, "inbound")
    cau_in = _adapt_v4_verdicts(cau_in)
    cau_in = _normalise_phase1_causations(cau_in, tid, sid, "inbound")
    return cau_in, _read_trace_reasons(tid, sid, "inbound"), enfguard_ms


async def _tool_phase_enforce(
    tid: int,
    sid: str,
    tool_events: list[Event],
    call_id: str,
    suppress_block_events: tuple[str, ...],
) -> tuple[dict[str, list[tuple[Any, ...]]], dict[str, str], int]:
    """Run tool-hook enforcement and treat suppressed tool facts as blocks."""

    cau_in, sup_in, enfguard_ms = await _phase1_enforce_raw(tid, sid, tool_events, "tool")
    cau_in = _adapt_v4_verdicts(cau_in)
    _add_tool_suppression_blocks(cau_in, sup_in, tid, call_id, suppress_block_events)
    cau_in = _normalise_phase1_causations(cau_in, tid, sid, "tool")
    return cau_in, _read_trace_reasons(tid, sid, "tool"), enfguard_ms


async def _phase1_enforce_raw(
    tid: int,
    sid: str,
    inbound_events: list[Event],
    phase: str,
) -> tuple[dict[str, list[tuple[Any, ...]]], dict[str, list[tuple[Any, ...]]], int]:
    calls = None if _aggressive_batching_enabled() else _active_predicate_calls()
    async with state.enforcement_lock:
        write_current_context(tid=tid, sid=sid, phase=phase, dry_run=_dry_run_enabled())
        await asyncio.to_thread(pre_evaluate, inbound_events, calls)
        started_at = time.monotonic()
        _, _, cau_in, sup_in = await asyncio.to_thread(_logger().log, inbound_events, tid)
        enfguard_ms = int((time.monotonic() - started_at) * 1000)
    return cau_in, sup_in, enfguard_ms


def _normalise_phase1_causations(
    cau_in: dict[str, list[tuple[Any, ...]]],
    tid: int,
    sid: str,
    phase: str,
) -> dict[str, list[tuple[Any, ...]]]:
    cau_in = _demote_warn_failures(cau_in, tid, sid, phase)
    cau_in = _apply_enforcement_mode(cau_in)
    return cau_in


async def _phase2_enforce(
    tid: int,
    sid: str,
    outbound_events: list[Event],
    preeval_events: list[Event] | None = None,
) -> tuple[dict[str, list[tuple[Any, ...]]], dict[str, str], int]:
    calls = None if _aggressive_batching_enabled() else _active_predicate_calls()
    async with state.enforcement_lock:
        write_current_context(tid=tid, sid=sid, phase="outbound", dry_run=_dry_run_enabled())
        await asyncio.to_thread(pre_evaluate, preeval_events or outbound_events, calls)
        started_at = time.monotonic()
        _, _, cau_out, sup_out = await asyncio.to_thread(_logger().log, outbound_events, tid)
        enfguard_ms = int((time.monotonic() - started_at) * 1000)
    cau_out = _adapt_v4_verdicts(cau_out)
    _add_response_suppression_blocks(cau_out, sup_out, tid, ("Completion",))
    cau_out = _demote_warn_failures(cau_out, tid, sid, "outbound")
    cau_out = _apply_enforcement_mode(cau_out)
    return cau_out, _read_trace_reasons(tid, sid, "outbound"), enfguard_ms


def _active_predicate_calls() -> dict[str, list[PredicateCall]]:
    """Return ``predicate_calls`` filtered to predicates whose policies are active.

    A predicate that appears in a clause without a ``PolicyActive`` gate
    (``frozenset()`` in the policy index) is always retained: there is no
    operator knob to disable it, so skipping pre-eval would silently change
    enforcement behaviour.
    """

    policies = state.predicate_policies
    if not policies:
        return state.predicate_calls
    active = set(_active_policies())
    keep: set[str] = {
        name
        for name, gating in policies.items()
        if not gating or gating & active
    }
    filtered: dict[str, list[PredicateCall]] = {}
    for event_name, calls in state.predicate_calls.items():
        kept = [call for call in calls if call.predicate in keep]
        if kept:
            filtered[event_name] = kept
    return filtered


def _blocked_inbound_response(
    tid: int,
    sid: str,
    provider: str,
    api_format: str,
    inbound_events: list[Event],
    cau_in: dict[str, list[tuple[Any, ...]]],
    judge_reasons_in: dict[str, str],
    synthetic,
    enfguard_ms_in: int = 0,
    stream: bool = False,
) -> JSONResponse | Response:
    normalized = handle_block_request(
        NormalizedResponse(api_format=api_format),
        cau_in["BlockRequest"],
        judge_reasons_in,
    )
    if "WarnRequest" in cau_in:
        warning = handle_warn_request(
            NormalizedResponse(api_format=api_format),
            cau_in["WarnRequest"],
            judge_reasons_in,
        )
        normalized.warned = True
        normalized.warn_entries = warning.warn_entries
        normalized.warn_message = warning.warn_message
        normalized = surface_warning_on_block(normalized, warning.warn_message)
        
    _append_session_log(
        sid,
        _session_record(
            tid,
            provider,
            "request_blocked",
            inbound_events,
            verdicts=_verdict_entries(cau_in, ("BlockRequest", "WarnRequest")),
            verdict_events=_verdict_events(tid, cau_in),
            enfguard_ms_in=enfguard_ms_in,
        ),
    )
    headers = _enforcement_headers("request_blocked", normalized.block_reason, tid)
    body = synthetic(normalized.block_reason)
    if stream and api_format == "anthropic":
        return _anthropic_sse_response(body, headers=headers)
    if stream and api_format == "openai":
        return _openai_sse_response(body, headers=headers)
    return JSONResponse(content=body, headers=headers)


async def _run_streaming_request(
    request: Request,
    body: JsonObject,
    tid: int,
    sid: str,
    api_format: str,
    provider: str,
    upstream_call,
    normalize,
    serialize,
    synthetic,
    active_policies: list[str],
    inbound_events: list[Event],
    cau_in: dict[str, list[tuple[Any, ...]]],
    inbound_warning: str,
    enfguard_ms_in: int,
) -> Response | JSONResponse:
    """Buffer an upstream streaming response, enforce outbound, then release SSE.

    Claude Agent SDK requests Anthropic Messages with ``stream: true``. The
    policy engine still wants complete response events, so this path buffers the
    upstream SSE body, reconstructs the final message JSON, runs normal Phase-2
    enforcement, and then releases either the original SSE or an EnfGuard-made
    replacement stream.
    """

    if api_format not in ("anthropic", "openai"):
        reason = "streaming is implemented for Anthropic Messages and OpenAI Chat Completions only"
        return JSONResponse(
            content=synthetic(reason),
            status_code=501,
            headers=_enforcement_headers("stream_unsupported", reason, tid),
        )

    synthetic_text = _extract_synthetic_completion(request, body)
    if synthetic_text is not None:
        upstream_ms = 0
        raw_response = _build_synthetic_upstream(api_format, synthetic_text, body.get("model"))
        if api_format == "anthropic":
            upstream_content = _anthropic_message_to_sse(raw_response).encode("utf-8")
        else:
            upstream_content = _openai_message_to_sse(raw_response).encode("utf-8")
    else:
        upstream_started_at = time.monotonic()
        upstream = await upstream_call()
        upstream_ms = int((time.monotonic() - upstream_started_at) * 1000)
        if upstream.status_code < 200 or upstream.status_code >= 300:
            error_body = _response_json_or_text(upstream)
            return JSONResponse(content=error_body, status_code=upstream.status_code)
        upstream_content = upstream.content
        if api_format == "anthropic":
            raw_response = _anthropic_stream_to_message(upstream.text, body.get("model"))
        else:
            raw_response = _openai_stream_to_message(upstream.text, body.get("model"))

    outbound_events = extract_outbound_events(
        tid=tid,
        request=body,
        response=raw_response,
        api_format=api_format,
        active_policies=active_policies,
    )
    state.record_proposing_tools(sid, collect_proposing_tools(outbound_events))
    state.record_tool_origins(sid, collect_tool_origins(outbound_events))
    outbound_events = _clock_events(tid, "response") + state.switches.emit_events(tid) + outbound_events
    preeval_events = inbound_events + outbound_events if _aggressive_batching_enabled() else outbound_events
    cau_out, judge_reasons_out, enfguard_ms_out = await _phase2_enforce(
        tid,
        sid,
        outbound_events,
        preeval_events,
    )
    cau_out = await _resolve_approvals(tid, sid, cau_out, "outbound")

    normalized, action, reason = _apply_outbound_verdict(
        tid=tid,
        raw_response=raw_response,
        normalize=normalize,
        cau_out=cau_out,
        judge_reasons_out=judge_reasons_out,
        inbound_warning=inbound_warning,
    )
    _finalize_session_record(
        tid,
        sid,
        provider,
        action,
        inbound_events,
        outbound_events,
        cau_in,
        cau_out,
        enfguard_ms_in=enfguard_ms_in,
        enfguard_ms_out=enfguard_ms_out,
        upstream_ms=upstream_ms,
    )

    headers = _enforcement_headers(action, reason, tid)
    if action == "allowed":
        return Response(content=upstream_content, media_type="text/event-stream", headers=headers)
    if api_format == "anthropic":
        return _anthropic_sse_response(serialize(normalized), headers=headers)
    return _openai_sse_response(serialize(normalized), headers=headers)


def _anthropic_sse_response(message: JsonObject, headers: dict[str, str] | None = None) -> Response:
    return Response(
        content=_anthropic_message_to_sse(message),
        media_type="text/event-stream",
        headers=headers,
    )


def _openai_sse_response(message: JsonObject, headers: dict[str, str] | None = None) -> Response:
    return Response(
        content=_openai_message_to_sse(message),
        media_type="text/event-stream",
        headers=headers,
    )


def _openai_stream_to_message(stream_text: str, fallback_model: Any = None) -> JsonObject:
    """Reconstruct a final OpenAI chat.completion JSON from a buffered SSE body.

    Mirrors _anthropic_stream_to_message: parse the buffered `data: {...}` chunks,
    concatenate `choices[0].delta.content` and any streamed tool-call arguments,
    and build the non-streamed chat.completion shape that normalize_openai expects.
    """
    message_id = "chatcmpl-stream-buffered"
    model = str(fallback_model or "")
    created = int(time.time())
    role = "assistant"
    content_parts: list[str] = []
    finish_reason: Any = None
    tool_calls: dict[int, JsonObject] = {}
    tool_arg_parts: dict[int, list[str]] = {}
    usage: JsonObject = {}

    for payload in _sse_json_payloads(stream_text):
        if payload.get("id"):
            message_id = str(payload["id"])
        if payload.get("model"):
            model = str(payload["model"])
        if payload.get("created"):
            created = _int(payload.get("created"), created)
        if isinstance(payload.get("usage"), dict) and payload["usage"]:
            usage = payload["usage"]
        choices = payload.get("choices") if isinstance(payload.get("choices"), list) else []
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            if choice.get("finish_reason"):
                finish_reason = choice.get("finish_reason")
            delta = choice.get("delta") if isinstance(choice.get("delta"), dict) else {}
            if delta.get("role"):
                role = str(delta.get("role"))
            piece = delta.get("content")
            if isinstance(piece, str):
                content_parts.append(piece)
            tcs = delta.get("tool_calls") if isinstance(delta.get("tool_calls"), list) else []
            for tc in tcs:
                if not isinstance(tc, dict):
                    continue
                idx = _int(tc.get("index"), 0)
                slot = tool_calls.setdefault(
                    idx, {"id": "", "type": "function", "function": {"name": "", "arguments": ""}}
                )
                if tc.get("id"):
                    slot["id"] = str(tc.get("id"))
                fn = tc.get("function") if isinstance(tc.get("function"), dict) else {}
                if fn.get("name"):
                    slot["function"]["name"] = str(fn.get("name"))
                if isinstance(fn.get("arguments"), str):
                    tool_arg_parts.setdefault(idx, []).append(fn["arguments"])

    msg: JsonObject = {"role": role, "content": "".join(content_parts)}
    if tool_calls:
        assembled = []
        for idx in sorted(tool_calls):
            slot = tool_calls[idx]
            slot["function"]["arguments"] = "".join(tool_arg_parts.get(idx, []))
            assembled.append(slot)
        msg["tool_calls"] = assembled
    return {
        "id": message_id,
        "object": "chat.completion",
        "created": created,
        "model": model,
        "choices": [{"index": 0, "message": msg, "finish_reason": finish_reason}],
        "usage": usage or {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


def _openai_message_to_sse(message: JsonObject) -> str:
    """Serialize an OpenAI chat.completion response as a minimal SSE stream."""
    choices = message.get("choices") if isinstance(message.get("choices"), list) else []
    first = choices[0] if choices and isinstance(choices[0], dict) else {}
    inner = first.get("message") if isinstance(first.get("message"), dict) else {}
    content = inner.get("content")
    content = content if isinstance(content, str) else ""
    finish = first.get("finish_reason") or "stop"
    base = {
        "id": str(message.get("id") or "chatcmpl-enfguard"),
        "object": "chat.completion.chunk",
        "created": _int(message.get("created"), int(time.time())),
        "model": str(message.get("model") or ""),
    }

    def _chunk(delta: JsonObject, finish_reason: Any = None) -> str:
        payload = dict(base)
        payload["choices"] = [{"index": 0, "delta": delta, "finish_reason": finish_reason}]
        return "data: " + json.dumps(payload) + "\n\n"

    parts = [_chunk({"role": "assistant"})]
    if content:
        parts.append(_chunk({"content": content}))
    parts.append(_chunk({}, finish))
    parts.append("data: [DONE]\n\n")
    return "".join(parts)


def _anthropic_message_to_sse(message: JsonObject) -> str:
    """Serialize an Anthropic Messages response as a minimal SSE stream."""

    msg = dict(message)
    content = msg.get("content") if isinstance(msg.get("content"), list) else []
    msg["content"] = []
    events: list[tuple[str, JsonObject]] = [
        ("message_start", {"type": "message_start", "message": msg}),
    ]
    for index, block in enumerate(content):
        if not isinstance(block, dict):
            continue
        block_type = str(block.get("type") or "")
        if block_type == "text":
            events.append(
                (
                    "content_block_start",
                    {
                        "type": "content_block_start",
                        "index": index,
                        "content_block": {"type": "text", "text": ""},
                    },
                )
            )
            text = str(block.get("text") or "")
            if text:
                events.append(
                    (
                        "content_block_delta",
                        {
                            "type": "content_block_delta",
                            "index": index,
                            "delta": {"type": "text_delta", "text": text},
                        },
                    )
                )
            events.append(("content_block_stop", {"type": "content_block_stop", "index": index}))
        elif block_type == "tool_use":
            events.append(
                (
                    "content_block_start",
                    {
                        "type": "content_block_start",
                        "index": index,
                        "content_block": {
                            "type": "tool_use",
                            "id": str(block.get("id") or ""),
                            "name": str(block.get("name") or ""),
                            "input": {},
                        },
                    },
                )
            )
            events.append(
                (
                    "content_block_delta",
                    {
                        "type": "content_block_delta",
                        "index": index,
                        "delta": {
                            "type": "input_json_delta",
                            "partial_json": json.dumps(block.get("input") or {}),
                        },
                    },
                )
            )
            events.append(("content_block_stop", {"type": "content_block_stop", "index": index}))

    events.append(
        (
            "message_delta",
            {
                "type": "message_delta",
                "delta": {
                    "stop_reason": message.get("stop_reason") or "end_turn",
                    "stop_sequence": message.get("stop_sequence"),
                },
                "usage": {
                    "output_tokens": (
                        message.get("usage", {}).get("output_tokens", 0)
                        if isinstance(message.get("usage"), dict)
                        else 0
                    )
                },
            },
        )
    )
    events.append(("message_stop", {"type": "message_stop"}))
    return "".join(
        f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
        for event, data in events
    )


def _anthropic_stream_to_message(stream_text: str, fallback_model: Any = None) -> JsonObject:
    """Reconstruct final Anthropic message JSON from a buffered SSE body."""

    message: JsonObject = {
        "id": "msg_stream_buffered",
        "type": "message",
        "role": "assistant",
        "model": str(fallback_model or ""),
        "content": [],
        "stop_reason": None,
        "stop_sequence": None,
        "usage": {"input_tokens": 0, "output_tokens": 0},
    }
    blocks: dict[int, JsonObject] = {}
    input_json_parts: dict[int, list[str]] = {}

    for payload in _sse_json_payloads(stream_text):
        event_type = str(payload.get("type") or "")
        if event_type == "message_start" and isinstance(payload.get("message"), dict):
            started = dict(payload["message"])
            started["content"] = []
            message.update(started)
            continue
        if event_type == "content_block_start":
            index = _int(payload.get("index"), len(blocks))
            block = payload.get("content_block") if isinstance(payload.get("content_block"), dict) else {}
            blocks[index] = dict(block)
            if blocks[index].get("type") == "tool_use":
                blocks[index].setdefault("input", {})
                input_json_parts.setdefault(index, [])
            continue
        if event_type == "content_block_delta":
            index = _int(payload.get("index"), 0)
            delta = payload.get("delta") if isinstance(payload.get("delta"), dict) else {}
            delta_type = str(delta.get("type") or "")
            block = blocks.setdefault(index, {"type": "text", "text": ""})
            if delta_type == "text_delta":
                block["type"] = "text"
                block["text"] = str(block.get("text") or "") + str(delta.get("text") or "")
            elif delta_type == "input_json_delta":
                input_json_parts.setdefault(index, []).append(str(delta.get("partial_json") or ""))
            continue
        if event_type == "content_block_stop":
            index = _int(payload.get("index"), 0)
            if index in input_json_parts:
                raw_input = "".join(input_json_parts[index])
                try:
                    blocks.setdefault(index, {})["input"] = json.loads(raw_input or "{}")
                except json.JSONDecodeError:
                    blocks.setdefault(index, {})["input"] = {"_raw": raw_input}
            continue
        if event_type == "message_delta":
            delta = payload.get("delta") if isinstance(payload.get("delta"), dict) else {}
            if "stop_reason" in delta:
                message["stop_reason"] = delta.get("stop_reason")
            if "stop_sequence" in delta:
                message["stop_sequence"] = delta.get("stop_sequence")
            usage = payload.get("usage") if isinstance(payload.get("usage"), dict) else {}
            if usage:
                current = message.get("usage") if isinstance(message.get("usage"), dict) else {}
                message["usage"] = {**current, **usage}

    message["content"] = [blocks[index] for index in sorted(blocks)]
    return message


def _sse_json_payloads(stream_text: str) -> list[JsonObject]:
    payloads: list[JsonObject] = []
    data_lines: list[str] = []
    for line in stream_text.splitlines():
        if line.startswith("data:"):
            data_lines.append(line.removeprefix("data:").strip())
            continue
        if line.strip():
            continue
        if data_lines:
            raw = "\n".join(data_lines)
            data_lines = []
            if raw and raw != "[DONE]":
                try:
                    value = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if isinstance(value, dict):
                    payloads.append(value)
    if data_lines:
        raw = "\n".join(data_lines)
        if raw and raw != "[DONE]":
            try:
                value = json.loads(raw)
            except json.JSONDecodeError:
                value = None
            if isinstance(value, dict):
                payloads.append(value)
    return payloads


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _apply_outbound_verdict(
    tid: int,
    raw_response: JsonObject,
    normalize,
    cau_out: dict[str, list[tuple[Any, ...]]],
    judge_reasons_out: dict[str, str],
    inbound_warning: str,
) -> tuple[NormalizedResponse, str, str]:
    normalized = normalize(raw_response)
    action = "allowed"
    reason = ""
    if "BlockResponse" in cau_out:
        normalized = handle_block_response(normalized, cau_out["BlockResponse"], judge_reasons_out)
        if "WarnResponse" in cau_out:
            warning = handle_warn_response(normalized, cau_out["WarnResponse"], judge_reasons_out)
            normalized.warned = True
            normalized.warn_entries = warning.warn_entries
            normalized.warn_message = warning.warn_message
            normalized = surface_warning_on_block(normalized, warning.warn_message)

        action = "response_blocked"
        reason = normalized.block_reason
    elif "WarnResponse" in cau_out:
        normalized = handle_warn_response(normalized, cau_out["WarnResponse"], judge_reasons_out)
        action = "response_warned"
        reason = normalized.warn_message
        _log_released(tid, normalized)
    else:
        _log_released(tid, normalized)

    if inbound_warning:
        if normalized.blocked:
            normalized = surface_warning_on_block(normalized, inbound_warning)
            reason = normalized.block_reason
        else:
            normalized = merge_warning_message(normalized, inbound_warning)
            action = "request_warned" if action == "allowed" else action
            reason = inbound_warning if not reason else f"{inbound_warning}\n\n{reason}"
    return normalized, action, reason


def _finalize_session_record(
    tid: int,
    sid: str,
    provider: str,
    action: str,
    inbound_events: list[Event],
    outbound_events: list[Event],
    cau_in: dict[str, list[tuple[Any, ...]]],
    cau_out: dict[str, list[tuple[Any, ...]]],
    enfguard_ms_in: int = 0,
    enfguard_ms_out: int = 0,
    upstream_ms: int = 0,
) -> None:
    _append_session_log(
        sid,
        _session_record(
            tid,
            provider,
            action,
            inbound_events,
            outbound_events,
            verdicts=[
                *_verdict_entries(cau_in, ("WarnRequest",)),
                *_verdict_entries(cau_out, ("BlockResponse", "WarnResponse")),
            ],
            verdict_events=_verdict_events(tid, cau_in, cau_out),
            enfguard_ms_in=enfguard_ms_in,
            enfguard_ms_out=enfguard_ms_out,
            upstream_ms=upstream_ms,
        ),
    )


async def _post_anthropic(request: Request, body: JsonObject) -> httpx.Response:
    client = _http()
    api_key = request.headers.get("x-api-key") or state.config.anthropic_api_key
    headers = {
        "content-type": "application/json",
        "anthropic-version": request.headers.get("anthropic-version", "2023-06-01"),
    }
    if api_key:
        headers["x-api-key"] = api_key
    if request.headers.get("anthropic-beta"):
        headers["anthropic-beta"] = request.headers["anthropic-beta"]
    return await _post_upstream_with_retry(
        f"{state.config.anthropic_base_url}/v1/messages", body, headers
    )


async def _post_openai(request: Request, body: JsonObject) -> httpx.Response:
    authorization = request.headers.get("authorization")
    if not authorization and state.config.openai_api_key:
        authorization = f"Bearer {state.config.openai_api_key}"
    headers = {"content-type": "application/json"}
    if authorization:
        headers["authorization"] = authorization
    return await _post_upstream_with_retry(
        f"{state.config.openai_base_url}/v1/chat/completions", body, headers
    )


def _upstream_retry_config() -> tuple[int, float, float]:
    """Read bounded upstream retry settings for transient provider failures.

    The defaults preserve the ordinary proxy behaviour.  Evaluation drivers can
    opt in through the environment when a provider's rate limit should delay a
    request rather than turn a complete batch into a transport failure.
    """
    try:
        attempts = max(1, int(os.getenv("ENFGUARD_UPSTREAM_MAX_ATTEMPTS", "1")))
    except ValueError:
        attempts = 1
    try:
        initial = max(0.1, float(os.getenv("ENFGUARD_UPSTREAM_INITIAL_BACKOFF_SECONDS", "1")))
    except ValueError:
        initial = 1.0
    try:
        maximum = max(initial, float(os.getenv("ENFGUARD_UPSTREAM_MAX_BACKOFF_SECONDS", "30")))
    except ValueError:
        maximum = max(initial, 30.0)
    return attempts, initial, maximum


def _retry_after_seconds(response: httpx.Response, fallback: float) -> float:
    try:
        return max(0.0, float(response.headers.get("retry-after", fallback)))
    except (TypeError, ValueError):
        return fallback


async def _post_upstream_with_retry(
    url: str, body: JsonObject, headers: dict[str, str]
) -> httpx.Response:
    """Retry only transient upstream failures before a response is released."""
    attempts, initial_backoff, maximum_backoff = _upstream_retry_config()
    client = _http()
    for attempt in range(1, attempts + 1):
        try:
            response = await client.post(url, json=body, headers=headers)
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout):
            if attempt == attempts:
                raise
            delay = min(maximum_backoff, initial_backoff * 2 ** (attempt - 1))
            await asyncio.sleep(delay)
            continue
        if response.status_code not in {429, 500, 502, 503, 504} or attempt == attempts:
            return response
        fallback = min(maximum_backoff, initial_backoff * 2 ** (attempt - 1))
        await asyncio.sleep(min(maximum_backoff, _retry_after_seconds(response, fallback)))
    raise AssertionError("unreachable")


async def _post_ollama(body: JsonObject) -> httpx.Response:
    client = _http()
    upstream = await client.post(
        f"{state.config.ollama_base_url}/api/chat",
        json=_ollama_request_from_openai(body),
        headers={"content-type": "application/json"},
    )
    if upstream.status_code < 200 or upstream.status_code >= 300:
        return upstream

    adapted = _ollama_to_openai_response(upstream.json(), body)
    return httpx.Response(
        status_code=200,
        content=json.dumps(adapted).encode("utf-8"),
        headers={"content-type": "application/json"},
        request=upstream.request,
        extensions=upstream.extensions,
    )


def _ollama_request_from_openai(body: JsonObject) -> JsonObject:
    options: JsonObject = {}
    if body.get("temperature") is not None:
        options["temperature"] = body["temperature"]
    if body.get("top_p") is not None:
        options["top_p"] = body["top_p"]
    if body.get("max_tokens") is not None:
        options["num_predict"] = body["max_tokens"]
    if body.get("max_completion_tokens") is not None:
        options["num_predict"] = body["max_completion_tokens"]

    request = {
        "model": body.get("model"),
        "messages": body.get("messages", []),
        "stream": False,
    }
    if options:
        request["options"] = options
    return request


def _ollama_to_openai_response(response: JsonObject, request_body: JsonObject) -> JsonObject:
    message = response.get("message") if isinstance(response.get("message"), dict) else {}
    prompt_tokens = _int_value(response.get("prompt_eval_count"))
    completion_tokens = _int_value(response.get("eval_count"))
    created = str(response.get("created_at", "ollama-chat"))
    return {
        "id": f"chatcmpl-ollama-{hashlib.blake2b(created.encode('utf-8'), digest_size=6).hexdigest()}",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": str(message.get("role", "assistant")),
                    "content": str(message.get("content", "") or ""),
                },
                "finish_reason": response.get("done_reason")
                or ("stop" if response.get("done", True) else "length"),
            }
        ],
        "model": str(response.get("model") or request_body.get("model", "")),
        "system_fingerprint": "ollama-local",
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        },
    }


_active_policies_cache: dict[str, Any] = {"path": None, "mtime": -1.0, "value": []}
_active_policies_cache_lock = threading.Lock()


def _active_policies() -> list[str]:
    """Return the active-policy ids, mtime-cached so the file isn't re-read per request."""

    path = state.config.state_dir / "active_policies.json"
    with _active_policies_cache_lock:
        cache = _active_policies_cache
        try:
            mtime = path.stat().st_mtime
        except FileNotFoundError:
            if cache["mtime"] != -1.0:
                cache.update({"path": path, "mtime": -1.0, "value": []})
            return []

        if cache["path"] != path or mtime != cache["mtime"]:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                data = {}
            active = data.get("active") if isinstance(data, dict) else []
            if not isinstance(active, list):
                active = []
            cache.update(
                {
                    "path": path,
                    "mtime": mtime,
                    "value": [str(item) for item in active if item],
                }
            )
        return list(cache["value"])


def _invalidate_active_policies_cache() -> None:
    with _active_policies_cache_lock:
        _active_policies_cache.update({"path": None, "mtime": -1.0, "value": []})


def _read_policy_state() -> JsonObject:
    path = state.config.state_dir / "active_policies.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        value = {}
    return value if isinstance(value, dict) else {}


def _append_feedback_log(event: Event) -> None:
    """Persist asynchronous feedback without sending old tids to EnfGuard.

    UI feedback and judge overrides often arrive after the monitored turn has
    completed. Sending those historical timestamps into the live EnfGuard
    process can desynchronise the stdout reader queue before the next request,
    so only active approval decisions go through ``log_only``. Everything else
    is still kept as structured evidence in ``logs/feedback.jsonl``.
    """

    try:
        path = state.config.logs_dir / "feedback.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    {"ts": time.time(), "event": _event_to_dict(event)},
                    ensure_ascii=False,
                )
                + "\n"
            )
    except OSError:
        return


def _clear_trace_logs() -> bool:
    """Remove local trace/session artifacts before a fresh benchmark run."""

    removed_any = False
    candidates = [
        state.config.trace_store_file,
        state.config.logs_dir / "feedback.jsonl",
    ]
    try:
        candidates.extend(state.config.logs_dir.glob("session_*.jsonl"))
        candidates.extend(state.config.logs_dir.glob("session_*.tokens"))
        candidates.extend((state.config.logs_dir / "traces").glob("tid_*.jsonl"))
    except OSError:
        pass
    for path in candidates:
        try:
            path.unlink()
            removed_any = True
        except FileNotFoundError:
            continue
        except OSError:
            continue
    return removed_any


def _sync_switch_value_to_policy_state(switch_id: str, normalized: str) -> None:
    """Mirror live switch updates into the policy state read by judge selectors."""

    current = _read_policy_state()
    switches = current.get("switches")
    if isinstance(switches, list):
        synced: list[Any] = []
        for entry in switches:
            if isinstance(entry, dict) and str(entry.get("id", "") or "") == switch_id:
                synced.append({**entry, "current": normalized})
            else:
                synced.append(entry)
        current["switches"] = synced

    if switch_id in {"judge_strategy", "judge_call_mode"}:
        runtime = current.get("runtime")
        if not isinstance(runtime, dict):
            runtime = {}
        runtime[switch_id] = normalized
        current["runtime"] = runtime

    _write_json_atomic(state.config.state_dir / "active_policies.json", current)
    _invalidate_active_policies_cache()


def _dry_run_enabled() -> bool:
    """Back-compat predicate: true whenever global mode is non-enforcing."""

    return _enforcement_mode() in {"audit", "warn"}


def _enforcement_mode() -> str:
    """Return the global audit/warn/enforce operational mode."""

    if state.switches.has(ENFORCEMENT_MODE_SWITCH_ID):
        mode = state.switches.get_value(ENFORCEMENT_MODE_SWITCH_ID).strip().lower()
        if mode in ENFORCEMENT_MODE_CHOICES:
            return mode
    if state.switches.has(DRY_RUN_SWITCH_ID) and state.switches.get_bool(DRY_RUN_SWITCH_ID):
        return "warn"
    return "enforce"


def _feedback_enabled() -> bool:
    feedback = _read_policy_state().get("feedback")
    if not isinstance(feedback, dict):
        return True
    return bool(feedback.get("enabled", True))


def _runtime_options() -> JsonObject:
    runtime = _read_policy_state().get("runtime")
    return runtime if isinstance(runtime, dict) else {}


def _aggressive_batching_enabled() -> bool:
    return str(_runtime_options().get("judge_batching", "conservative") or "").lower() == "aggressive"


def _trusted_tool_names() -> frozenset[str]:
    """Tools whose results should NOT be tagged as untrusted.

    Loaded from ``backend.trusted_tool_names`` on every YAML reload and
    snapshotted onto ``state``. Reading from ``state`` is safe under the
    enforcement lock because reloads swap the snapshot atomically.
    """

    return state.trusted_tool_names


def _trace_assistant_content_enabled() -> bool:
    return bool(_runtime_options().get("trace_assistant_content", True))


def _human_approval_from_state(value: JsonObject) -> HumanApprovalConfig:
    enabled = bool(value.get("enabled", False))
    try:
        timeout_seconds = int(value.get("timeout_seconds", 60) or 60)
    except (TypeError, ValueError):
        timeout_seconds = 60
    timeout_seconds = max(1, timeout_seconds)
    on_timeout = str(value.get("on_timeout", "block") or "block").strip().lower()
    if on_timeout not in {"allow", "warn", "block"}:
        on_timeout = "block"
    return HumanApprovalConfig(
        enabled=enabled,
        timeout_seconds=timeout_seconds,
        on_timeout=on_timeout,
    )


def _live_policy_path() -> Path:
    return state.config.state_dir / _LIVE_POLICIES_FILENAME


def _normalize_live_policy_payload(value: JsonObject) -> JsonObject:
    policy_id = str(value.get("id", "") or "").strip()
    if not _LIVE_POLICY_ID_RE.match(policy_id):
        raise HTTPException(
            status_code=422,
            detail="live policy id must start with a letter or underscore and contain only letters, numbers, and underscores",
        )
    mfotl = str(value.get("mfotl", "") or "").strip()
    if not mfotl:
        raise HTTPException(status_code=422, detail="live policy MFOTL must not be empty")
    expected_gate = f'PolicyActive(t, "{policy_id}")'
    if expected_gate not in mfotl:
        raise HTTPException(
            status_code=422,
            detail=f"live policy must reference {expected_gate!r} so the UI toggle works",
        )
    raw_scope = value.get("scope", _LIVE_POLICY_DEFAULT_SCOPE)
    scope = str(raw_scope or _LIVE_POLICY_DEFAULT_SCOPE).strip().lower()
    if scope not in _LIVE_POLICY_VALID_SCOPES:
        raise HTTPException(
            status_code=422,
            detail=(
                f"live policy scope must be one of {sorted(_LIVE_POLICY_VALID_SCOPES)} "
                f"(got {raw_scope!r})"
            ),
        )
    policy: JsonObject = {
        "id": policy_id,
        "enabled": _bool_like(value.get("enabled", True)),
        "mfotl": mfotl,
        "scope": scope,
    }
    if "threshold" in value and value.get("threshold") not in (None, ""):
        try:
            policy["threshold"] = float(value["threshold"])
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail="live policy threshold must be numeric") from exc
    return policy


def _bool_like(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() not in {"", "0", "false", "no", "off"}
    return bool(value)


def _purge_session_scoped_live_policies() -> None:
    """Drop session-scoped live overlays at proxy startup.

    Live policies installed without ``scope: persistent`` are scratch-pad
    additions for the current proxy run only. We strip them from
    ``state/live_policies.json`` before the first reload so the next run
    starts from the pure YAML + persistent-overlay set. The file is
    rewritten only if at least one entry is dropped, to keep mtime stable
    when there's nothing to purge.
    """

    path = _live_policy_path()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[live_policy] could not read {path} during startup purge: {exc}", flush=True)
        return
    items = raw.get("policies") if isinstance(raw, dict) else raw
    if not isinstance(items, list):
        return
    survivors: list[JsonObject] = []
    dropped: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        scope = str(item.get("scope", _LIVE_POLICY_DEFAULT_SCOPE) or _LIVE_POLICY_DEFAULT_SCOPE).strip().lower()
        if scope == "persistent":
            survivors.append(item)
        else:
            dropped.append(str(item.get("id", "") or ""))
    if not dropped:
        return
    _write_json_atomic(path, {"policies": survivors})
    print(
        f"[live_policy] dropped {len(dropped)} session-scoped live policies at startup: "
        f"{', '.join(filter(None, dropped))}",
        flush=True,
    )


def _read_live_policy_store(path: Path | None = None) -> list[JsonObject]:
    policy_path = path or _live_policy_path()
    try:
        raw = json.loads(policy_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=422, detail=f"invalid live policy store: {exc}") from exc
    items = raw.get("policies") if isinstance(raw, dict) else raw
    if not isinstance(items, list):
        raise HTTPException(status_code=422, detail="live policy store must contain a policies list")
    policies: list[JsonObject] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        policies.append(_normalize_live_policy_payload(item))
    return policies


def _upsert_live_policy(policies: list[JsonObject], policy: JsonObject) -> list[JsonObject]:
    replaced = False
    next_policies: list[JsonObject] = []
    for current in policies:
        if current.get("id") == policy["id"]:
            next_policies.append(policy)
            replaced = True
        else:
            next_policies.append(current)
    if not replaced:
        next_policies.append(policy)
    return next_policies


def _sync_live_policy_enabled_from_state(value: JsonObject) -> None:
    active = value.get("active")
    policies = value.get("policies")
    if not isinstance(active, list) or not isinstance(policies, list):
        return
    active_ids = {str(item) for item in active if item}
    live_ids = {
        str(policy.get("id"))
        for policy in policies
        if isinstance(policy, dict) and policy.get("source") == "live" and policy.get("id")
    }
    if not live_ids:
        return
    live_policies = _read_live_policy_store()
    changed = False
    next_live_policies: list[JsonObject] = []
    for policy in live_policies:
        policy_id = str(policy.get("id", "") or "")
        if policy_id in live_ids:
            enabled = policy_id in active_ids
            if policy.get("enabled") != enabled:
                policy = {**policy, "enabled": enabled}
                changed = True
        next_live_policies.append(policy)
    if changed:
        _write_json_atomic(_live_policy_path(), {"policies": next_live_policies})


def _sync_policy_enabled_flags(value: JsonObject) -> None:
    """Keep the UI's full policy list aligned with the active-id list."""

    active = value.get("active")
    policies = value.get("policies")
    if not isinstance(active, list) or not isinstance(policies, list):
        return
    active_ids = {str(item) for item in active if item}
    seen: set[str] = set()
    synced: list[JsonObject] = []
    for policy in policies:
        if not isinstance(policy, dict):
            continue
        policy_id = str(policy.get("id", "") or "")
        if not policy_id:
            continue
        seen.add(policy_id)
        synced.append({**policy, "enabled": policy_id in active_ids})
    for policy_id in active_ids - seen:
        synced.append({"id": policy_id, "enabled": True})
    value["policies"] = synced


def _write_json_atomic(path: Path, value: JsonObject) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp_path.replace(path)


def _write_text_atomic(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(value, encoding="utf-8")
    tmp_path.replace(path)


def _apply_loaded_config(config: RuntimeConfig, loaded: LoadedConfig) -> RuntimeConfig:
    """Merge YAML over process env; YAML backend URLs intentionally win."""

    env = dict(config.enfguard_env)
    env.update(
        {
            "JUDGE_BACKEND": loaded.backend.judge_backend,
            "JUDGE_OPENAI_MODEL": loaded.backend.judge_openai_model,
            "JUDGE_OLLAMA_MODEL": loaded.backend.judge_ollama_model,
            "JUDGE_ANTHROPIC_MODEL": loaded.backend.judge_anthropic_model,
            "JUDGE_TIMEOUT_MS": str(loaded.backend.judge_timeout_ms),
            "JUDGE_FAIL_MODE": loaded.backend.judge_fail_mode,
            "OPENAI_BASE_URL": loaded.backend.openai_base_url or config.openai_base_url,
            "OLLAMA_BASE_URL": loaded.backend.ollama_base_url or config.ollama_base_url,
            # Anthropic env so the judge HTTP path can reach the API. The
            # proxy already forwards Anthropic chat requests; reuse the
            # same base URL/version for judge calls.
            "ANTHROPIC_BASE_URL": loaded.backend.anthropic_base_url or config.anthropic_base_url,
            "ANTHROPIC_API_KEY": config.anthropic_api_key,
        }
    )
    enfguard_bin = loaded.backend.enfguard_bin or config.enfguard_bin
    return replace(
        config,
        enfguard_bin=enfguard_bin,
        composite_signature_file=loaded.merged_sig_path,
        composite_policy_file=loaded.merged_mfotl_path,
        anthropic_base_url=loaded.backend.anthropic_base_url or config.anthropic_base_url,
        openai_base_url=loaded.backend.openai_base_url or config.openai_base_url,
        ollama_base_url=loaded.backend.ollama_base_url or config.ollama_base_url,
        enfguard_env=env,
    )


def _extract_rid(request: Request | None, tid: int, body: JsonObject | None = None) -> str:
    """Resolve the user-facing request id for this LLM call.

    Reads ``X-Request-Id`` from the headers, falls back to ``rid``/``request_id``
    on the body, and otherwise mints a deterministic ``req-<tid>`` so every
    Turn has a non-empty rid. The proxy is single-tenant for now; an agent
    framework should reuse one rid across the LLM calls of one user request.
    """

    if request is not None:
        header = request.headers.get("x-request-id") or request.headers.get("x-rid")
        if header:
            return str(header).strip()
    if isinstance(body, dict):
        for key in ("rid", "request_id"):
            value = body.get(key)
            if value:
                return str(value).strip()
    return f"req-{tid}"


def _adapt_v4_verdicts(cau: dict[str, list[tuple[Any, ...]]]) -> dict[str, list[tuple[Any, ...]]]:
    """Re-key v4 verdict events into v3-style phase-split keys.

    EnfGuard returns the causable v4 events ``Block(tid, phase, category,
    reason)``, ``Warn(tid, phase, category, reason)`` and
    ``Approve(tid, phase, label)``. Block and Warn still feed phase-specific
    downstream handlers, so this adapter splits those verdicts into
    ``BlockRequest`` / ``BlockResponse`` / ``BlockToolCall`` and matching Warn
    keys. Approve remains the canonical approval verdict.

    The phase is stripped from each tuple while preserving ``tid`` when
    EnfGuard includes it in the causable event arguments.
    """

    result: dict[str, list[tuple[Any, ...]]] = {
        key: list(value) for key, value in cau.items()
    }

    def _split(event: str, mapping: dict[str, str]) -> None:
        entries = result.pop(event, None)
        if not entries:
            return
        for args in entries:
            if not args:
                continue
            if len(args) >= 2 and str(args[1]) in mapping:
                phase = str(args[1])
                payload = (args[0], *args[2:])
            else:
                phase = str(args[0])
                payload = tuple(args[1:])
            legacy = mapping.get(phase)
            if legacy is None:
                continue
            result.setdefault(legacy, []).append(payload)

    _split(
        "Block",
        {"request": "BlockRequest", "response": "BlockResponse", "tool": "BlockToolCall"},
    )
    _split(
        "Warn",
        {"request": "WarnRequest", "response": "WarnResponse", "tool": "WarnToolCall"},
    )
    # The resolver already knows the current phase, so retain the canonical
    # Approve key while normalizing entries to (tid, label).
    approve_entries = result.pop("Approve", None)
    if approve_entries:
        normalized: list[tuple[Any, ...]] = []
        for args in approve_entries:
            if len(args) >= 3 and str(args[1]) in {"request", "response", "tool"}:
                normalized.append((args[0], args[2]))
            elif len(args) >= 2 and str(args[0]) in {"request", "response", "tool"}:
                normalized.append((args[1],))
            elif len(args) >= 2:
                normalized.append((args[0], args[1]))
            elif args:
                normalized.append(tuple(args))
        if normalized:
            result["Approve"] = normalized
    return result


def _clock_events(tid: int, phase: str) -> list[Event]:
    """Return one ``Clock(tid, phase, ms)`` event for this phase.

    Emitted alongside setting/policy events at the start of every phase so
    policies can express wall-clock intervals on top of the logical
    ``tid`` clock. ``phase`` is one of ``"request"`` or ``"response"``.
    Companion: the ``wall_ms_within`` builtin predicate.
    """

    return [Event("Clock", tid, phase, int(time.time() * 1000))]


# Back-compat alias retained for tests and older call paths.
def _clock_tick_events(tid: int, phase: str = "request") -> list[Event]:
    return _clock_events(tid, phase)


def _policy_active_events(tid: int, active_policies: list[str]) -> list[Event]:
    events: list[Event] = []
    seen: set[str] = set()
    for policy_id in active_policies:
        pid = str(policy_id or "").strip()
        if not pid or pid in seen:
            continue
        events.append(Event("PolicyActive", tid, pid))
        seen.add(pid)
    return events


def _tool_result_content_risk_events(
    tid: int,
    call_id: str,
    content: str,
    untrusted: bool,
) -> list[Event]:
    events: list[Event] = []
    secret_label, secret_judge_status = secret_material_label_with_status(content)
    if secret_label:
        events.append(Event("Classify", tid, call_id, "content_risk", "secret_material"))
    _emit_judge_telemetry(events, tid, call_id, "secret_material", secret_judge_status)
    if untrusted:
        events.append(Event("Untrusted", tid, "tool_result"))
        if is_instruction_like(content):
            events.append(Event("Classify", tid, call_id, "content_risk", "instruction_like"))
        persistence_label, persistence_judge_status = (
            persistence_instruction_label_with_status(content)
        )
        if persistence_label:
            events.append(Event("Classify", tid, call_id, "content_risk", "persistence_instruction"))
        _emit_judge_telemetry(
            events, tid, call_id, "persistence_instruction", persistence_judge_status
        )
        _already = bool(
            secret_label or is_instruction_like(content) or persistence_label
        )
        append_broad_content_events(
            events, tid, call_id, content, untrusted=True, already_flagged=_already
        )
    return events


def _body_tid(body: JsonObject) -> int:
    try:
        tid = int(body.get("tid", 0))
    except (TypeError, ValueError):
        return 0
    return tid if tid > 0 else 0


def _audit_events(name: str, tid: int, args_list: list[tuple[Any, ...]]) -> list[Event]:
    events: list[Event] = []
    for args in args_list:
        category = str(args[1]) if len(args) >= 2 else "general"
        reason = str(args[2]) if len(args) >= 3 else ""
        events.append(Event(name, tid, category, reason))
    return events


def _verdict_events(
    tid: int,
    cau_in: dict[str, list[tuple[Any, ...]]],
    cau_out: dict[str, list[tuple[Any, ...]]] | None = None,
) -> list[Event]:
    """Reconstruct the verdict events the proxy sent to EnfGuard for this turn.

    ``RequestAllowed/Blocked/Warned`` and ``ResponseAllowed/Blocked/Warned``
    are normally emitted via ``log_only`` deep inside the request lifecycle
    and we don't otherwise hold on to them. Mirroring the same conditional
    logic here gives us a stable list to surface to the trace UI without
    tracker plumbing through every code path.
    """

    events: list[Event] = []
    if cau_in.get("BlockRequest"):
        events.extend(_audit_events("RequestBlocked", tid, cau_in["BlockRequest"]))
        if cau_in.get("WarnRequest"):
            events.extend(_audit_events("RequestWarned", tid, cau_in["WarnRequest"]))
    elif cau_in.get("WarnRequest"):
        events.extend(_audit_events("RequestWarned", tid, cau_in["WarnRequest"]))
    else:
        events.append(Event("RequestAllowed", tid))

    if cau_out is None:
        return events

    if cau_out.get("BlockResponse"):
        events.extend(_audit_events("ResponseBlocked", tid, cau_out["BlockResponse"]))
        if cau_out.get("WarnResponse"):
            events.extend(_audit_events("ResponseWarned", tid, cau_out["WarnResponse"]))
    elif cau_out.get("WarnResponse"):
        events.extend(_audit_events("ResponseWarned", tid, cau_out["WarnResponse"]))
    else:
        events.append(Event("ResponseAllowed", tid))
    return events


def _verdict_entries(
    cau_enc: dict[str, list[tuple[Any, ...]]],
    names: tuple[str, ...],
) -> list[JsonObject]:
    entries: list[JsonObject] = []
    for name in names:
        for args in cau_enc.get(name, []):
            entries.append(
                {
                    "action": name,
                    "tid": int(args[0]) if args and _is_int_like(args[0]) else None,
                    "category": str(args[1]) if len(args) >= 2 else "general",
                    "reason": str(args[2]) if len(args) >= 3 else "",
                }
            )
    return entries


def _add_tool_suppression_blocks(
    cau_enc: dict[str, list[tuple[Any, ...]]],
    sup_enc: dict[str, list[tuple[Any, ...]]],
    tid: int,
    call_id: str,
    event_names: tuple[str, ...],
) -> None:
    """Convert suppressed tool-hook facts into a blocking tool verdict."""

    for event_name in event_names:
        for args in sup_enc.get(event_name, []):
            if call_id and len(args) >= 2 and str(args[1]) != call_id:
                continue
            cau_enc.setdefault("BlockToolCall", []).append(
                (tid, "suppression", f"{event_name} suppressed by policy")
            )
            return


def _add_response_suppression_blocks(
    cau_enc: dict[str, list[tuple[Any, ...]]],
    sup_enc: dict[str, list[tuple[Any, ...]]],
    tid: int,
    event_names: tuple[str, ...],
) -> None:
    """Convert suppressed response facts into a blocking response verdict."""

    for event_name in event_names:
        if sup_enc.get(event_name):
            cau_enc.setdefault("BlockResponse", []).append(
                (tid, "suppression", f"{event_name} suppressed by policy")
            )
            return


def _tool_verdict_events(tid: int, cau_enc: dict[str, list[tuple[Any, ...]]]) -> list[Event]:
    events: list[Event] = []
    for args in cau_enc.get("BlockToolCall", []):
        category = str(args[1]) if len(args) >= 2 else "tool"
        reason = str(args[2]) if len(args) >= 3 else ""
        events.append(Event("Block", tid, "tool", category, reason))
    for args in cau_enc.get("WarnToolCall", []):
        category = str(args[1]) if len(args) >= 2 else "tool"
        reason = str(args[2]) if len(args) >= 3 else ""
        events.append(Event("Warn", tid, "tool", category, reason))
    return events


def _tool_decision(cau_enc: dict[str, list[tuple[Any, ...]]]) -> tuple[str, str, str]:
    if cau_enc.get("BlockToolCall"):
        return "block", _tool_verdict_reason(cau_enc["BlockToolCall"]), ""
    if cau_enc.get("BlockRequest"):
        return "block", _tool_verdict_reason(cau_enc["BlockRequest"]), ""
    if cau_enc.get("WarnToolCall"):
        return "allow", "", _tool_verdict_reason(cau_enc["WarnToolCall"])
    if cau_enc.get("WarnRequest"):
        return "allow", "", _tool_verdict_reason(cau_enc["WarnRequest"])
    return "allow", "", ""


def _policy_tool_decision(cau_enc: dict[str, list[tuple[Any, ...]]]) -> JsonObject:
    """Snapshot the policy verdict before approval handling changes it."""

    verdicts = _verdict_entries(
        cau_enc,
        (
            "BlockToolCall",
            "BlockRequest",
            "Approve",
            "WarnToolCall",
            "WarnRequest",
        ),
    )
    if cau_enc.get("BlockToolCall"):
        decision, entries = "block", cau_enc["BlockToolCall"]
    elif cau_enc.get("BlockRequest"):
        decision, entries = "block", cau_enc["BlockRequest"]
    elif cau_enc.get("Approve"):
        decision, entries = "approve", cau_enc["Approve"]
    elif cau_enc.get("WarnToolCall"):
        decision, entries = "warn", cau_enc["WarnToolCall"]
    elif cau_enc.get("WarnRequest"):
        decision, entries = "warn", cau_enc["WarnRequest"]
    else:
        decision, entries = "allow", []
    return {
        "decision": decision,
        "reason": _tool_verdict_reason(entries),
        "verdicts": verdicts,
    }


def _tool_decision_trace(
    policy: JsonObject,
    final_decision: str,
    reason: str,
    warning: str,
) -> JsonObject:
    """Describe both the policy verdict and its concrete runtime handling."""

    policy_name = str(policy.get("decision", "allow"))
    final_reason = reason or warning
    if final_decision == "block":
        if policy_name == "approve" and reason.startswith("approval timeout:"):
            runtime_decision = "blocked_on_approval_timeout"
        elif policy_name == "approve" and reason.startswith("user denied:"):
            runtime_decision = "blocked_on_approval_denial"
        elif policy_name == "approve":
            runtime_decision = "blocked_by_approval_policy"
        else:
            runtime_decision = "blocked_by_policy"
        effect_executed: bool | None = False
    elif policy_name == "approve":
        runtime_decision = "proceed_after_approval"
        effect_executed = None
    elif policy_name == "warn":
        runtime_decision = "proceed_with_warning"
        effect_executed = None
    else:
        runtime_decision = "proceed"
        effect_executed = None
    return {
        "schema_version": 1,
        "policy_decision": policy_name,
        "policy_reason": str(policy.get("reason", "")),
        "policy_verdicts": policy.get("verdicts", []),
        "runtime_decision": runtime_decision,
        "runtime_reason": final_reason,
        "effect_executed": effect_executed,
    }


def _tool_verdict_reason(entries: list[tuple[Any, ...]]) -> str:
    if not entries:
        return ""
    first = entries[0]
    if len(first) >= 3:
        return str(first[2])
    if len(first) >= 2:
        return str(first[1])
    return ""


def _demote_warn_failures(
    cau_enc: dict[str, list[tuple[Any, ...]]],
    tid: int,
    sid: str,
    phase: str,
) -> dict[str, list[tuple[Any, ...]]]:
    """Turn judge fail-mode blocks into warnings while preserving all verdicts."""

    fail_warn_predicates = _warn_fail_predicates(tid, sid, phase)
    if not fail_warn_predicates:
        return cau_enc

    demoted: dict[str, list[tuple[Any, ...]]] = {
        name: list(args_list) for name, args_list in cau_enc.items()
    }
    _demote_block_entries(
        demoted,
        block_name="BlockRequest",
        warn_name="WarnRequest",
        category_predicates=_INBOUND_DEMOTE_PREDICATES,
        fail_warn_predicates=fail_warn_predicates,
    )
    _demote_block_entries(
        demoted,
        block_name="BlockResponse",
        warn_name="WarnResponse",
        category_predicates=_OUTBOUND_DEMOTE_PREDICATES,
        fail_warn_predicates=fail_warn_predicates,
    )
    return {name: args_list for name, args_list in demoted.items() if args_list}


def _demote_block_entries(
    cau_enc: dict[str, list[tuple[Any, ...]]],
    block_name: str,
    warn_name: str,
    category_predicates: dict[str, tuple[str, ...]],
    fail_warn_predicates: set[str],
) -> None:
    kept: list[tuple[Any, ...]] = []
    moved: list[tuple[Any, ...]] = []
    for args in cau_enc.get(block_name, []):
        category = str(args[1]) if len(args) >= 2 else "general"
        predicates = category_predicates.get(category, ())
        if predicates and fail_warn_predicates.intersection(predicates):
            moved.append(args)
        else:
            kept.append(args)

    if moved:
        cau_enc[block_name] = kept
        cau_enc.setdefault(warn_name, []).extend(moved)


async def _resolve_approvals(
    tid: int,
    sid: str,
    cau_enc: dict[str, list[tuple[Any, ...]]],
    phase: str,
) -> dict[str, list[tuple[Any, ...]]]:
    """Pause on ``Approve`` and convert the verdict per the user's reply.

    Works for both Phase 1 (``phase="inbound"``) and Phase 2
    (``phase="outbound"``). The deny / timeout fallback maps to
    ``Block{Request,Response}`` / ``Warn{Request,Response}`` based on which
    phase produced the approval verdict, so a Phase-2 policy can also gate
    the response release behind a UI prompt.

    If ``human_approval`` is disabled in YAML, every ``Approve`` is
    treated as a hard block (Block{Request,Response}) so the proxy stays
    safe when the UI is not wired. In non-enforcing modes (audit/warn), the
    proxy auto-approves and logs a synthetic ``UserFeedback`` event without
    suspending the request.
    """

    approvals = cau_enc.get("Approve", [])
    if not approvals:
        return cau_enc
    cau_enc = {name: list(args_list) for name, args_list in cau_enc.items()}
    cau_enc.pop("Approve", None)

    block_key, warn_key = _approval_verdict_targets(phase)

    # Block dominates Approve. If a hard block for this gate already exists in the
    # SAME EnfGuard response (e.g. a shell credential sweep that matched both
    # credential_sweep -> Block and credential_access_command -> Approve), the
    # approval cannot change the outcome — so drop it WITHOUT prompting: no pending
    # approval, no UI button, no wait. The phase decision (_tool_decision /
    # phase-1/2) then returns block. Approve only matters when there is no Block.
    dominating_blocks = {block_key}
    if phase == "tool":
        dominating_blocks.add("BlockRequest")  # _tool_decision also blocks on this
    if any(cau_enc.get(key) for key in dominating_blocks):
        return cau_enc

    if not state.human_approval.enabled:
        cau_enc.setdefault(block_key, []).extend(
            (tid, "approval", _approval_label(args) or "approval gate disabled")
            for args in approvals
        )
        return cau_enc

    if _dry_run_enabled():
        for args in approvals:
            label = _approval_label(args) or "approval"
            _logger().log_only(
                [make_feedback_event(tid, "approve", f"{_enforcement_mode()} mode auto-approval: {label}")],
                tid,
            )
        return cau_enc

    # Real human-in-the-loop pause. Only the first label is shown to the
    # user, but every approval entry contributes to the eventual verdict.
    label = _approval_label(approvals[0]) or "Sensitive action — proceed?"
    pending = PendingApproval(
        tid=tid,
        sid=sid,
        label=label,
        created_ts=time.time(),
        timeout_seconds=state.human_approval.timeout_seconds,
        on_timeout=state.human_approval.on_timeout,
        phase=phase,
    )
    with state.pending_approvals_lock:
        state.pending_approvals[tid] = pending

    try:
        try:
            await asyncio.wait_for(pending.event.wait(), timeout=state.human_approval.timeout_seconds)
            decision = pending.decision or "deny"
        except asyncio.TimeoutError:
            decision = "timeout"
            pending.decision = "timeout"
    finally:
        with state.pending_approvals_lock:
            state.pending_approvals.pop(tid, None)

    if decision == "approve":
        # User opted in. Drop the approval requirement entirely.
        return cau_enc
    if decision == "deny":
        cau_enc.setdefault(block_key, []).extend(
            (tid, "approval", f"user denied: {label}") for _ in approvals
        )
        return cau_enc
    # timeout, apply the YAML-configured fallback policy.
    on_timeout = state.human_approval.on_timeout
    if on_timeout == "allow":
        return cau_enc
    target_key = block_key if on_timeout == "block" else warn_key
    cau_enc.setdefault(target_key, []).extend(
        (tid, "approval", f"approval timeout: {label}") for _ in approvals
    )
    return cau_enc


def _approval_verdict_targets(phase: str) -> tuple[str, str]:
    """Return (block_verdict_name, warn_verdict_name) for the given phase."""

    if phase == "outbound":
        return "BlockResponse", "WarnResponse"
    if phase == "tool":
        return "BlockToolCall", "WarnToolCall"
    return "BlockRequest", "WarnRequest"


def _approval_label(args: tuple[Any, ...] | list[Any]) -> str:
    if len(args) >= 2:
        return str(args[1])
    return ""


def _resolve_pending_approval(tid: int, decision: str, payload: str) -> None:
    """Wake the coroutine waiting on the pending approval for ``tid``."""

    with state.pending_approvals_lock:
        pending = state.pending_approvals.get(tid)
    if pending is None:
        return
    pending.decision = decision
    pending.payload = payload or ""
    pending.event.set()


def _has_pending_approval(tid: int) -> bool:
    with state.pending_approvals_lock:
        return tid in state.pending_approvals


def _normalize_approval_decision(kind: str) -> str:
    """Map a feedback ``kind`` value to ``approve`` / ``deny`` / ``""``.

    Existing UI values such as ``approve_block`` / ``deny_allow`` reflect the
    feedback tab's verdict labels, not approval semantics, so we reject them
    here. Only an explicit ``approve`` / ``deny`` resolves an approval gate.
    """

    text = (kind or "").strip().lower()
    if text == "approve":
        return "approve"
    if text == "deny":
        return "deny"
    return ""


def _pending_approvals_payload() -> list[JsonObject]:
    with state.pending_approvals_lock:
        snapshots = list(state.pending_approvals.values())
    payload: list[JsonObject] = []
    now = time.time()
    for pending in snapshots:
        elapsed = max(0, now - pending.created_ts)
        remaining = max(0, int(pending.timeout_seconds - elapsed))
        payload.append(
            {
                "tid": pending.tid,
                "sid": pending.sid,
                "label": pending.label,
                "created_ts": pending.created_ts,
                "timeout_seconds": pending.timeout_seconds,
                "remaining_seconds": remaining,
                "on_timeout": pending.on_timeout,
                "phase": pending.phase,
            }
        )
    return payload


def _demote_all_blocks_for_dry_run(
    cau_enc: dict[str, list[tuple[Any, ...]]],
) -> dict[str, list[tuple[Any, ...]]]:
    """In warn mode preserve verdict visibility without suppressing traffic."""

    demoted: dict[str, list[tuple[Any, ...]]] = {
        name: list(args_list) for name, args_list in cau_enc.items()
    }
    if demoted.get("BlockRequest"):
        demoted.setdefault("WarnRequest", []).extend(demoted.pop("BlockRequest"))
    if demoted.get("BlockResponse"):
        demoted.setdefault("WarnResponse", []).extend(demoted.pop("BlockResponse"))
    if demoted.get("BlockToolCall"):
        demoted.setdefault("WarnToolCall", []).extend(demoted.pop("BlockToolCall"))
    return {name: args_list for name, args_list in demoted.items() if args_list}


def _apply_enforcement_mode(
    cau_enc: dict[str, list[tuple[Any, ...]]],
) -> dict[str, list[tuple[Any, ...]]]:
    mode = _enforcement_mode()
    if mode == "enforce":
        return cau_enc
    if mode == "warn":
        return _demote_all_blocks_for_dry_run(cau_enc)
    if mode == "audit":
        return {
            name: list(args_list)
            for name, args_list in cau_enc.items()
            if name
            not in {
                "BlockRequest",
                "BlockResponse",
                "BlockToolCall",
                "WarnRequest",
                "WarnResponse",
                "WarnToolCall",
                "Approve",
            }
        }
    return cau_enc


def _warn_fail_predicates(tid: int, sid: str, phase: str) -> set[str]:
    return {
        str(row.get("predicate"))
        for row in _read_trace_rows(tid, sid, phase)
        if _trace_row_fired(row) and str(row.get("fail_mode", "")).lower() == "warn"
    }


def _read_trace_reasons(tid: int, sid: str, phase: str = "") -> dict[str, str]:
    """Return fired predicate reasons for one turn, preserving multi-reasons."""

    reasons_by_predicate: dict[str, list[str]] = {}
    for row in _read_trace_rows(tid, sid, phase):
        if not _trace_row_fired(row):
            continue
        predicate = str(row.get("predicate") or "")
        if not predicate:
            continue
        reasons = _trace_reasons(row)
        if not reasons:
            continue
        bucket = reasons_by_predicate.setdefault(predicate, [])
        for reason in reasons:
            if reason not in bucket:
                bucket.append(reason)
    return {predicate: "; ".join(reasons) for predicate, reasons in reasons_by_predicate.items()}


def _read_trace_rows(tid: int, sid: str, phase: str = "") -> list[JsonObject]:
    rows = _read_trace_index_rows(tid)
    if not rows:
        rows = _read_legacy_trace_rows(tid)
    if not sid:
        return _prefer_phase_rows(rows, phase)
    sid_rows = [row for row in rows if str(row.get("sid", "") or "") == sid]
    return _prefer_phase_rows(sid_rows or rows, phase)


def _read_trace_rows_any_phase(tid: int) -> list[JsonObject]:
    return _read_trace_index_rows(tid) or _read_legacy_trace_rows(tid)


# Phases of one turn (chat request/response and, for a tool turn, a tool-gate
# record plus a slightly-later tool-result record) are written within the same
# HTTP round-trip — sub-second apart. A ``tid`` reused by a later turn (e.g. a
# reused browser session, or a restart that kept the same session file) is
# separated by a far larger gap. This threshold groups the former while keeping
# the latter apart.
_TRACE_TURN_GAP_SECONDS = 30.0


def _records_for_latest_turn(records: list[JsonObject]) -> list[JsonObject]:
    """All phase records of the most recent turn, in ascending time order.

    Walk back from the newest record, keeping records while consecutive gaps stay
    within ``_TRACE_TURN_GAP_SECONDS`` so a tool turn's gate record (which carries
    the verdict) stays grouped with its later result record, but a much earlier
    reused-``tid`` turn is excluded.
    """

    if not records:
        return []
    ordered = sorted(records, key=lambda record: float(record.get("ts", 0.0) or 0.0))
    cluster = [ordered[-1]]
    for record in reversed(ordered[:-1]):
        gap = float(cluster[-1].get("ts", 0.0) or 0.0) - float(record.get("ts", 0.0) or 0.0)
        if gap > _TRACE_TURN_GAP_SECONDS:
            break
        cluster.append(record)
    cluster.reverse()
    return cluster


def _trace_bundle_for_tid(tid: int) -> tuple[list[JsonObject], list[JsonObject]]:
    """Return trace rows and session records scoped to one logical turn.

    Returns EVERY phase record of the most recent turn, not just the newest one.
    A tool turn writes a tool-gate record (which carries the Warn/Block/Approve
    verdict) followed by a slightly-later tool-result record with no verdict;
    returning only the newest record rendered the result phase and hid the gate
    verdict in the UI. ``_summarise_phases`` accumulates the tool verdicts across
    these records, so passing them all surfaces the tool-phase Warn/Block.

    Older local runs reused ``tid`` values after proxy restarts, so predicate
    rows and session records are scoped to the same ``sid`` and to the trailing
    turn cluster to avoid mixing a much-later reused-``tid`` turn into the bundle.
    """

    records = _session_records_for_tid(tid)
    if not records:
        return _read_trace_rows_any_phase(tid), []

    latest = _latest_session_record(records)
    sid = _record_sid(latest) if latest is not None else ""
    if not sid:
        return _read_trace_rows_any_phase(tid), _records_for_latest_turn(records)

    same_sid_records = [record for record in records if _record_sid(record) == sid]
    turn_records = _records_for_latest_turn(same_sid_records)
    turn_ids = {id(record) for record in turn_records}
    previous_ts = max(
        (
            float(record.get("ts", 0.0) or 0.0)
            for record in same_sid_records
            if id(record) not in turn_ids
        ),
        default=0.0,
    )
    rows = [
        row
        for row in _read_trace_rows(tid, sid)
        if previous_ts <= 0.0 or float(row.get("ts_wall", 0.0) or 0.0) > previous_ts
    ]
    return rows, turn_records


def _resolve_judge_override_content(
    tid: int,
    predicate: str,
    phase: str,
    content_preview: str,
) -> str | None:
    rows, session_records = _trace_bundle_for_tid(tid)
    matching_rows = [
        row
        for row in rows
        if str(row.get("predicate", "") or "") == predicate
        and str(row.get("phase", "") or "") == phase
        and (
            not content_preview
            or str(row.get("content_preview", "") or "") == content_preview
        )
    ]
    if not matching_rows:
        return None
    row = matching_rows[-1]
    preview = str(row.get("content_preview", "") or content_preview or "")
    if not preview or preview.startswith("[assistant content omitted"):
        return None

    source_names = _trace_row_source_event_names(row)
    if not source_names:
        source_names = (
            {"Message"}
            if phase == "inbound"
            else {"Completion"}
        )
    candidates: list[str] = []
    for record in session_records:
        events = record.get(phase)
        if not isinstance(events, list):
            continue
        for event in events:
            if not isinstance(event, dict):
                continue
            if str(event.get("name", "") or "") not in source_names:
                continue
            args = event.get("args")
            if not isinstance(args, list) or len(args) < 2:
                continue
            content = str(args[1] or "")
            if content == preview:
                return content
            if content.startswith(preview):
                candidates.append(content)
    if len(candidates) == 1:
        return candidates[0]
    return None


def _trace_row_source_event_names(row: JsonObject) -> set[str]:
    names: set[str] = set()
    arg_sources = row.get("arg_sources")
    if isinstance(arg_sources, list):
        for source in arg_sources:
            name = str(source or "").split(".", 1)[0]
            if name:
                names.add(name)
    return names


def _read_trace_index_rows(tid: int) -> list[JsonObject]:
    return _read_jsonl_rows(state.config.logs_dir / "traces" / f"tid_{tid}.jsonl")


def _read_legacy_trace_rows(tid: int) -> list[JsonObject]:
    rows: list[JsonObject] = []
    try:
        with state.config.trace_store_file.open(encoding="utf-8") as handle:
            for line in handle:
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(row, dict):
                    continue
                if not _same_trace_tid(row, tid):
                    continue
                rows.append(row)
    except FileNotFoundError:
        return []
    except OSError:
        return []
    return rows


def _read_jsonl_rows(path: Path) -> list[JsonObject]:
    rows: list[JsonObject] = []
    try:
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(row, dict):
                    rows.append(row)
    except (FileNotFoundError, OSError):
        return []
    return rows


def _same_trace_tid(row: JsonObject, tid: int) -> bool:
    try:
        return int(row.get("tid_hint", -1)) == int(tid)
    except (TypeError, ValueError):
        return False


def _prefer_phase_rows(rows: list[JsonObject], phase: str) -> list[JsonObject]:
    if not phase:
        return rows
    phase_rows = [row for row in rows if str(row.get("phase", "") or "") == phase]
    return phase_rows or rows


def _trace_row_fired(row: JsonObject) -> bool:
    try:
        return float(row.get("score", 0.0)) >= 0.5
    except (TypeError, ValueError):
        return False


def _trace_reasons(row: JsonObject) -> list[str]:
    raw_reasons = row.get("reasons")
    reasons: list[str] = []
    if isinstance(raw_reasons, list):
        reasons.extend(str(reason).strip() for reason in raw_reasons if str(reason).strip())
    reason = str(row.get("reason", "") or "").strip()
    if reason and reason not in reasons:
        reasons.insert(0, reason)
    return reasons


def _log_released(tid: int, response: NormalizedResponse) -> None:
    text = response.content
    if response.warned and response.warn_message:
        text = f"{response.warn_message}\n\n{text}" if text else response.warn_message
    _logger().log_only([Event("CompletionReleased", tid, text, _estimate_tokens(text))], tid)


def _session_record(
    tid: int,
    provider: str,
    action: str,
    inbound_events: list[Event],
    outbound_events: list[Event] | None = None,
    verdicts: list[JsonObject] | None = None,
    verdict_events: list[Event] | None = None,
    enfguard_ms_in: int = 0,
    enfguard_ms_out: int = 0,
    upstream_ms: int = 0,
    decision_trace: JsonObject | None = None,
) -> JsonObject:
    include_assistant_content = _trace_assistant_content_enabled()
    record: JsonObject = {
        "tid": tid,
        "ts": time.time(),
        "provider": provider,
        "action": action,
        "verdicts": verdicts or [],
        # EnfGuard runtime evaluation cost per phase, in milliseconds.
        # Pre-evaluation (judge HTTP) is excluded, that lives on the
        # individual predicate trace rows. Allows the trace UI to split
        # "engine time" from "judge time" cleanly.
        "enfguard_ms": {
            "inbound": int(enfguard_ms_in or 0),
            "outbound": int(enfguard_ms_out or 0),
        },
        # Deterministic classifier (map_tool_call) wall time for this turn, in ms.
        # Runs during event extraction, before the enfguard_ms monitor query, so it
        # is reported separately here rather than folded into enfguard_ms. Popped
        # per tid (cleared on read) so summing across a case's turns is exact.
        "classifier_ms": round(pop_classifier_ms(tid), 4),
        # Per-turn capture of every gated ingest-judge model call (system-prompt
        # sha, input, raw reply, cache_hit, ms). Empty unless judges are on and a
        # judge actually ran. Popped per tid (cleared on read) like classifier_ms.
        # Lets a judges-on run show what each judge was asked and answered, so a
        # no_match is attributable to prompt vs cache vs model limitation.
        "judge_calls": pop_judge_calls(tid),
        "upstream_ms": int(upstream_ms or 0),
        # Events that went into EnfGuard for this turn, chat content,
        # switches, model selection, policy gates, etc.
        "inbound": [
            _event_to_dict(event, include_assistant_content=include_assistant_content)
            for event in inbound_events
            if _keep_trace_event(event, include_assistant_content=include_assistant_content)
        ],
        "outbound": [
            _event_to_dict(event, include_assistant_content=include_assistant_content)
            for event in outbound_events or []
            if _keep_trace_event(event, include_assistant_content=include_assistant_content)
        ],
        # Events that came outt of the proxy's verdict resolution and were
        # logged back to EnfGuard. Includes Request/Response Allowed/Blocked/
        # Warned and CompletionReleased. Surfaced in the trace UI under "Events".
        "verdict_events": [
            _event_to_dict(event, include_assistant_content=include_assistant_content)
            for event in verdict_events or []
            if _keep_trace_event(event, include_assistant_content=include_assistant_content)
        ],
    }
    if decision_trace is not None:
        record["decision_trace"] = decision_trace
    return record


def _append_session_log(sid: str, record: JsonObject) -> None:
    log_sid = sid or "_no_session"
    try:
        path = state.config.logs_dir / f"session_{_safe_file_part(log_sid)}.jsonl"
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        _update_session_token_index(log_sid, record)
    except OSError:
        return


def _update_session_token_index(sid: str, record: JsonObject) -> None:
    total_delta = 0
    for event in record.get("outbound", []):
        if not isinstance(event, dict) or event.get("name") != "TokenUsage":
            continue
        args = event.get("args")
        if isinstance(args, list) and len(args) >= 4:
            total_delta += _int_value(args[3])
    if total_delta <= 0:
        return
    path = state.config.logs_dir / f"session_{_safe_file_part(sid)}.tokens"
    try:
        current = int(path.read_text(encoding="utf-8").strip() or "0") if path.exists() else 0
    except (OSError, ValueError):
        current = 0
    _write_text_atomic(path, str(current + total_delta))


def _summarise_phases(
    predicate_rows: list[JsonObject],
    session_records: list[JsonObject],
) -> list[JsonObject]:
    """Group predicate rows by phase and pair each phase with its verdict."""

    by_phase: dict[str, list[JsonObject]] = {"inbound": [], "outbound": []}
    for row in predicate_rows:
        phase = str(row.get("phase", "") or "")
        if phase not in by_phase:
            by_phase.setdefault(phase, [])
        by_phase[phase].append(row)

    verdict_by_phase: dict[str, dict[str, Any]] = {}
    enfguard_ms_by_phase: dict[str, int] = {"inbound": 0, "outbound": 0}
    upstream_ms = 0
    for record in session_records:
        action = str(record.get("action", "") or "")
        upstream_ms = max(upstream_ms, int(record.get("upstream_ms", 0) or 0))
        engine_ms = record.get("enfguard_ms")
        if isinstance(engine_ms, dict):
            enfguard_ms_by_phase["inbound"] = max(
                enfguard_ms_by_phase["inbound"], int(engine_ms.get("inbound", 0) or 0)
            )
            enfguard_ms_by_phase["outbound"] = max(
                enfguard_ms_by_phase["outbound"], int(engine_ms.get("outbound", 0) or 0)
            )
        if not action:
            continue
        # Map session-record actions to the phase the verdict belongs to.
        if action.startswith("request_"):
            verdict_by_phase["inbound"] = {"action": action, "verdicts": record.get("verdicts", [])}
        elif action.startswith("tool"):
            # tool_execute / tool_result gate. A WarnToolCall returns decision
            # "allow" (action "tool_allow"), so the per-record action alone would
            # render an ALLOW pill and hide the warn. Accumulate the verdicts
            # across this turn's tool records; the phase action is derived from
            # them below so Warn (and Block/Approve) surface in the dashboard.
            bucket = verdict_by_phase.setdefault("tool", {"action": "tool_allow", "verdicts": []})
            bucket["verdicts"].extend(record.get("verdicts", []) or [])
        elif action.startswith("response_") or action == "allowed":
            verdict_by_phase.setdefault("outbound", {"action": action, "verdicts": record.get("verdicts", [])})

    # Derive the tool-phase action from its verdicts so a WarnToolCall shows a
    # WARN pill (verdictKind matches the "warn"/"block"/"approval" substring).
    tool_bucket = verdict_by_phase.get("tool")
    if tool_bucket is not None:
        verdict_actions = " ".join(
            str(v.get("action", "") or "") for v in tool_bucket["verdicts"]
        ).lower()
        if "block" in verdict_actions:
            tool_bucket["action"] = "tool_block"
        elif "warn" in verdict_actions:
            tool_bucket["action"] = "tool_warn"
        elif "approval" in verdict_actions or "approve" in verdict_actions:
            tool_bucket["action"] = "tool_approval"
        else:
            tool_bucket["action"] = "tool_allow"

    phases: list[JsonObject] = []
    for phase_name in ("inbound", "tool", "outbound"):
        rows = by_phase.get(phase_name, [])
        if not rows and phase_name not in verdict_by_phase:
            continue
        verdict = verdict_by_phase.get(phase_name, {"action": "allowed", "verdicts": []})
        fired = [
            {
                "predicate": str(row.get("predicate", "") or ""),
                "score": float(row.get("score", 0.0) or 0.0),
                "raw_score": float(row.get("raw_score", 0.0) or 0.0),
                "reason": str(row.get("reason", "") or ""),
            }
            for row in rows
            if float(row.get("score", 0.0) or 0.0) >= 0.5
        ]
        judge_row_ms = _sum_judge_row_ms(rows)
        judge_ms = _unique_judge_wall_ms(rows)
        engine_ms = enfguard_ms_by_phase.get(phase_name, 0)
        model_ms = upstream_ms if phase_name == "outbound" else 0
        phases.append(
            {
                "phase": phase_name,
                "action": verdict.get("action", "allowed"),
                "verdicts": verdict.get("verdicts", []),
                "fired_predicates": fired,
                "predicate_count": len(rows),
                # `judge_ms` is the wall-clock cost of upstream judge HTTP
                # calls; `enfguard_ms` is the OCaml engine cost; `wall_ms`
                # is the sum, kept for back-compat with older UI code.
                "judge_ms": judge_ms,
                "judge_row_ms": judge_row_ms,
                "enfguard_ms": engine_ms,
                "upstream_ms": model_ms,
                "wall_ms": judge_ms + engine_ms + model_ms,
            }
        )
    return phases


def _sum_judge_row_ms(rows: list[JsonObject]) -> int:
    return sum(int(row.get("latency_ms", 0) or 0) for row in rows)


def _unique_judge_wall_ms(rows: list[JsonObject]) -> int:
    """Return judge wall time without multiplying shared batch latency.

    Batched and parallel pre-evaluation can produce several predicate rows
    from one upstream dispatch. Those rows share a ``batch_id`` and each
    carries the dispatch latency for trace readability. For phase timing,
    count the maximum latency per batch once, plus ordinary non-batched rows.
    """

    total = 0
    batch_max: dict[str, int] = {}
    for row in rows:
        latency = int(row.get("latency_ms", 0) or 0)
        batch_id = str(row.get("batch_id", "") or "")
        if not batch_id:
            total += latency
            continue
        batch_max[batch_id] = max(batch_max.get(batch_id, 0), latency)
    return total + sum(batch_max.values())


def _summarise_batches(predicate_rows: list[JsonObject]) -> dict[str, JsonObject]:
    """Aggregate per-``batch_id`` totals so the drill-down can collapse rows."""

    summary: dict[str, JsonObject] = {}
    for row in predicate_rows:
        batch_id = str(row.get("batch_id", "") or "")
        if not batch_id:
            continue
        bucket = summary.setdefault(
            batch_id,
            {"batch_id": batch_id, "latency_ms": 0, "predicates": []},
        )
        # The batch latency is identical across rows that share a batch_id;
        # take the max so we are robust if an older entry is missing the
        # field altogether.
        bucket["latency_ms"] = max(int(bucket["latency_ms"]), int(row.get("latency_ms", 0) or 0))
        bucket["predicates"].append(str(row.get("predicate", "") or ""))
    return summary


def _list_recent_traces(limit: int) -> list[JsonObject]:
    """Return recent current-run tids from predicate indexes or session logs."""

    traces_dir = state.config.logs_dir / "traces"
    # Only list turns from the CURRENT proxy run. tid restarts at 1 every run
    # (_reset_run_scoped_state) and the per-tid trace files are reused/appended
    # across runs, so without this guard the list surfaces stale turns from
    # previous runs. A file written this run has mtime >= run_started_at; the 2s
    # slack absorbs coarse (1s) filesystem mtime granularity. run_started_at == 0
    # (no lifespan, e.g. unit tests) disables the guard, preserving old behaviour.
    cutoff = (getattr(state, "run_started_at", 0.0) or 0.0)
    cutoff = (cutoff - 2.0) if cutoff > 0.0 else 0.0
    entries_by_tid: dict[int, float] = {}
    try:
        for path in traces_dir.glob("tid_*.jsonl"):
            try:
                tid_part = path.stem.removeprefix("tid_")
                tid = int(tid_part)
            except ValueError:
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            if cutoff and stat.st_mtime < cutoff:
                continue
            entries_by_tid[tid] = max(entries_by_tid.get(tid, 0.0), stat.st_mtime)
    except OSError:
        pass

    # Deterministic tool calls may never invoke an LLM predicate, so they have
    # session records but no logs/traces/tid_*.jsonl file. Include those tids or
    # the live evaluation runner would silently miss ordinary mapper verdicts.
    try:
        session_paths = state.config.logs_dir.glob("session_*.jsonl")
    except OSError:
        session_paths = []
    for path in session_paths:
        for row in _read_jsonl_rows(path):
            try:
                tid = int(row.get("tid"))
                ts = float(row.get("ts", 0.0) or 0.0)
            except (TypeError, ValueError):
                continue
            if cutoff and ts < cutoff:
                continue
            entries_by_tid[tid] = max(entries_by_tid.get(tid, 0.0), ts)

    entries = sorted(entries_by_tid.items(), key=lambda item: item[1], reverse=True)
    summary: list[JsonObject] = []
    for tid, mtime in entries[:limit]:
        rows, records = _trace_bundle_for_tid(tid)
        phases = _summarise_phases(rows, records)
        verdict = _verdict_for_summary(tid)
        fired = sorted(
            {
                str(row.get("predicate", "") or "")
                for row in rows
                if float(row.get("score", 0.0) or 0.0) >= 0.5
            }
        )
        summary.append(
            {
                "tid": tid,
                "ts": mtime,
                "action": verdict.get("action", ""),
                "phase": verdict.get("phase", ""),
                "predicate_count": len(rows),
                "fired_predicates": fired,
                "wall_ms": sum(int(phase.get("wall_ms", 0) or 0) for phase in phases)
                if phases
                else _unique_judge_wall_ms(rows),
            }
        )
    return summary


def _verdict_for_summary(tid: int) -> dict[str, str]:
    """Return the newest session verdict for ``tid``.

    ``tid`` used to reset on every proxy restart. Choosing the newest record
    prevents an old blocked ``T1`` from shadowing a new allowed ``T1`` in the
    trace list.
    """

    record = _latest_session_record(_session_records_for_tid(tid))
    if record is None:
        return {"action": "", "phase": ""}
    action = str(record.get("action", "") or "")
    phase = "inbound" if action.startswith("request_") else "outbound" if action else ""
    return {"action": action, "phase": phase}


def _session_records_for_tid(tid: int) -> list[JsonObject]:
    records: list[JsonObject] = []
    try:
        paths = list(state.config.logs_dir.glob("session_*.jsonl"))
    except OSError:
        return records
    for path in paths:
        for row in _read_jsonl_rows(path):
            try:
                if int(row.get("tid", -1)) == tid:
                    records.append(row)
            except (TypeError, ValueError):
                continue
    return records


def _latest_session_record(records: list[JsonObject]) -> JsonObject | None:
    if not records:
        return None
    return max(records, key=lambda record: float(record.get("ts", 0.0) or 0.0))


def _record_sid(record: JsonObject) -> str:
    for group_name in ("inbound", "outbound"):
        events = record.get(group_name)
        if not isinstance(events, list):
            continue
        for event in events:
            if not isinstance(event, dict):
                continue
            name = event.get("name")
            args = event.get("args")
            if not isinstance(args, list):
                continue
        
            if name == "Turn" and len(args) >= 3:
                return str(args[2] or "")
            if name == "Turn" and len(args) >= 2:
                return str(args[1] or "")
            if name in {"Session", "SessionStart"} and args:
                return str(args[0] or "")
    return ""


def _max_logged_tid() -> int:
    """Return the highest turn id already present in local logs."""

    max_tid = 0
    try:
        for path in (state.config.logs_dir / "traces").glob("tid_*.jsonl"):
            try:
                max_tid = max(max_tid, int(path.stem.removeprefix("tid_")))
            except ValueError:
                continue
    except OSError:
        pass

    try:
        session_paths = list(state.config.logs_dir.glob("session_*.jsonl"))
    except OSError:
        session_paths = []
    for path in session_paths:
        for row in _read_jsonl_rows(path):
            try:
                max_tid = max(max_tid, int(row.get("tid", 0) or 0))
            except (TypeError, ValueError):
                continue
    return max_tid


def _session_token_total(sid: str) -> int:
    token_path = state.config.logs_dir / f"session_{_safe_file_part(sid)}.tokens"
    try:
        return int(token_path.read_text(encoding="utf-8").strip() or "0")
    except (FileNotFoundError, OSError, ValueError):
        pass
    total = 0
    path = state.config.logs_dir / f"session_{_safe_file_part(sid)}.jsonl"
    for record in _read_jsonl_rows(path):
        for event in record.get("outbound", []):
            if not isinstance(event, dict) or event.get("name") != "TokenUsage":
                continue
            args = event.get("args")
            if isinstance(args, list) and len(args) >= 4:
                total += _int_value(args[3])
    return total


def _limit_text(value: Any, limit: int) -> str:
    return str(value or "").replace("\r", " ").replace("\n", " ")[:limit]


def _keep_trace_event(event: Event, *, include_assistant_content: bool = True) -> bool:
    if include_assistant_content:
        return True
    if event.name == "Message" and len(event.args) >= 2 and event.args[1] == "assistant":
        return False
    return event.name not in {
        "AssistantHistory",  # legacy v3, kept for old trace records
        "CompletionObserved",  # legacy v3, kept for old trace records, maybe i'll clean up later 
        "Completion",
        "CompletionRedacted",
        "CompletionReleased",
    }


def _event_to_dict(event: Event, *, include_assistant_content: bool = True) -> JsonObject:
    args = list(event.args)
    return {"name": event.name, "args": args}


def _response_json_or_text(response: httpx.Response) -> JsonObject:
    try:
        value = response.json()
    except ValueError:
        return {"error": response.text}
    return value if isinstance(value, dict) else {"error": value}


def _extract_synthetic_completion(request: Request, body: JsonObject) -> str | None:
    """Pull the synthetic-completion override out of a chat request, if any.

    Two equivalent ways to set it:

    * ``x-synthetic-completion`` request header — preferred for bench harnesses
      that send it alongside the existing prompt body without modifying it.
    * ``metadata.synthetic_completion`` inside the request body — useful when a
      proxy client cannot easily set custom headers.

    Returns ``None`` when neither is present, so the regular upstream path runs
    unchanged. Empty strings are accepted and mean "the assistant produced no
    text" — that is itself a useful test case (e.g. over-refusal probes that
    return only a refusal sentence).
    """

    header = request.headers.get("x-synthetic-completion")
    if header is not None:
        return header

    metadata = body.get("metadata") if isinstance(body, dict) else None
    if isinstance(metadata, dict) and "synthetic_completion" in metadata:
        value = metadata.get("synthetic_completion")
        if isinstance(value, str):
            return value
    return None


def _build_synthetic_upstream(
    api_format: str,
    synthetic_text: str,
    model: Any,
) -> JsonObject:
    """Build a chat-completion-shaped JSON payload carrying ``synthetic_text``.

    The shape mirrors what the upstream provider would have returned, so the
    rest of ``_run_enforced_request`` (normalize → outbound enforcement →
    serialize) treats the synthetic completion identically to a real one.
    """

    model_id = str(model) if isinstance(model, str) and model else "enfguard-synthetic"
    if api_format == "anthropic":
        return {
            "id": "msg_enfguard_synthetic",
            "type": "message",
            "role": "assistant",
            "model": model_id,
            "content": [{"type": "text", "text": synthetic_text}],
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "usage": {"input_tokens": 0, "output_tokens": 0},
        }
    return {
        "id": "chatcmpl-enfguard-synthetic",
        "object": "chat.completion",
        "created": 0,
        "model": model_id,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": synthetic_text},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


def _enforcement_headers(action: str, reason: str, tid: int) -> dict[str, str]:
    return {
        "X-Enforcement-Action": action,
        "X-Enforcement-Reason": _safe_header_value(reason),
        "X-Tid": str(tid),
    }


def _safe_header_value(value: Any, limit: int = 512) -> str:
    """Encode an arbitrary string as a single-line, ASCII-safe HTTP header value.

    HTTP headers are latin-1 by spec; previously we used ``encode('latin-1',
    'replace')`` which silently turned every non-ASCII character into ``?``,
    so a German judge reason like "Verstößt gegen…" would show up as
    "Verst????t gegen…". We now percent-encode anything outside printable
    ASCII so the original bytes are recoverable client-side via
    ``urllib.parse.unquote``.
    """

    text = str(value or "").replace("\r", " ").replace("\n", " ")
    text = " ".join(text.split())
    # quote() leaves ASCII printable + a small safe set untouched and
    # percent-encodes the rest, including raw bytes.
    text = quote(text, safe=" ()[]{}.,:;!?/-_+'\"")
    if len(text) > limit:
        text = text[: limit - 3].rstrip() + "..."
    return text


def _safe_file_part(value: str) -> str:
    raw = str(value or "")
    safe = "".join(char if char.isalnum() or char in "._-" else "_" for char in raw)
    digest = hashlib.blake2b(raw.encode("utf-8"), digest_size=6).hexdigest()
    return f"{safe[:64] or 'default'}-{digest}"


def _int_value(value: Any) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return 0
    return max(0, number)


def _is_int_like(value: Any) -> bool:
    try:
        int(value)
    except (TypeError, ValueError):
        return False
    return True


def _logger() -> Logger:
    if state.logger is None:
        raise HTTPException(status_code=503, detail="Enforcer is not started")
    return state.logger


def _http() -> httpx.AsyncClient:
    if state.http is None:
        raise HTTPException(status_code=503, detail="HTTP client is not started")
    return state.http
