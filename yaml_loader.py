"""Load ``enfguard.yaml`` and materialize runtime state.

The YAML file is the restart-time source of truth. The user owns every policy and every predicate. 
The composite formula is the user's policy snippets joined together and the composite signature is he
events the proxy emits plus a ``fun`` declaration for every predicate the user declares in ``predicates``.

Three predicate kinds are supported:

* ``kind: builtin`` — opt-in to a helper Python predicate that ships with the
  proxy (``hard_rules``, ``contains_secrets``, ``model_blocklist``). The
  signature is generated automatically.
* ``kind: llm_judge`` — judge-style predicate; the YAML provides the system
  prompt.
* ``kind: python`` — load a function from a user-controlled file.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from config import RuntimeConfig
from static_analysis import extract_predicate_calls
from switch_state import ENFORCEMENT_MODE_SWITCH_ID, SwitchSpec, default_enforcement_mode_spec

JsonObject = dict[str, Any]

_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_VALID_FAIL_MODES = {"open", "closed", "warn"}

# Predicates that the proxy ships as Python helpers. Users opt in by declaring
# `kind: builtin` with one of these names.
_BUILTIN_PREDICATE_NAMES: frozenset[str] = frozenset(
    {"hard_rules", "contains_secrets", "model_blocklist", "wall_ms_within"}
)
_DETERMINISTIC_BUILTIN_PREDICATES: frozenset[str] = frozenset({"hard_rules", "model_blocklist"})
_VALID_ARG_TYPES = {"string", "int", "float"}
_VALID_JUDGE_BACKENDS = {"", "openai", "ollama", "anthropic"}
_LLM_JUDGE_ALLOWED_INPUTS: frozenset[tuple[str, str]] = frozenset(
    {
        ("Message", "content"),
        ("Completion", "content"),
        # Tool-plan / tool-call input string (the proposed command or args).
        # Lets judges classify the *action* an agent is about to take, not just
        # request/response text. Still current-turn only (no history/results).
        ("ToolPlanned", "input"),
        ("ToolCall", "input"),
    }
)

# Restriction: LLM judges may see current message/completion content or the
# current tool-plan/tool-call input — NOT tool results, session history, etc.


_VALID_SWITCH_KINDS = {"int", "number", "boolean", "choice"}
_NUMERIC_SWITCH_KINDS = {"int", "number"}
_VALID_HUMAN_APPROVAL_TIMEOUT_FALLBACKS = {"allow", "warn", "block"}
_POLICY_ACTIVE_RE = re.compile(r'PolicyActive\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*,\s*"([^"]+)"\s*\)')
_LIVE_POLICIES_FILENAME = "live_policies.json"


@dataclass(frozen=True)
class IngestJudgeConfig:
    """Independent switches for deterministic-first ingest-time judges."""

    enabled: bool = True
    unknown_tool: bool = True
    unknown_tool_allow_threshold: float = 0.95
    url_risk: bool = True
    persistence_instruction: bool = True
    secret_material: bool = True
    uncertain_action: bool = True
    package_name: bool = True
    webshell: bool = True
    content_disclosure: bool = True
    semantic_command: bool = True
    content_semantics: bool = True
    memory_poison: bool = True
    authored_capability: bool = True


@dataclass(frozen=True)
class BackendConfig:
    """Backend/runtime settings loaded from YAML."""

    chat_llm: str = "openai"
    enfguard_bin: Path | None = None
    anthropic_base_url: str | None = None
    openai_base_url: str | None = None
    ollama_base_url: str | None = None
    judge_backend: str = "ollama"
    judge_openai_model: str = "gpt-4o-mini"
    judge_ollama_model: str = "qwen2.5:0.5b"
    judge_anthropic_model: str = "claude-3-5-haiku-latest"
    judge_timeout_ms: int = 2500
    judge_fail_mode: str = "closed"
    # Tools whose results are NOT tagged as untrusted. By default every
    # ``ToolCallResult`` is paired with an ``Untrusted(tid, "tool_result")``
    # event so prompt-injection-via-tool defences fire. A deployment can
    # opt specific tool names out (e.g. a deterministic calculator or an
    # internal clock) by listing them here.
    trusted_tool_names: tuple[str, ...] = ()
    # Legacy all-ingest-judges master/default. New YAML should use the
    # independent ``ingest_judges`` block below.
    unknown_tool_judge: bool = True
    ingest_judges: IngestJudgeConfig = IngestJudgeConfig()


@dataclass(frozen=True)
class PredicateArg:
    """One generated signature argument for a user predicate."""

    name: str
    type: str = "string"


@dataclass(frozen=True)
class PredicateInput:
    """One event field to pre-evaluate for a predicate.

    Predicate functions are still single-argument at runtime. Multiple
    ``inputs`` entries mean "run the same predicate independently for each
    listed event field and cache each result."
    """

    source: str
    arg: str = "content"


@dataclass(frozen=True)
class PredicateSpec:
    """A user-declared predicate made available to custom policies later.

    The ``backend`` / ``model`` / ``timeout_ms`` fields are per-predicate
    overrides for the global ``backend.judge_*`` settings. Empty / zero
    values mean "fall back to the global default". Per-predicate overrides
    only apply to ``kind: llm_judge`` and ``kind: builtin`` predicates;
    ``kind: python`` predicates don't call a judge LLM.
    """

    name: str
    kind: str
    args: tuple[PredicateArg, ...] = (PredicateArg("content", "string"),)
    inputs: tuple[PredicateInput, ...] = ()
    path: Path | None = None
    system_prompt: str = ""
    on_fail: str | None = None
    backend: str = ""        # "openai" | "ollama" | "anthropic" | ""
    model: str = ""          # provider-specific model id; "" = use global default
    timeout_ms: int = 0      # 0 = use global JUDGE_TIMEOUT_MS


@dataclass(frozen=True)
class PolicySpec:
    """One MFOTL policy declared in YAML or installed as a live overlay.

    ``scope`` controls persistence across proxy restarts. YAML-sourced
    policies are always ``"persistent"`` (they live in source-controlled
    YAML). Live overlays can be ``"session"`` (default — wiped from
    runtime state at proxy startup so the next run starts from pure YAML)
    or ``"persistent"`` (kept across restarts in ``live_policies.json``).
    """

    id: str
    enabled: bool = True
    threshold: float | None = None
    mfotl: str = ""
    source: str = "yaml"
    scope: str = "persistent"


_VALID_LIVE_POLICY_SCOPES: frozenset[str] = frozenset({"session", "persistent"})


@dataclass(frozen=True)
class HumanApprovalConfig:
    """Toggle and timeout policy for the human-approval verdict.

    When ``enabled=False`` the proxy treats any ``Approve`` verdict
    coming back from EnfGuard as a hard block, so policies stay safe even if
    the operator forgot to wire the UI subscription.
    """

    enabled: bool = False
    timeout_seconds: int = 60
    on_timeout: str = "block"


@dataclass(frozen=True)
class FeedbackConfig:
    """Toggle for optional user feedback events.

    Human approval decisions are controlled by ``human_approval`` and remain
    resolvable even when generic feedback is disabled.
    """

    enabled: bool = True


JUDGE_STRATEGY_CHOICES = ("off", "all_firing", "active_policy", "guard_aware")
JUDGE_CALL_MODE_CHOICES = ("batched", "parallel")


@dataclass(frozen=True)
class RuntimeOptions:
    """Proxy-runtime behavior toggles loaded from YAML and editable in UI.

    ``judge_strategy`` selects which judge calls are pre-computed before
    EnfGuard runs:

    * ``off``            — no pre-evaluation; EnfGuard's subprocess calls
                           each predicate sequentially. Correctness baseline.
    * ``all_firing``     — every declared judge predicate × every event
                           it could possibly read. Greedy upper bound.
    * ``active_policy``  — only judges referenced by an active policy
                           (current default — uses ``predicate_policies``).
    * ``guard_aware``    — ``active_policy`` plus skip judges whose
                           single-clause switch guard makes them inert.

    ``judge_call_mode`` controls *how* the selected tasks are dispatched
    when there are multiple cache misses for the same backend/model:

    * ``batched`` — one upstream call carrying all tasks (current default).
    * ``parallel`` — N concurrent single-task calls (asyncio gather over
                     a thread pool). Avoids the long batch prompt format.

    Both options exist so a benchmark harness can sweep the matrix.
    """

    judge_batching: str = "conservative"  # conservative | aggressive
    trace_assistant_content: bool = True
    judge_strategy: str = "active_policy"  # see JUDGE_STRATEGY_CHOICES
    judge_call_mode: str = "batched"       # see JUDGE_CALL_MODE_CHOICES


@dataclass(frozen=True)
class LoadedConfig:
    """Normalized YAML config and generated composite-policy path."""

    backend: BackendConfig
    predicates: list[PredicateSpec] = field(default_factory=list)
    policies: list[PolicySpec] = field(default_factory=list)
    switches: list[SwitchSpec] = field(default_factory=list)
    human_approval: HumanApprovalConfig = field(default_factory=HumanApprovalConfig)
    feedback: FeedbackConfig = field(default_factory=FeedbackConfig)
    runtime_options: RuntimeOptions = field(default_factory=RuntimeOptions)
    merged_mfotl_path: Path = Path()
    merged_sig_path: Path = Path()


def load(path: Path, runtime: RuntimeConfig) -> LoadedConfig:
    """Load YAML and write runtime files used by the proxy and predicates."""

    raw = _read_yaml(path)
    base_dir = path.resolve().parent if path.exists() else runtime.base_dir
    backend = _parse_backend(raw.get("backend"), base_dir)
    predicates = _parse_predicates(
        raw.get("predicates"),
        base_dir,
        _signature_events(runtime.signature_file),
    )
    yaml_policies = _parse_policies(raw.get("policies"))
    live_policies = _load_live_policies(runtime.state_dir / _LIVE_POLICIES_FILENAME)
    policies = _merge_live_policies(yaml_policies, live_policies)
    if raw.get("features") is not None:
        raise ValueError(
            "the `features:` block is no longer used. Drop it from "
            "enfguard.yaml — the runtime knobs you used to put there "
            "(such as enforcement_mode) live in `switches:` instead."
        )
    switches = _parse_switches(raw.get("switches"))
    human_approval = _parse_human_approval(raw.get("human_approval"))
    feedback = _parse_feedback(raw.get("feedback"))
    runtime_options = _parse_runtime_options(raw.get("runtime"))

    runtime.state_dir.mkdir(parents=True, exist_ok=True)
    runtime.logs_dir.mkdir(parents=True, exist_ok=True)
    sig_path = _write_composite_sig(runtime.signature_file, runtime.composite_signature_file, predicates)
    enfguard_bin = backend.enfguard_bin or runtime.enfguard_bin
    _validate_custom_mfotl_snippets(
        sig_path=sig_path,
        policies=policies,
        enfguard_bin=enfguard_bin,
        work_dir=runtime.state_dir,
    )
    composite_text, custom_blocks = _build_composite_mfotl(
        runtime.default_policy_file,
        policies,
    )
    candidate_path = _write_candidate_composite_mfotl(runtime.composite_policy_file, composite_text)
    _validate_composite_mfotl(sig_path, candidate_path, enfguard_bin)
    _validate_llm_judge_policy_sources(sig_path, candidate_path, predicates)
    merged_path = _promote_composite_mfotl(
        runtime.composite_policy_file,
        composite_text,
        custom_blocks,
    )
    _write_active_state(
        runtime.state_dir / "active_policies.json",
        backend,
        predicates,
        policies,
        raw,
        switches,
        human_approval,
        feedback,
        runtime_options,
    )

    return LoadedConfig(
        backend=backend,
        predicates=predicates,
        policies=policies,
        switches=switches,
        human_approval=human_approval,
        feedback=feedback,
        runtime_options=runtime_options,
        merged_mfotl_path=merged_path,
        merged_sig_path=sig_path,
    )


def _read_yaml(path: Path) -> JsonObject:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return _default_yaml()
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML in {path}: {exc}") from exc
    if data is None:
        return _default_yaml()
    if not isinstance(data, dict):
        raise ValueError("enfguard.yaml must contain a mapping at the top level")
    return data


def _default_yaml() -> JsonObject:
    """Empty YAML — no predicates, no policies. Composite collapses to ALWAYS TRUE."""

    return {
        "backend": {},
        "predicates": [],
        "policies": [],
    }


def _parse_backend(raw: Any, base_dir: Path) -> BackendConfig:
    data = _mapping(raw, "backend")
    legacy_judge_enabled = _bool_value(data.get("unknown_tool_judge"), True)
    return BackendConfig(
        chat_llm=str(data.get("chat_llm", "openai") or "openai"),
        enfguard_bin=_optional_path(data.get("enfguard_bin"), base_dir),
        anthropic_base_url=_optional_str(data.get("anthropic_base_url")),
        openai_base_url=_optional_str(data.get("openai_base_url")),
        ollama_base_url=_optional_str(data.get("ollama_base_url")),
        judge_backend=str(data.get("judge_backend", "ollama") or "ollama"),
        judge_openai_model=str(data.get("judge_openai_model", "gpt-4o-mini") or "gpt-4o-mini"),
        judge_ollama_model=str(data.get("judge_ollama_model", "qwen2.5:0.5b") or "qwen2.5:0.5b"),
        judge_anthropic_model=str(
            data.get("judge_anthropic_model", "claude-3-5-haiku-latest")
            or "claude-3-5-haiku-latest"
        ),
        judge_timeout_ms=max(1, _int_value(data.get("judge_timeout_ms"), 2500)),
        judge_fail_mode=_fail_mode(data.get("judge_fail_mode"), "closed"),
        trusted_tool_names=_parse_trusted_tool_names(data.get("trusted_tool_names")),
        unknown_tool_judge=legacy_judge_enabled,
        ingest_judges=_parse_ingest_judges(
            data.get("ingest_judges"),
            legacy_judge_enabled,
        ),
    )


def _parse_ingest_judges(raw: Any, legacy_default: bool) -> IngestJudgeConfig:
    """Parse per-adapter ingest judge switches.

    ``backend.unknown_tool_judge`` remains the backward-compatible default and
    master value when ``ingest_judges`` is absent. Once the new block is
    present, ``enabled`` is its master switch and every child defaults to that
    value unless explicitly overridden.
    """

    data = _mapping(raw, "backend.ingest_judges")
    master = _bool_value(data.get("enabled"), legacy_default)
    return IngestJudgeConfig(
        enabled=master,
        unknown_tool=_bool_value(data.get("unknown_tool"), master),
        unknown_tool_allow_threshold=_float_value(
            data.get("unknown_tool_allow_threshold", 0.95)
        ),
        url_risk=_bool_value(data.get("url_risk"), master),
        persistence_instruction=_bool_value(
            data.get("persistence_instruction"),
            master,
        ),
        secret_material=_bool_value(data.get("secret_material"), master),
        uncertain_action=_bool_value(data.get("uncertain_action"), master),
        package_name=_bool_value(data.get("package_name"), master),
        webshell=_bool_value(data.get("webshell"), master),
        content_disclosure=_bool_value(data.get("content_disclosure"), master),
        semantic_command=_bool_value(data.get("semantic_command"), master),
        content_semantics=_bool_value(data.get("content_semantics"), master),
        memory_poison=_bool_value(data.get("memory_poison"), master),
        authored_capability=_bool_value(data.get("authored_capability"), master),
    )


def _parse_trusted_tool_names(raw: Any) -> tuple[str, ...]:
    """Read ``backend.trusted_tool_names`` into a frozen tuple of names.

    Accepts a list of strings or a single string. Empty / missing values
    produce an empty tuple, which means every ``ToolCallResult`` will be
    paired with an ``Untrusted`` event (the safe default).
    """

    if raw is None or raw == "":
        return ()
    if isinstance(raw, str):
        names = [raw.strip()]
    elif isinstance(raw, (list, tuple)):
        names = [str(item).strip() for item in raw]
    else:
        return ()
    seen: list[str] = []
    for name in names:
        if not name:
            continue
        if name in seen:
            continue
        seen.append(name)
    return tuple(seen)


def _parse_predicates(
    raw: Any,
    base_dir: Path,
    signature_events: dict[str, tuple[str, ...]],
) -> list[PredicateSpec]:
    """Validate and normalize the YAML ``predicates`` block.

    Three kinds are accepted: ``builtin`` (must be one of the helper names
    shipped with the proxy), ``llm_judge`` (with a ``system_prompt``), and
    ``python`` (with a ``path``). Names must not collide with each other or
    with an event from the proxy's signature file.
    """

    specs: list[PredicateSpec] = []
    seen_names: set[str] = set()
    for item in _list(raw, "predicates"):
        data = _mapping(item, "predicate")
        name = str(data.get("name", "") or "")
        _validate_name(name, "predicate name")
        signature_event_names = set(signature_events)
        if name in signature_event_names:
            raise ValueError(
                f"predicate name {name!r} collides with a proxy event in the signature; "
                "rename it (e.g. acme_contains_pii) so it does not shadow events"
            )
        if name in seen_names:
            raise ValueError(f"duplicate user predicate name: {name!r}")
        seen_names.add(name)

        kind = str(data.get("kind", "") or "").strip()
        if kind not in {"builtin", "python", "llm_judge"}:
            raise ValueError(f"predicate {name!r} has unsupported kind {kind!r}")

        if kind == "builtin" and name not in _BUILTIN_PREDICATE_NAMES:
            allowed = ", ".join(sorted(_BUILTIN_PREDICATE_NAMES))
            raise ValueError(
                f"builtin predicate {name!r} is not a known helper; "
                f"available built-ins: {allowed}"
            )

        # Built-ins with non-default argument shapes get a default-args
        # override here so the user does not have to spell them out in
        # YAML. `wall_ms_within(now_ms, then_ms, threshold_ms)` takes
        # three integers; the others default to a single `content`.
        if kind == "builtin" and name == "wall_ms_within" and "args" not in data:
            args = (
                PredicateArg("now_ms", "int"),
                PredicateArg("then_ms", "int"),
                PredicateArg("threshold_ms", "int"),
            )
        else:
            args = _parse_predicate_args(data.get("args"))
        inputs = _parse_predicate_inputs(data.get("inputs"), signature_events, name)
        path = _optional_path(data.get("path"), base_dir)
        system_prompt = str(data.get("system_prompt", "") or "")
        if kind == "python":
            if path is None:
                raise ValueError(f"python predicate {name!r} needs a path")
            if not path.exists():
                raise ValueError(f"python predicate path does not exist: {path}")
        if kind == "llm_judge" and not system_prompt.strip():
            raise ValueError(f"llm_judge predicate {name!r} needs system_prompt")
        if kind == "llm_judge":
            _validate_llm_judge_inputs_current_only(name, inputs)
            _warn_judge_prompt_format_instructions(name, system_prompt)

        on_fail = data.get("on_fail")

        # Per-predicate judge backend overrides. Empty / zero means "use
        # the global default declared in `backend:`". `kind: python`
        # predicates do not talk to a judge LLM, so we reject these
        # fields on them to surface YAML mistakes instead of silently
        # ignoring them.
        backend_raw = str(data.get("backend", "") or "").strip().lower()
        if backend_raw not in _VALID_JUDGE_BACKENDS:
            raise ValueError(
                f"predicate {name!r}: backend must be one of "
                f"{sorted(b for b in _VALID_JUDGE_BACKENDS if b)} "
                f"(got {backend_raw!r})"
            )
        model_override = str(data.get("model", "") or "").strip()
        timeout_override = data.get("timeout_ms")
        if timeout_override is None:
            timeout_ms = 0
        else:
            timeout_ms = _int_value(timeout_override, 0)
            if timeout_ms <= 0:
                raise ValueError(
                    f"predicate {name!r}: timeout_ms must be a positive integer (got {timeout_override!r})"
                )
        if kind == "python" and (backend_raw or model_override or timeout_ms):
            raise ValueError(
                f"predicate {name!r}: backend / model / timeout_ms only apply "
                "to kind: llm_judge or kind: builtin (kind: python loads a "
                "function from disk, no judge call is made)"
            )

        specs.append(
            PredicateSpec(
                name=name,
                kind=kind,
                args=args,
                inputs=inputs,
                path=path,
                system_prompt=system_prompt,
                on_fail=_fail_mode(on_fail, "") if on_fail else None,
                backend=backend_raw,
                model=model_override,
                timeout_ms=timeout_ms,
            )
        )
    return specs


def _signature_events(sig_file: Path) -> dict[str, tuple[str, ...]]:
    """Pull event names and argument names out of the base signature file."""

    events: dict[str, tuple[str, ...]] = {}
    try:
        lines = sig_file.read_text(encoding="utf-8").splitlines()
    except OSError:
        return events
    for raw_line in lines:
        line = raw_line.split("#", 1)[0].strip()
        match = re.match(r"^(?:fun\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)", line)
        if match:
            arg_names: list[str] = []
            for raw_arg in match.group(2).split(","):
                raw_arg = raw_arg.strip()
                if not raw_arg or ":" not in raw_arg:
                    continue
                arg_names.append(raw_arg.split(":", 1)[0].strip())
            events[match.group(1)] = tuple(arg_names)
    return events


def _parse_predicate_inputs(
    raw: Any,
    signature_events: dict[str, tuple[str, ...]],
    predicate_name: str,
) -> tuple[PredicateInput, ...]:
    if raw is None:
        return ()
    inputs: list[PredicateInput] = []
    seen: set[tuple[str, str]] = set()
    for item in _list(raw, f"predicate {predicate_name!r} inputs"):
        data = _mapping(item, f"predicate {predicate_name!r} input")
        source = str(data.get("source", "") or "")
        arg = str(data.get("arg", "content") or "content")
        _validate_name(source, f"predicate {predicate_name!r} input source")
        _validate_name(arg, f"predicate {predicate_name!r} input arg")
        if source not in signature_events:
            raise ValueError(
                f"predicate {predicate_name!r} input source {source!r} is not an event in the signature"
            )
        if arg not in signature_events[source]:
            raise ValueError(
                f"predicate {predicate_name!r} input {source}.{arg} does not exist; "
                f"available args: {', '.join(signature_events[source])}"
            )
        key = (source, arg)
        if key in seen:
            continue
        seen.add(key)
        inputs.append(PredicateInput(source=source, arg=arg))
    return tuple(inputs)


def _validate_llm_judge_inputs_current_only(
    predicate_name: str,
    inputs: tuple[PredicateInput, ...],
) -> None:
    """Keep judge prompts scoped to the current user request or model response."""

    for item in inputs:
        key = (item.source, item.arg)
        if key in _LLM_JUDGE_ALLOWED_INPUTS:
            continue
        allowed = ", ".join(f"{source}.{arg}" for source, arg in sorted(_LLM_JUDGE_ALLOWED_INPUTS))
        raise ValueError(
            f"llm_judge predicate {predicate_name!r} input {item.source}.{item.arg} is not allowed; "
            "judge prompts may only receive current request/response text "
            f"({allowed})"
        )


def _validate_llm_judge_policy_sources(
    sig_path: Path,
    mfotl_path: Path,
    predicates: list[PredicateSpec],
) -> None:
    """Reject policies that bind LLM judges to history/system events."""

    judge_names = {predicate.name for predicate in predicates if predicate.kind == "llm_judge"}
    if not judge_names:
        return
    calls_by_event = extract_predicate_calls(mfotl_path, sig_path)
    for calls in calls_by_event.values():
        for call in calls:
            if call.predicate not in judge_names:
                continue
            for arg_source in call.arg_sources:
                source, _, arg = str(arg_source).partition(".")
                key = (source, arg)
                if key in _LLM_JUDGE_ALLOWED_INPUTS:
                    continue
                allowed = ", ".join(
                    f"{allowed_source}.{allowed_arg}"
                    for allowed_source, allowed_arg in sorted(_LLM_JUDGE_ALLOWED_INPUTS)
                )
                raise ValueError(
                    f"llm_judge predicate {call.predicate!r} is bound to {arg_source} in policy "
                    f"{mfotl_path}; judge prompts may only receive current request/response text "
                    f"({allowed})"
                )


def _parse_policies(raw: Any) -> list[PolicySpec]:
    items = _list(raw, "policies")
    return _parse_policy_items(items, source="yaml")


def _parse_policy_items(items: list[Any], *, source: str) -> list[PolicySpec]:
    specs: list[PolicySpec] = []
    seen_ids: set[str] = set()
    default_scope = "session" if source == "live" else "persistent"
    for item in items:
        data = _mapping(item, "policy")
        policy_id = str(data.get("id", "") or "")
        _validate_name(policy_id, "policy id")
        if policy_id in seen_ids:
            raise ValueError(f"duplicate policy id: {policy_id!r}")
        seen_ids.add(policy_id)
        mfotl = str(data.get("mfotl", "") or "").strip()
        if not mfotl:
            raise ValueError(
                f"policy {policy_id!r} is missing an `mfotl` body; copy a clause from "
                "examples/inspiration_policies.mfotl or write your own"
            )
        threshold = data.get("threshold")
        # YAML policies are always persistent; live overlays may set scope.
        if source == "live":
            raw_scope = str(data.get("scope", default_scope) or default_scope).strip().lower()
            if raw_scope not in _VALID_LIVE_POLICY_SCOPES:
                raise ValueError(
                    f"live policy {policy_id!r} has unsupported scope {raw_scope!r}; "
                    f"expected one of {sorted(_VALID_LIVE_POLICY_SCOPES)}"
                )
            scope = raw_scope
        else:
            scope = "persistent"
        specs.append(
            PolicySpec(
                id=policy_id,
                enabled=_bool_value(data.get("enabled"), True),
                threshold=_float_value(threshold) if threshold is not None else None,
                mfotl=mfotl,
                source=source,
                scope=scope,
            )
        )
    return specs


def _load_live_policies(path: Path) -> list[PolicySpec]:
    """Load policies installed through the admin UI.

    The starter YAML stays human-readable; live policies live in runtime state
    and are merged into the same validation/reload path as YAML policies.
    """

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in {path}: {exc}") from exc
    if isinstance(raw, dict):
        items = raw.get("policies")
    else:
        items = raw
    return _parse_policy_items(_list(items, "live policies"), source="live")


def _merge_live_policies(base: list[PolicySpec], live: list[PolicySpec]) -> list[PolicySpec]:
    if not live:
        return base
    by_id = {policy.id: policy for policy in live}
    merged: list[PolicySpec] = []
    consumed: set[str] = set()
    for policy in base:
        replacement = by_id.get(policy.id)
        if replacement is None:
            merged.append(policy)
            continue
        merged.append(replacement)
        consumed.add(policy.id)
    merged.extend(policy for policy in live if policy.id not in consumed)
    return merged


def _parse_switches(raw: Any) -> list[SwitchSpec]:
    """Parse the optional ``switches:`` block.

    Switches are user-declared parameterisable controls. The proxy emits each
    one as an MFOTL event at the start of every phase so policies can
    reference current values. ``enforcement_mode`` is special-cased: if the
    user does not declare it, the proxy synthesises the global
    ``audit | warn | enforce`` mode switch.
    """

    items = _list(raw, "switches")
    specs: list[SwitchSpec] = []
    seen_ids: set[str] = set()
    for item in items:
        data = _mapping(item, "switch")
        switch_id = str(data.get("id", "") or "")
        _validate_name(switch_id, "switch id")
        if switch_id in seen_ids:
            raise ValueError(f"duplicate switch id: {switch_id!r}")
        seen_ids.add(switch_id)

        kind_raw = str(data.get("kind", "") or "").strip().lower()
        if kind_raw not in _VALID_SWITCH_KINDS:
            raise ValueError(
                f"switch {switch_id!r} has unsupported kind {kind_raw!r}; "
                f"expected one of {sorted(_VALID_SWITCH_KINDS)}"
            )
        # `number` is an alias for `int` so existing YAML keeps working.
        kind = "int" if kind_raw == "number" else kind_raw
        label = str(data.get("label", "") or "")
        default = data.get("default")

        min_value: float | None = None
        max_value: float | None = None
        options: tuple[str, ...] = ()
        if kind in _NUMERIC_SWITCH_KINDS:
            if "min" in data:
                min_value = _float_unbounded(data.get("min"), f"switch {switch_id!r} min")
            if "max" in data:
                max_value = _float_unbounded(data.get("max"), f"switch {switch_id!r} max")
            if min_value is not None and max_value is not None and min_value > max_value:
                raise ValueError(
                    f"switch {switch_id!r}: min {min_value} is greater than max {max_value}"
                )
            if default is not None:
                default_number = _float_unbounded(default, f"switch {switch_id!r} default")
                if min_value is not None and default_number < min_value:
                    raise ValueError(
                        f"switch {switch_id!r}: default {default_number} is below min {min_value}"
                    )
                if max_value is not None and default_number > max_value:
                    raise ValueError(
                        f"switch {switch_id!r}: default {default_number} is above max {max_value}"
                    )
                default = default_number
            # `int` switches must hold integer values — reject fractional
            # defaults / bounds rather than silently truncating them.
            if kind == "int":
                for label_text, value in (
                    ("default", default),
                    ("min", min_value),
                    ("max", max_value),
                ):
                    if value is None:
                        continue
                    if float(value) != int(float(value)):
                        raise ValueError(
                            f"switch {switch_id!r}: int switches require integer "
                            f"{label_text} (got {value!r}); use basis points for fractional values"
                        )
                default = None if default is None else int(float(default))
                min_value = None if min_value is None else float(int(min_value))
                max_value = None if max_value is None else float(int(max_value))
        elif kind == "boolean":
            default = _bool_value(default, False)
        elif kind == "choice":
            raw_options = data.get("options")
            if not isinstance(raw_options, list) or not raw_options:
                raise ValueError(
                    f"switch {switch_id!r}: choice switches need a non-empty `options` list"
                )
            options = tuple(str(option) for option in raw_options)
            if default is None:
                default = options[0]
            elif str(default) not in options:
                raise ValueError(
                    f"switch {switch_id!r}: default {default!r} is not in options {list(options)}"
                )

        specs.append(
            SwitchSpec(
                id=switch_id,
                kind=kind,
                label=label,
                default=default,
                min_value=min_value,
                max_value=max_value,
                options=options,
            )
        )

    if not any(spec.id == ENFORCEMENT_MODE_SWITCH_ID for spec in specs):
        specs.append(default_enforcement_mode_spec())

    return specs


def _parse_human_approval(raw: Any) -> HumanApprovalConfig:
    data = _mapping(raw, "human_approval")
    defaults = HumanApprovalConfig()
    timeout_raw = data.get("timeout_seconds", defaults.timeout_seconds)
    timeout = _int_value(timeout_raw, defaults.timeout_seconds)
    if timeout <= 0:
        raise ValueError("human_approval.timeout_seconds must be a positive integer")
    on_timeout = str(data.get("on_timeout", defaults.on_timeout) or defaults.on_timeout).strip().lower()
    if on_timeout not in _VALID_HUMAN_APPROVAL_TIMEOUT_FALLBACKS:
        raise ValueError(
            f"human_approval.on_timeout must be one of "
            f"{sorted(_VALID_HUMAN_APPROVAL_TIMEOUT_FALLBACKS)}, got {on_timeout!r}"
        )
    return HumanApprovalConfig(
        enabled=_bool_value(data.get("enabled"), defaults.enabled),
        timeout_seconds=timeout,
        on_timeout=on_timeout,
    )


def _parse_feedback(raw: Any) -> FeedbackConfig:
    data = _mapping(raw, "feedback")
    defaults = FeedbackConfig()
    return FeedbackConfig(enabled=_bool_value(data.get("enabled"), defaults.enabled))


def _parse_runtime_options(raw: Any) -> RuntimeOptions:
    data = _mapping(raw, "runtime")
    defaults = RuntimeOptions()
    batching = str(data.get("judge_batching", defaults.judge_batching) or defaults.judge_batching)
    batching = batching.strip().lower()
    if batching not in {"conservative", "aggressive"}:
        raise ValueError("runtime.judge_batching must be 'conservative' or 'aggressive'")
    strategy = str(
        data.get("judge_strategy", defaults.judge_strategy) or defaults.judge_strategy
    ).strip().lower()
    if strategy not in JUDGE_STRATEGY_CHOICES:
        raise ValueError(
            f"runtime.judge_strategy must be one of {list(JUDGE_STRATEGY_CHOICES)}"
        )
    call_mode = str(
        data.get("judge_call_mode", defaults.judge_call_mode) or defaults.judge_call_mode
    ).strip().lower()
    if call_mode not in JUDGE_CALL_MODE_CHOICES:
        raise ValueError(
            f"runtime.judge_call_mode must be one of {list(JUDGE_CALL_MODE_CHOICES)}"
        )
    return RuntimeOptions(
        judge_batching=batching,
        trace_assistant_content=_bool_value(
            data.get("trace_assistant_content"),
            defaults.trace_assistant_content,
        ),
        judge_strategy=strategy,
        judge_call_mode=call_mode,
    )


def _write_active_state(
    path: Path,
    backend: BackendConfig,
    predicates: list[PredicateSpec],
    policies: list[PolicySpec],
    raw: JsonObject,
    switches: list[SwitchSpec],
    human_approval: HumanApprovalConfig,
    feedback: FeedbackConfig,
    runtime_options: RuntimeOptions,
) -> None:
    """Write ``state/active_policies.json`` from the user-authored YAML."""

    active = [policy.id for policy in policies if policy.enabled]
    # `thresholds` is now strictly user-authored: we no longer infer
    # per-predicate thresholds from policy thresholds. A user who wants a
    # custom hard_rules threshold writes `thresholds: {hard_rules: 0.7}`.
    thresholds = {
        str(name): float(value)
        for name, value in _mapping(raw.get("thresholds"), "thresholds").items()
    }

    judge_fail_modes = {
        spec.name: spec.on_fail
        for spec in predicates
        if spec.on_fail is not None and spec.name not in _DETERMINISTIC_BUILTIN_PREDICATES
    }
    raw_fail_modes = _mapping(raw.get("judge_fail_modes"), "judge_fail_modes")
    for name, mode in raw_fail_modes.items():
        predicate_name = str(name)
        _validate_name(predicate_name, "judge fail-mode predicate name")
        if predicate_name in _DETERMINISTIC_BUILTIN_PREDICATES:
            continue
        judge_fail_modes[predicate_name] = _fail_mode(mode, "")

    state: JsonObject = {
        "active": active,
        "policies": [_policy_state(policy) for policy in policies],
        "thresholds": thresholds,
        "policy_thresholds": {
            policy.id: policy.threshold for policy in policies if policy.threshold is not None
        },
        "model_blocklist": _string_list(raw.get("model_blocklist")),
        "judge_fail_mode": backend.judge_fail_mode,
        "ingest_judges": {
            "enabled": backend.ingest_judges.enabled,
            "unknown_tool": backend.ingest_judges.unknown_tool,
            "unknown_tool_allow_threshold": (
                backend.ingest_judges.unknown_tool_allow_threshold
            ),
            "url_risk": backend.ingest_judges.url_risk,
            "persistence_instruction": backend.ingest_judges.persistence_instruction,
            "secret_material": backend.ingest_judges.secret_material,
            "uncertain_action": backend.ingest_judges.uncertain_action,
            "package_name": backend.ingest_judges.package_name,
            "webshell": backend.ingest_judges.webshell,
            "content_disclosure": backend.ingest_judges.content_disclosure,
            "semantic_command": backend.ingest_judges.semantic_command,
            "content_semantics": backend.ingest_judges.content_semantics,
            "memory_poison": backend.ingest_judges.memory_poison,
            "authored_capability": backend.ingest_judges.authored_capability,
        },
        "judge_fail_modes": judge_fail_modes,
        "user_predicates": [_predicate_state(spec) for spec in predicates],
        "switches": [_switch_state(spec) for spec in switches],
        "human_approval": {
            "enabled": human_approval.enabled,
            "timeout_seconds": human_approval.timeout_seconds,
            "on_timeout": human_approval.on_timeout,
        },
        "feedback": {
            "enabled": feedback.enabled,
        },
        "runtime": {
            "judge_batching": runtime_options.judge_batching,
            "trace_assistant_content": runtime_options.trace_assistant_content,
            "judge_strategy": runtime_options.judge_strategy,
            "judge_call_mode": runtime_options.judge_call_mode,
        },
        "predicate_policies": _predicate_policy_state(predicates, policies),
    }
    _write_json_atomic(path, state)


def _policy_state(policy: PolicySpec) -> JsonObject:
    entry: JsonObject = {
        "id": policy.id,
        "enabled": policy.enabled,
        "source": policy.source,
        # The MFOTL body is persisted so runtime strategies (e.g. the
        # guard-aware judge selector) can inspect clause guards without
        # re-parsing the YAML or the composite formula.
        "mfotl": policy.mfotl,
        # ``scope`` is meaningful only for live overlays (``"session"`` vs
        # ``"persistent"``). YAML policies are always persistent.
        "scope": policy.scope,
    }
    if policy.threshold is not None:
        entry["threshold"] = policy.threshold
    return entry


def _predicate_policy_state(
    predicates: list[PredicateSpec],
    policies: list[PolicySpec],
) -> JsonObject:
    predicate_names = {spec.name for spec in predicates}
    result: dict[str, set[str]] = {name: set() for name in predicate_names}
    for policy in policies:
        active_gates = {match.group(1) for match in _POLICY_ACTIVE_RE.finditer(policy.mfotl)}
        for name in predicate_names:
            if re.search(rf"\b{re.escape(name)}\s*\(", policy.mfotl):
                result.setdefault(name, set()).update(active_gates)
    return {name: sorted(ids) for name, ids in result.items() if ids}


def _switch_state(spec: SwitchSpec) -> JsonObject:
    entry: JsonObject = {
        "id": spec.id,
        "kind": spec.kind,
        "label": spec.label,
        "default": spec.default,
    }
    # "number" was a back-compat alias for "int" that is normalised away in
    # _parse_switches. Use the canonical numeric kinds here so min/max are
    # always written for int AND float switches (the frontend needs them to
    # render range sliders correctly).
    if spec.kind in ("int", "float", "number"):
        if spec.min_value is not None:
            entry["min"] = spec.min_value
        if spec.max_value is not None:
            entry["max"] = spec.max_value
    if spec.kind == "choice":
        entry["options"] = list(spec.options)
    return entry


def _predicate_state(spec: PredicateSpec) -> JsonObject:
    return {
        "name": spec.name,
        "kind": spec.kind,
        "args": [{"name": arg.name, "type": arg.type} for arg in spec.args],
        "inputs": [{"source": item.source, "arg": item.arg} for item in spec.inputs],
        "path": str(spec.path) if spec.path else "",
        "system_prompt": spec.system_prompt,
        "on_fail": spec.on_fail,
        "backend": spec.backend,
        "model": spec.model,
        "timeout_ms": spec.timeout_ms,
    }


def _build_composite_mfotl(
    default_policy_file: Path,
    policies: list[PolicySpec],
) -> tuple[str, list[tuple[PolicySpec, str]]]:
    """Build the composite MFOTL formula from user-authored policies only.

    With at least one policy, the composite is the policy snippets joined by
    ``\\n\\nAND\\n\\n``. With zero policies, we fall back to the no-op file at
    ``default_policy_file`` (which ships as ``ALWAYS TRUE``) so the proxy
    still has a valid formula to load.
    """

    custom_blocks = [(policy, _format_custom_policy(policy)) for policy in policies]
    if not custom_blocks:
        fallback = default_policy_file.read_text(encoding="utf-8").strip()
        return fallback, []
    parts = [block for _, block in custom_blocks]
    text = "\n\nAND\n\n".join(parts)
    return text, custom_blocks


def _write_candidate_composite_mfotl(composite_policy_file: Path, text: str) -> Path:
    candidate_path = composite_policy_file.with_suffix(composite_policy_file.suffix + ".candidate")
    _write_text_atomic(candidate_path, text + "\n")
    return candidate_path


def _promote_composite_mfotl(
    composite_policy_file: Path,
    text: str,
    custom_blocks: list[tuple[PolicySpec, str]],
) -> Path:
    _write_text_atomic(composite_policy_file, text + "\n")
    _write_composite_map(composite_policy_file, custom_blocks)
    return composite_policy_file


def _write_composite_map(
    composite_policy_file: Path,
    custom_blocks: list[tuple[PolicySpec, str]],
) -> None:
    """Write a per-line index from composite line numbers back to YAML policies."""

    entries: list[JsonObject] = []
    if not custom_blocks:
        # The fallback `ALWAYS TRUE` is one logical block — record it as such
        # so trace/inspector views still get a valid map.
        entries.append(
            {
                "source": "default",
                "id": "fallback",
                "start_line": 1,
                "end_line": 1,
            }
        )
    else:
        current_line = 1
        for index, (policy, block) in enumerate(custom_blocks):
            block_lines = _line_count(block)
            entries.append(
                {
                    "source": "enfguard.yaml",
                    "id": policy.id,
                    "start_line": current_line,
                    "end_line": current_line + block_lines - 1,
                }
            )
            current_line += block_lines
            if index < len(custom_blocks) - 1:
                # Blank, AND, blank lines inserted by the join().
                current_line += 3

    map_path = composite_policy_file.with_suffix(composite_policy_file.suffix + ".map.json")
    _write_json_atomic(map_path, {"composite": str(composite_policy_file), "entries": entries})


def _line_count(text: str) -> int:
    return len((text or "").splitlines()) or 1


def _validate_custom_mfotl_snippets(
    sig_path: Path,
    policies: list[PolicySpec],
    enfguard_bin: Path,
    work_dir: Path,
) -> None:
    if not policies:
        return
    formatted_policies = [(policy, _format_custom_policy(policy)) for policy in policies]
    work_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mfotl_validate_", dir=work_dir) as temp_dir:
        temp_path = Path(temp_dir)
        for policy, formatted in formatted_policies:
            formula_path = temp_path / f"{policy.id}.mfotl"
            formula_path.write_text(formatted + "\n", encoding="utf-8")
            _run_enfguard_formula_check(enfguard_bin, sig_path, formula_path, policy.id)


def _validate_composite_mfotl(sig_path: Path, composite_path: Path, enfguard_bin: Path) -> None:
    _run_enfguard_formula_check(enfguard_bin, sig_path, composite_path, "composite")


def _run_enfguard_formula_check(
    enfguard_bin: Path,
    sig_path: Path,
    formula_path: Path,
    policy_id: str,
) -> None:
    cmd = [
        str(enfguard_bin),
        "-sig",
        str(sig_path),
        "-formula",
        str(formula_path),
        "-json",
    ]
    try:
        completed = subprocess.run(
            cmd,
            input=b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=5,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        output = _decode_process_output(exc.output)
        raise ValueError(
            f"custom policy {policy_id!r} MFOTL validation timed out"
            + (f": {output}" if output else "")
        ) from exc
    except OSError as exc:
        warnings.warn(
            f"skipping EnfGuard MFOTL syntax validation for {policy_id!r}: {exc}",
            RuntimeWarning,
            stacklevel=2,
        )
        return

    output = _decode_process_output(completed.stdout)
    if completed.returncode != 0:
        raise ValueError(
            f"custom policy {policy_id!r} has invalid MFOTL"
            + (f": {output}" if output else "")
        )


def _decode_process_output(raw: bytes | str | None) -> str:
    if raw is None:
        return ""
    if isinstance(raw, str):
        text = raw
    else:
        text = raw.decode("utf-8", errors="replace")
    return " ".join(text.split())[:1200]


def _format_custom_policy(policy: PolicySpec) -> str:
    expected_gate = f'PolicyActive(t, "{policy.id}")'
    if expected_gate not in policy.mfotl:
        raise ValueError(
            f"custom policy {policy.id!r} must reference {expected_gate!r} "
            "so runtime policy toggles work"
        )
    return policy.mfotl.strip()


def _write_composite_sig(
    builtin_sig_file: Path,
    composite_sig_file: Path,
    predicates: list[PredicateSpec],
) -> Path:
    """Write the composite signature: events from the base file + user funs.

    The base signature file declares only events. For each predicate the user
    declared in YAML — regardless of kind — we append a corresponding
    ``fun <name>(<args>) : float`` line so the EnfGuard build used by this
    proxy can call Python predicate functions through ``-func``.
    """

    base = builtin_sig_file.read_text(encoding="utf-8").rstrip()
    if not predicates:
        _write_text_atomic(composite_sig_file, base + "\n")
        return composite_sig_file

    lines = [base, "", "# User-defined predicates from enfguard.yaml."]
    for spec in predicates:
        args = ", ".join(f"{arg.name}:{arg.type}" for arg in spec.args)
        lines.append(f"fun {spec.name}({args}) : float")
    _write_text_atomic(composite_sig_file, "\n".join(lines) + "\n")
    return composite_sig_file


def _parse_predicate_args(raw: Any) -> tuple[PredicateArg, ...]:
    if raw is None:
        return (PredicateArg("content", "string"),)
    if not isinstance(raw, list) or not raw:
        raise ValueError("predicate args must be a non-empty list")

    args: list[PredicateArg] = []
    seen: set[str] = set()
    for item in raw:
        if isinstance(item, str):
            name = item
            arg_type = "string"
        else:
            data = _mapping(item, "predicate arg")
            name = str(data.get("name", "") or "")
            arg_type = str(data.get("type", "string") or "string")
        _validate_name(name, "predicate argument name")
        if name in seen:
            raise ValueError(f"duplicate predicate argument name: {name!r}")
        if arg_type not in _VALID_ARG_TYPES:
            raise ValueError(f"predicate argument {name!r} has unsupported type {arg_type!r}")
        seen.add(name)
        args.append(PredicateArg(name, arg_type))
    return tuple(args)


def _mapping(raw: Any, label: str) -> JsonObject:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError(f"{label} must be a mapping")
    return raw


def _list(raw: Any, label: str) -> list[Any]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError(f"{label} must be a list")
    return raw


def _string_list(raw: Any) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError("model_blocklist must be a list")
    return [str(item) for item in raw if str(item)]


def _optional_str(raw: Any) -> str | None:
    if raw is None:
        return None
    value = str(raw).strip()
    return value or None


def _optional_path(raw: Any, base_dir: Path) -> Path | None:
    if raw is None or str(raw).strip() == "":
        return None
    path = Path(os.path.expanduser(str(raw)))
    return path if path.is_absolute() else (base_dir / path).resolve()


def _validate_name(value: str, label: str) -> None:
    if not _NAME_RE.match(value):
        raise ValueError(f"invalid {label}: {value!r}")


def _fail_mode(raw: Any, default: str) -> str:
    value = str(raw or default).strip().lower()
    if value not in _VALID_FAIL_MODES:
        raise ValueError(f"judge fail mode must be one of {sorted(_VALID_FAIL_MODES)}")
    return value


def _warn_judge_prompt_format_instructions(name: str, system_prompt: str) -> None:
    text = str(system_prompt or "").lower()
    format_terms = (
        "json",
        "verdict",
        "evidence",
        "markdown",
        "schema",
    )
    if not any(term in text for term in format_terms):
        return
    warnings.warn(
        (
            f"llm_judge predicate {name!r} appears to include output-format "
            "instructions. EnfGuard owns the judge JSON/label/reason "
            "contract; YAML system_prompt should describe only what counts "
            "as a match and what is harmless/no-match."
        ),
        stacklevel=3,
    )


def _bool_value(raw: Any, default: bool) -> bool:
    if raw is None:
        return default
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, (int, float)):
        return bool(raw)
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _int_value(raw: Any, default: int) -> int:
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def _float_value(raw: Any) -> float:
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"threshold must be a number: {raw!r}") from exc
    return min(1.0, max(0.0, value))


def _float_unbounded(raw: Any, label: str) -> float:
    """Coerce ``raw`` to a finite float without clamping to [0, 1]."""

    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a number: {raw!r}") from exc
    return value


def _write_json_atomic(path: Path, data: JsonObject) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp_path, path)


def _write_text_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(text, encoding="utf-8")
    os.replace(tmp_path, path)
