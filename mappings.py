"""Map chat API payloads to EnfGuard v4 events
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from chat_text import (
    anthropic_content_text as _anthropic_content_text,
)
from chat_text import (
    anthropic_system_text as _anthropic_system_text,
)
from chat_text import (
    estimate_tokens,
)
from chat_text import (
    int_value as _int_value,
)
from chat_text import (
    openai_message_text as _openai_message_text,
)
from event_schema import (
    ROLE_ASSISTANT,
    ROLE_DEVELOPER,
    ROLE_SYSTEM,
    ROLE_USER,
)
from instrlib import Event
from instrlib import judge_capture
from instrlib.tool_mapper import (
    _emit_judge_telemetry,
    append_broad_content_events,
    classify_result_origin,
    is_instruction_like,
    map_tool_call,
    persistence_instruction_label_with_status,
    secret_material_label_with_status,
)

JsonObject = dict[str, Any]


def extract_inbound_events(
    tid: int,
    request: JsonObject,
    api_format: str,
    sid: str,
    rid: str = "",
    provider: str | None = None,
    active_policies: Sequence[str] | None = None,
    include_session_start: bool = False,
    proposing_tool_for_call_id: Mapping[str, str] | None = None,
    trusted_tool_names: Iterable[str] = (),
    blocked_call_ids: Iterable[str] = (),
    origin_for_call_id: Mapping[str, str] | None = None,
) -> list[Event]:
    """Extract Phase-1 events from a chat request before it is forwarded.

    Returns events in the order: ``PolicyActive`` per active policy,
    optional ``Session``, then ``Turn(tid, rid, sid)``, then chat-content
    ``Message`` events (and any inbound ``ToolResult`` / ``Untrusted``
    pairs), then per-turn configuration (``ModelSelection``,
    ``StreamConfig``).

    ``proposing_tool_for_call_id`` and ``trusted_tool_names`` drive the
    ``Untrusted`` emission rule. Each ``ToolResult`` is paired with
    ``Untrusted(tid, "tool_result")`` unless the proposing tool name
    (looked up via ``call_id``) is in the trust allowlist.
    """

    family = _normalise_api_format(api_format)
    provider_label = provider or family
    trusted = frozenset(trusted_tool_names or ())
    tools = dict(proposing_tool_for_call_id or {})
    blocked = frozenset(blocked_call_ids or ())
    origins = dict(origin_for_call_id or {})

    events = _policy_active_events(tid, active_policies)
    if include_session_start:
        events.append(Event("Session", sid))
    events.append(Event("Turn", tid, rid or _default_rid(tid), sid))

    if family == "anthropic":
        events.extend(_inbound_anthropic(tid, request, tools, trusted, blocked, origins))
    elif family == "openai":
        events.extend(_inbound_openai(tid, request, tools, trusted, blocked, origins))
    else:
        raise ValueError(f"Unsupported api_format: {api_format!r}")

    events.extend(_request_config_events(tid, request, provider_label))
    return events


def extract_outbound_events(
    tid: int,
    request: JsonObject,
    response: JsonObject,
    api_format: str,
    active_policies: Sequence[str] | None = None,
) -> list[Event]:
    """Extract Phase-2 events from chat response before it is released.

    Returns ``PolicyActive`` per active policy, followed by  outbound
    events: ``ToolCall`` + ``Classify`` from tool proposals, then a single
    ``Completion`` with the text the model produced.

    ``CompletionReleased`` is emitted by the proxy after the redaction
    handler runs, not here.
    """

    family = _normalise_api_format(api_format)
    events: list[Event] = _policy_active_events(tid, active_policies)

    if family == "anthropic":
        events.extend(_outbound_anthropic(tid, response))
    elif family == "openai":
        events.extend(_outbound_openai_compatible(tid, request, response))
    else:
        raise ValueError(f"Unsupported api_format: {api_format!r}")

    return events

# Helpers


def _default_rid(tid: int) -> str:
    """Synthesise an rid from tid when the client did not supply one."""

    return f"req-{tid}"


def _normalise_api_format(api_format: str) -> str:
    """Map API-shape aliases to one of the two parser families."""

    value = (api_format or "").strip().lower()
    if value in {"anthropic", "anthropic_messages", "messages", "/v1/messages"}:
        return "anthropic"
    if value in {
        "openai",
        "openai_chat",
        "openai_chat_completions",
        "openai_compatible",
        "openai-compatible",
        "chat",
        "chat_completions",
        "chat.completions",
        "/v1/chat/completions",
    }:
        return "openai"
    return value


def _policy_active_events(tid: int, active_policies: Sequence[str] | None) -> list[Event]:
    """Emit one ``PolicyActive`` event per active policy, preserving order."""

    events: list[Event] = []
    seen: set[str] = set()
    for policy_id in active_policies or ():
        pid = str(policy_id or "").strip()
        if not pid or pid in seen:
            continue
        events.append(Event("PolicyActive", tid, pid))
        seen.add(pid)
    return events


def _request_config_events(tid: int, request: JsonObject, provider: str) -> list[Event]:
    """Extract model and stream settings that are common across chat APIs."""

    events: list[Event] = []
    model = request.get("model")
    if model is not None:
        events.append(Event("ModelSelection", tid, provider, str(model)))
    events.append(Event("StreamConfig", tid, 1 if bool(request.get("stream", False)) else 0))
    return events

# Inbound (Phase 1)


def _inbound_anthropic(
    tid: int,
    request: JsonObject,
    proposing_tools: Mapping[str, str],
    trusted_tool_names: frozenset[str],
    blocked_call_ids: frozenset[str] = frozenset(),
    origins: Mapping[str, str] | None = None,
) -> list[Event]:
    """Extract inbound events from Anthropic Messages format."""

    events: list[Event] = []

    system_text = _anthropic_system_text(request.get("system"))
    if system_text:
        events.append(
            Event("Message", tid, ROLE_SYSTEM, system_text, estimate_tokens(system_text))
        )

    messages = _message_list(request.get("messages"))
    last_user_index = _last_index_with_role(messages, "user")

    for index, message in enumerate(messages):
        role = str(message.get("role", ""))
        events.extend(
            _anthropic_tool_result_events(
                tid, message.get("content"), proposing_tools, trusted_tool_names,
                blocked_call_ids, origins,
            )
        )
        text = _anthropic_content_text(message.get("content"))
        if not text:
            continue
        tokens = estimate_tokens(text)
        if role == "user" and index == last_user_index:
            events.append(Event("Message", tid, ROLE_USER, text, tokens))
        elif role == "assistant":
            events.append(Event("Message", tid, ROLE_ASSISTANT, text, tokens))

    return events


def _inbound_openai(
    tid: int,
    request: JsonObject,
    proposing_tools: Mapping[str, str],
    trusted_tool_names: frozenset[str],
    blocked_call_ids: frozenset[str] = frozenset(),
    origins: Mapping[str, str] | None = None,
) -> list[Event]:
    """Extract inbound events from OpenAI chat-completions format."""

    events: list[Event] = []
    messages = _message_list(request.get("messages"))
    last_user_index = _last_index_with_role(messages, "user")

    for index, message in enumerate(messages):
        role = str(message.get("role", ""))
        if role == "tool":
            events.extend(
                _openai_tool_result_events(
                    tid, message, proposing_tools, trusted_tool_names,
                    blocked_call_ids, origins,
                )
            )
        text = _openai_message_text(message)
        if not text:
            continue
        tokens = estimate_tokens(text)

        if role == "system":
            events.append(Event("Message", tid, ROLE_SYSTEM, text, tokens))
        elif role == "developer":
            events.append(Event("Message", tid, ROLE_DEVELOPER, text, tokens))
        elif role == "user" and index == last_user_index:
            events.append(Event("Message", tid, ROLE_USER, text, tokens))
        elif role == "assistant":
            events.append(Event("Message", tid, ROLE_ASSISTANT, text, tokens))

    return events


# Outbound (Phase 2)


def _outbound_anthropic(tid: int, response: JsonObject) -> list[Event]:
    """Extract Phase-2 events from an Anthropic Messages response."""

    events = _anthropic_tool_use_events(tid, response.get("content"))
    text = _anthropic_content_text(response.get("content"))
    usage = response.get("usage") if isinstance(response.get("usage"), dict) else {}
    completion_tokens = _int_value(usage.get("output_tokens")) or estimate_tokens(text)
    events.append(Event("Completion", tid, text, completion_tokens))
    return events


def _outbound_openai_compatible(
    tid: int,
    request: JsonObject,
    response: JsonObject,
) -> list[Event]:
    """Extract Phase-2 events from OpenAI-compatible chat responses."""

    events: list[Event] = []
    choices = response.get("choices")
    completion_texts: list[str] = []
    if isinstance(choices, list) and choices:
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            message = choice.get("message") if isinstance(choice.get("message"), dict) else {}
            events.extend(_openai_tool_call_events(tid, message.get("tool_calls")))
            text = _openai_message_text(message)
            events.append(Event("Completion", tid, text, estimate_tokens(text)))
            completion_texts.append(text)

    combined_text = "\n".join(completion_texts)
    usage = response.get("usage") if isinstance(response.get("usage"), dict) else {}
    completion_tokens = _int_value(usage.get("completion_tokens")) or estimate_tokens(combined_text)

    completion_indexes = [
        index for index, event in enumerate(events) if event.name == "Completion"
    ]
    if len(completion_indexes) == 1:
        # Common case: patch the single Completion with the real token count.
        index = completion_indexes[0]
        events[index] = Event("Completion", tid, events[index].args[1], completion_tokens)
    elif len(completion_indexes) > 1:
        # Multi-choice response (n > 1 in the request): usage.completion_tokens
        # covers the total across all choices. Distribute evenly so each
        # Completion event carries a real count rather than a character estimate.
        per_choice = max(1, completion_tokens // len(completion_indexes))
        for idx in completion_indexes:
            events[idx] = Event("Completion", tid, events[idx].args[1], per_choice)
    elif not completion_indexes:
        events.append(Event("Completion", tid, "", completion_tokens))

    return events

# Tool events


def _anthropic_tool_use_events(tid: int, content: Any) -> list[Event]:
    """Map Anthropic response ``tool_use`` blocks to ToolCall + Classify."""

    events: list[Event] = []
    if not isinstance(content, list):
        return events
    for block in content:
        if not isinstance(block, dict) or block.get("type") != "tool_use":
            continue
        call_id = str(block.get("id") or "")
        tool_name = str(block.get("name") or "")
        events.extend(map_tool_call(tid, call_id, tool_name, _tool_input_object(block.get("input"))))
    return events


def _openai_tool_call_events(tid: int, tool_calls: Any) -> list[Event]:
    """Map OpenAI-compatible assistant ``tool_calls`` to ToolCall + Classify."""

    events: list[Event] = []
    if not isinstance(tool_calls, list):
        return events
    for tool_call in tool_calls:
        if not isinstance(tool_call, dict):
            continue
        call_id = str(tool_call.get("id") or "")
        function = tool_call.get("function")
        if isinstance(function, dict):
            tool_name = str(function.get("name") or "")
            tool_input = _parse_openai_tool_arguments(function.get("arguments"))
        else:
            tool_name = str(tool_call.get("name") or tool_call.get("type") or "")
            tool_input = _tool_input_object(tool_call.get("input"))
        events.extend(map_tool_call(tid, call_id, tool_name, tool_input))
    return events


def _anthropic_tool_result_events(
    tid: int,
    content: Any,
    proposing_tools: Mapping[str, str],
    trusted_tool_names: frozenset[str],
    blocked_call_ids: frozenset[str] = frozenset(),
    origins: Mapping[str, str] | None = None,
) -> list[Event]:
    """Extract Anthropic inbound ``tool_result`` blocks as ToolResult + Untrusted."""

    events: list[Event] = []
    if not isinstance(content, list):
        return events
    for block in content:
        if not isinstance(block, dict) or block.get("type") != "tool_result":
            continue
        call_id = str(block.get("tool_use_id") or block.get("id") or "")
        text = _preview_value(block.get("content"))
        exit_code = 1 if bool(block.get("is_error")) else 0
        events.append(Event("ToolResult", tid, call_id, text, exit_code))
        if call_id and call_id in blocked_call_ids:
            # Denial echo: EnfGuard already blocked this call, so this "result" is
            # the echo of our own block reason. Record ToolResult for the trace but
            # do NOT re-ingest it as untrusted/content-risk content (it would
            # re-arm provenance tiers). Mirrors the /v1/tool_result guard.
            continue
        # Output-safety: tag a tool result that contains plaintext secret material
        # (credential echo, cat 8) regardless of trust.
        with judge_capture.capturing(tid):
            secret_label, secret_judge_status = secret_material_label_with_status(text)
        if secret_label:
            events.append(Event("Classify", tid, call_id, "content_risk", "secret_material"))
        _emit_judge_telemetry(events, tid, call_id, "secret_material", secret_judge_status)
        if _tool_result_is_untrusted(call_id, proposing_tools, trusted_tool_names, origins):
            events.append(Event("Untrusted", tid, "tool_result"))
            # Narrow the indirect-execution signal: tag untrusted content that
            # is addressed to the agent (an injected instruction), so policies
            # block only on instruction-like provenance, not on every result.
            if is_instruction_like(text):
                events.append(Event("Classify", tid, call_id, "content_risk", "instruction_like"))
            # Narrower still: untrusted content instructing persistence (used by
            # the persistence pack's provenance tier). Deterministic-first, with a
            # gated judge for ambiguous weak-signal wording.
            with judge_capture.capturing(tid):
                persistence_label, persistence_judge_status = (
                    persistence_instruction_label_with_status(text)
                )
            if persistence_label:
                events.append(Event("Classify", tid, call_id, "content_risk", "persistence_instruction"))
            _emit_judge_telemetry(
                events, tid, call_id, "persistence_instruction",
                persistence_judge_status,
            )
            # Broad untrusted-content judge (max-coverage): reaches the residue the
            # weak-signal secret/instruction/persistence paths never route.
            _already = bool(
                secret_label or is_instruction_like(text) or persistence_label
            )
            append_broad_content_events(
                events, tid, call_id, text, untrusted=True, already_flagged=_already
            )
    return events


def _openai_tool_result_events(
    tid: int,
    message: JsonObject,
    proposing_tools: Mapping[str, str],
    trusted_tool_names: frozenset[str],
    blocked_call_ids: frozenset[str] = frozenset(),
    origins: Mapping[str, str] | None = None,
) -> list[Event]:
    """Extract an OpenAI-compatible inbound ``role=tool`` result as v4 events.

    OpenAI tool messages have no explicit error field (unlike Anthropic's
    ``is_error``). We infer exit_code from the content via
    ``_infer_openai_exit_code``: common error prefixes (``Error:``,
    ``Traceback``, etc.) → 1; otherwise → 0. This lets MFOTL policies that
    check ``ToolResult(t, _, _, 1)`` fire on obvious OpenAI tool failures
    rather than silently missing them.
    """

    call_id = str(message.get("tool_call_id") or message.get("id") or "")
    text = _preview_value(message.get("content"))
    exit_code = _infer_openai_exit_code(text)
    events: list[Event] = [Event("ToolResult", tid, call_id, text, exit_code)]
    if call_id and call_id in blocked_call_ids:
        # Denial echo for an already-blocked call: record ToolResult only, skip
        # re-ingestion as untrusted/content-risk content (see Anthropic path).
        return events
    with judge_capture.capturing(tid):
        secret_label, secret_judge_status = secret_material_label_with_status(text)
    if secret_label:
        events.append(Event("Classify", tid, call_id, "content_risk", "secret_material"))
    _emit_judge_telemetry(events, tid, call_id, "secret_material", secret_judge_status)
    if _tool_result_is_untrusted(call_id, proposing_tools, trusted_tool_names, origins):
        events.append(Event("Untrusted", tid, "tool_result"))
        if is_instruction_like(text):
            events.append(Event("Classify", tid, call_id, "content_risk", "instruction_like"))
        with judge_capture.capturing(tid):
            persistence_label, persistence_judge_status = (
                persistence_instruction_label_with_status(text)
            )
        if persistence_label:
            events.append(Event("Classify", tid, call_id, "content_risk", "persistence_instruction"))
        _emit_judge_telemetry(
            events, tid, call_id, "persistence_instruction", persistence_judge_status
        )
        _already = bool(
            secret_label or is_instruction_like(text) or persistence_label
        )
        append_broad_content_events(
            events, tid, call_id, text, untrusted=True, already_flagged=_already
        )
    return events


def _infer_openai_exit_code(content: str) -> int:
    """Infer a best-effort exit code from OpenAI tool result content.

    OpenAI's Chat Completions API has no per-tool-result error flag.
    We scan for prefixes that agent frameworks and Python runtimes emit when
    a tool call fails, so policies can match on exit_code without knowing
    which provider produced the result.

    Returns:
        1  — content looks like an error / exception
        0  — content looks like a successful result (default)
    """
    if not content:
        return 0

    lower = content.lstrip().lower()
    error_signals = (
        "error:",
        "exception:",
        "traceback (most recent",   
        "failed:",
        "failure:",
        "valueerror:",
        "typeerror:",
        "runtimeerror:",
        "oserror:",
        "permissionerror:",
        "filenotfounderror:",
        "attributeerror:",
        "keyerror:",
    )
    if any(lower.startswith(signal) for signal in error_signals):
        return 1
    return 0


def _tool_result_is_untrusted(
    call_id: str,
    proposing_tools: Mapping[str, str],
    trusted_tool_names: frozenset[str],
    origins: Mapping[str, str] | None = None,
) -> bool:
    """Decide whether a tool result should be tagged ``Untrusted``.

    Source-based rule (the real threat = bytes that can carry an indirect
    prompt injection):
      * origin ``external`` (network fetch / out-of-workspace read) -> untrusted;
      * origin ``local`` (in-workspace read / local compute) -> trusted;
      * origin ``unknown`` (unrecognised tool, uninspectable input) -> fall back
        to the legacy tool-name allowlist: untrusted unless the proposing tool
        is in ``backend.trusted_tool_names``.

    ``trusted_tool_names`` is therefore no longer the primary discriminator — it
    is the override/fallback for the cases the origin classifier cannot resolve.
    With ``origins`` empty (no per-call origin recorded) the behaviour is exactly
    the legacy allowlist, so callers that do not record origins are unaffected.
    """

    origin = (origins or {}).get(call_id, "unknown") if call_id else "unknown"
    if origin == "external":
        return True
    if origin == "local":
        return False
    proposing_tool = proposing_tools.get(call_id, "") if call_id else ""
    return proposing_tool not in trusted_tool_names


def collect_tool_origins(events: Sequence[Event]) -> dict[str, str]:
    """Return a ``call_id -> origin`` map for every ``ToolCall`` event.

    Mirrors ``collect_proposing_tools`` but records *where the result bytes
    will come from* (external | local | unknown) using the tool name and input
    preview the proxy already extracted, so the per-session origin table backs
    the source-based ``Untrusted`` lookup when the result arrives later.
    """

    mapping: dict[str, str] = {}
    for event in events:
        if event.name != "ToolCall" or len(event.args) < 4:
            continue
        call_id = str(event.args[1])
        tool_name = str(event.args[2])
        input_preview = event.args[3]
        if call_id:
            mapping[call_id] = classify_result_origin(tool_name, input_preview)
    return mapping


def _parse_openai_tool_arguments(arguments: Any) -> JsonObject:
    """Parse OpenAI function-call arguments into the mapper's dict shape."""

    if isinstance(arguments, dict):
        return arguments
    if isinstance(arguments, str):
        try:
            parsed = json.loads(arguments)
        except json.JSONDecodeError:
            return {"arguments": arguments}
        return _tool_input_object(parsed)
    return _tool_input_object(arguments)


def _tool_input_object(value: Any) -> JsonObject:
    """Return a dict for mapper input while preserving non-dict values."""

    if isinstance(value, dict):
        return value
    if value is None:
        return {}
    return {"input": value}


_TOOL_RESULT_CONTENT_LIMIT = 2000


def _preview_value(value: Any, limit: int = _TOOL_RESULT_CONTENT_LIMIT) -> str:
    """Extract and truncate tool-result content for the EnfGuard event stream.

    Converts any provider payload shape (string, Anthropic content list, or
    arbitrary JSON) into a single compact string and trims it to ``limit``
    characters. Whitespace is normalised (collapse runs of whitespace to a
    single space) so the truncation boundary is predictable.
    """

    if isinstance(value, str):
        preview = value
    elif isinstance(value, list):
        preview = _anthropic_content_text(value)
    else:
        try:
            preview = json.dumps(value, ensure_ascii=False)
        except TypeError:
            preview = str(value)
    return " ".join(preview.split())[:limit]


def _message_list(value: Any) -> list[JsonObject]:
    """Return only dict-like chat messages from ``value``."""

    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _last_index_with_role(messages: Sequence[JsonObject], role: str) -> int:
    """Return the last message index with ``role``, or ``-1`` if absent."""

    for index in range(len(messages) - 1, -1, -1):
        if messages[index].get("role") == role:
            return index
    return -1


def collect_proposing_tools(events: Sequence[Event]) -> dict[str, str]:
    """Return a ``call_id -> tool_name`` map for every ``ToolCall`` event.

    Proxy calls this after extracting outbound events for an LLM call,
    so the per-session table that backs the ``Untrusted`` lookup stays in
    sync with the model proposals the proxy has just seen.
    """

    mapping: dict[str, str] = {}
    for event in events:
        if event.name != "ToolCall":
            continue
        # ToolCall args: (tid, call_id, tool_name, input_preview)
        if len(event.args) < 3:
            continue
        call_id = str(event.args[1])
        tool_name = str(event.args[2])
        if call_id:
            mapping[call_id] = tool_name
    return mapping
