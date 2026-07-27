"""Apply EnfGuard verdicts to normalized chat API responses.

Mapper extracts provider-agnostic events from OpenAI-compatible Chat Completions and Anthropic Messages.
Raw provider responses are normalized into one ``NormalizedResponse`` object, enforcement handlers mutate that object, and
serializers patch the original API-shaped response before returning
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any

from chat_text import (
    anthropic_content_text as _anthropic_content_text,
    int_value as _int_value,
    openai_message_text as _openai_message_text,
)

JsonObject = dict[str, Any]
VerdictArgs = list[tuple[Any, ...] | list[Any]]


@dataclass
class NormalizedResponse:
    """API-agnostic representation of one upstream chat response."""

    api_format: str
    content: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    model: str = ""
    finish_reason: str = ""
    reasoning_tokens: int = 0
    refusal: str = ""
    blocked: bool = False
    block_reason: str = ""
    warned: bool = False
    warn_message: str = ""
    block_entries: list[tuple[str, str]] = field(default_factory=list)
    warn_entries: list[tuple[str, str]] = field(default_factory=list)
    raw_response: JsonObject = field(default_factory=dict)


def normalize_anthropic(response: JsonObject) -> NormalizedResponse:
    """Normalize an Anthropic Messages response."""

    usage = response.get("usage") if isinstance(response.get("usage"), dict) else {}
    prompt_tokens = (
        _int_value(usage.get("input_tokens"))
        + _int_value(usage.get("cache_creation_input_tokens"))
        + _int_value(usage.get("cache_read_input_tokens"))
    )
    completion_tokens = _int_value(usage.get("output_tokens"))

    return NormalizedResponse(
        api_format="anthropic",
        content=_anthropic_content_text(response.get("content")),
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=prompt_tokens + completion_tokens,
        model=str(response.get("model", "")),
        finish_reason=_anthropic_finish_reason(response.get("stop_reason")),
        raw_response=deepcopy(response),
    )


def normalize_openai(response: JsonObject) -> NormalizedResponse:
    """Normalize an OpenAI-compatible Chat Completions response."""

    choices = response.get("choices") if isinstance(response.get("choices"), list) else []
    first_choice = choices[0] if choices and isinstance(choices[0], dict) else {}
    first_message = (
        first_choice.get("message") if isinstance(first_choice.get("message"), dict) else {}
    )
    usage = response.get("usage") if isinstance(response.get("usage"), dict) else {}
    completion_details = (
        usage.get("completion_tokens_details")
        if isinstance(usage.get("completion_tokens_details"), dict)
        else {}
    )

    return NormalizedResponse(
        api_format="openai",
        content=_openai_message_text(first_message),
        prompt_tokens=_int_value(usage.get("prompt_tokens")),
        completion_tokens=_int_value(usage.get("completion_tokens")),
        total_tokens=_int_value(usage.get("total_tokens")),
        model=str(response.get("model", "")),
        finish_reason=str(first_choice.get("finish_reason", "") or ""),
        reasoning_tokens=_int_value(completion_details.get("reasoning_tokens")),
        refusal=str(first_message.get("refusal", "") or ""),
        raw_response=deepcopy(response),
    )


def serialize_anthropic(response: NormalizedResponse) -> JsonObject:
    """Serialize a normalized response back to Anthropic Messages format."""

    out = deepcopy(response.raw_response)
    if response.blocked:
        out["content"] = [{"type": "text", "text": response.block_reason}]
        out["stop_reason"] = "end_turn"
        return out

    if response.warned and response.warn_message:
        _prepend_anthropic_text(out, response.warn_message)
    elif response.content != _anthropic_content_text(response.raw_response.get("content")):
        _replace_anthropic_text(out, response.content)
    return out


def serialize_openai(response: NormalizedResponse) -> JsonObject:
    """Serialize a normalized response back to OpenAI-compatible chat format."""

    out = deepcopy(response.raw_response)
    choices = out.get("choices") if isinstance(out.get("choices"), list) else []

    if response.blocked:
        for choice in choices:
            if isinstance(choice, dict):
                _set_openai_choice_text(choice, response.block_reason)
                choice["finish_reason"] = "stop"
        return out

    if response.warned and response.warn_message:
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            message = choice.get("message") if isinstance(choice.get("message"), dict) else {}
            original = _openai_message_text(message)
            _set_openai_choice_text(choice, f"{response.warn_message}\n\n{original}")
    elif choices and response.content != _openai_message_text(
        choices[0].get("message") if isinstance(choices[0], dict) else {}
    ):
        first_choice = choices[0] if isinstance(choices[0], dict) else {}
        _set_openai_choice_text(first_choice, response.content)
    return out


def handle_block_request(
    response: NormalizedResponse,
    args_list: VerdictArgs,
    judge_reasons: dict[str, str] | None = None,
) -> NormalizedResponse:
    """Apply a Phase-1 BlockRequest verdict."""

    text, entries = _format_entries("Blocked", args_list, judge_reasons)
    response.blocked = True
    response.block_entries = entries
    response.block_reason = (
        f"Request blocked.\n{text}" if len(entries) > 1 else f"Request blocked: {text}"
    )
    return response


def handle_warn_request(
    response: NormalizedResponse,
    args_list: VerdictArgs,
    judge_reasons: dict[str, str] | None = None,
) -> NormalizedResponse:
    """Apply a Phase-1 WarnRequest verdict."""

    text, entries = _format_entries("Warned", args_list, judge_reasons)
    response.warned = True
    response.warn_entries = entries
    response.warn_message = (
        f"Input warnings.\n{text}" if len(entries) > 1 else f"Input warning: {text}"
    )
    return response


def handle_block_response(
    response: NormalizedResponse,
    args_list: VerdictArgs,
    judge_reasons: dict[str, str] | None = None,
) -> NormalizedResponse:
    """Apply a Phase-2 BlockResponse verdict."""

    text, entries = _format_entries("Blocked", args_list, judge_reasons)
    response.blocked = True
    response.block_entries = entries
    response.block_reason = (
        f"Response blocked.\n{text}" if len(entries) > 1 else f"Response blocked: {text}"
    )
    response.content = ""
    return response


def handle_warn_response(
    response: NormalizedResponse,
    args_list: VerdictArgs,
    judge_reasons: dict[str, str] | None = None,
) -> NormalizedResponse:
    """Apply a Phase-2 WarnResponse verdict."""

    text, entries = _format_entries("Warned", args_list, judge_reasons)
    response.warned = True
    response.warn_entries = entries
    response.warn_message = (
        f"Policy warnings.\n{text}" if len(entries) > 1 else f"Policy warning: {text}"
    )
    return response


def handle_allow_request(response: NormalizedResponse, args_list: VerdictArgs) -> NormalizedResponse:
    """Return the response unchanged for explicit allow verdicts."""

    return response


def handle_allow_response(response: NormalizedResponse, args_list: VerdictArgs) -> NormalizedResponse:
    """Return the response unchanged for explicit allow verdicts."""

    return response


def merge_warning_message(response: NormalizedResponse, warning_text: str) -> NormalizedResponse:
    """Merge an inbound warning into the eventual outbound response warning."""

    warning = str(warning_text or "").strip()
    if not warning:
        return response
    if response.warned and response.warn_message:
        response.warn_message = f"{warning}\n\n{response.warn_message}"
    else:
        response.warned = True
        response.warn_message = warning
    return response


def surface_warning_on_block(
    response: NormalizedResponse,
    warning_text: str,
) -> NormalizedResponse:
    """Make warning details visible even when a block controls the response."""

    warning = str(warning_text or "").strip()
    if not warning:
        return response

    if response.blocked:
        response.block_reason = f"{response.block_reason}\n\nAlso fired:\n{warning}"
    else:
        response = merge_warning_message(response, warning)
    return response


def synthetic_anthropic(reason: str) -> JsonObject:
    """Build an Anthropic-shaped response for a blocked request."""

    return {
        "id": "msg_enfguard_blocked",
        "type": "message",
        "role": "assistant",
        "model": "enfguard",
        "content": [{"type": "text", "text": reason}],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 0, "output_tokens": 0},
    }


def synthetic_openai(reason: str) -> JsonObject:
    """Build an OpenAI-compatible response for a blocked request."""

    return {
        "id": "chatcmpl-enfguard-blocked",
        "object": "chat.completion",
        "created": 0,
        "model": "enfguard",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": reason},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


_CATEGORY_PREDICATES: dict[str, tuple[str, ...]] = {
    "safety": ("hard_rules",),
    "secrets": ("contains_secrets",),
    "model_policy": ("model_blocklist",),
}


def _format_entries(
    verb: str,
    args_list: VerdictArgs,
    judge_reasons: dict[str, str] | None = None,
) -> tuple[str, list[tuple[str, str]]]:
    entries: list[tuple[str, str]] = []
    for args in args_list or []:
        if len(args) >= 3:
            entries.append((str(args[1]), str(args[2])))
        elif len(args) >= 2:
            entries.append((str(args[1]), ""))
        else:
            entries.append(("general", ""))

    if not entries:
        return f"{verb} by enforcement policy.", entries

    if len(entries) == 1:
        category, reason = entries[0]
        return f"[{category}] {_with_judge_reason(category, reason, judge_reasons)}", entries

    lines = [f"{verb} by {len(entries)} policies:"]
    for category, reason in entries:
        lines.append(f"  - [{category}] {_with_judge_reason(category, reason, judge_reasons)}")
    return "\n".join(lines), entries


def _with_judge_reason(
    category: str,
    reason: str,
    judge_reasons: dict[str, str] | None,
) -> str:
    if not judge_reasons:
        return reason
    best_name = ""
    best_reason = ""
    for name in _CATEGORY_PREDICATES.get(category, ()):
        candidate = judge_reasons.get(name, "")
        if len(candidate) > len(best_reason):
            best_name = name
            best_reason = candidate
    if not best_reason:
        return reason
    return f"{reason}\n    {best_name}: {best_reason}"


def _anthropic_finish_reason(stop_reason: Any) -> str:
    return {
        "end_turn": "stop",
        "max_tokens": "length",
        "stop_sequence": "stop",
        "tool_use": "tool_calls",
    }.get(str(stop_reason or ""), "stop")


def _prepend_anthropic_text(response: JsonObject, warning: str) -> None:
    content = response.setdefault("content", [])
    if not isinstance(content, list):
        response["content"] = [{"type": "text", "text": warning}]
        return
    for block in content:
        if isinstance(block, dict) and block.get("type") == "text":
            block["text"] = f"{warning}\n\n{block.get('text', '')}"
            return
    content.insert(0, {"type": "text", "text": warning})


def _replace_anthropic_text(response: JsonObject, text: str) -> None:
    content = response.setdefault("content", [])
    if not isinstance(content, list):
        response["content"] = [{"type": "text", "text": text}]
        return
    for block in content:
        if isinstance(block, dict) and block.get("type") == "text":
            block["text"] = text
            return
    content.insert(0, {"type": "text", "text": text})


def _set_openai_choice_text(choice: JsonObject, text: str) -> None:
    message = choice.setdefault("message", {})
    if not isinstance(message, dict):
        choice["message"] = {"role": "assistant", "content": text}
        return
    message["content"] = text
    if "refusal" in message:
        message["refusal"] = None
