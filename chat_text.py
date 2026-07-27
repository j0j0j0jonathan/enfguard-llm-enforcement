"""Shared text-extraction helpers for chat API payloads.
``mappings.py`` extracts request/response text into MFOTL events,
``handlers.py`` reads it for normalization/serialization, and ``proxy.py``
estimates token counts for released completions (only for Ollama, model doesnt give tokwn counts). 
"""

from __future__ import annotations

from typing import Any

JsonObject = dict[str, Any]


def estimate_tokens(text: str) -> int:
    """Estimate tokens for fields where providers do not give a count."""

    if not text:
        return 0
    return max(1, len(text) // 4)


def int_value(value: Any) -> int:
    """Coerce provider counters to non-negative integers."""

    try:
        number = int(value)
    except (TypeError, ValueError):
        return 0
    return max(0, number)


def anthropic_content_text(content: Any) -> str:
    """Extract visible text from an Anthropic content value."""

    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return str(content)

    parts: list[str] = []
    for block in content:
        if not isinstance(block, dict):
            continue
        block_type = block.get("type")
        if block_type == "text":
            parts.append(str(block.get("text", "")))
        elif block_type == "search_result":
            parts.append(anthropic_content_text(block.get("content")))
        elif block_type == "document":
            parts.append(anthropic_document_text(block))
        elif block_type == "tool_result":
            parts.append(anthropic_content_text(block.get("content")))
        elif "text" in block and isinstance(block.get("text"), str):
            parts.append(str(block.get("text", "")))
    return "\n".join(part for part in parts if part)


def anthropic_document_text(block: JsonObject) -> str:
    """Extract plain text from an Anthropic document block when present."""

    source = block.get("source")
    if not isinstance(source, dict):
        return ""
    source_type = source.get("type")
    if source_type == "text":
        return str(source.get("data", ""))
    if source_type == "content":
        return anthropic_content_text(source.get("content"))
    return ""


def anthropic_system_text(system: Any) -> str:
    """Extract text from Anthropic's top-level ``system`` field."""

    if system is None:
        return ""
    if isinstance(system, str):
        return system
    if isinstance(system, list):
        return anthropic_content_text(system)
    return str(system)


def openai_content_text(content: Any) -> str:
    """Extract visible text from an OpenAI content value."""

    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return str(content)

    parts: list[str] = []
    for part in content:
        if not isinstance(part, dict):
            continue
        part_type = part.get("type")
        if part_type in {"text", "input_text", "output_text"}:
            parts.append(str(part.get("text", "")))
        elif part_type == "refusal":
            parts.append(str(part.get("refusal", "")))
        elif "text" in part and isinstance(part.get("text"), str):
            parts.append(str(part.get("text", "")))
    return "\n".join(part for part in parts if part)


def openai_message_text(message: Any) -> str:
    """Extract visible text from an OpenAI chat message object."""

    if not isinstance(message, dict):
        return ""
    parts = [openai_content_text(message.get("content"))]
    refusal = message.get("refusal")
    if isinstance(refusal, str) and refusal not in parts:
        parts.append(refusal)
    audio = message.get("audio")
    if isinstance(audio, dict) and isinstance(audio.get("transcript"), str):
        transcript = str(audio.get("transcript", ""))
        if transcript not in parts:
            parts.append(transcript)
    return "\n".join(part for part in parts if part)
