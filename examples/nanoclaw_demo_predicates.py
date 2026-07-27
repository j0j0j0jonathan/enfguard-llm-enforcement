"""Deterministic helpers for the NanoClaw three-point demo."""

from __future__ import annotations

import re

_EMOJI_RE = re.compile(
    "["
    "\U0001F1E6-\U0001F1FF"
    "\U0001F300-\U0001F5FF"
    "\U0001F600-\U0001F64F"
    "\U0001F680-\U0001F6FF"
    "\U0001F700-\U0001F77F"
    "\U0001F780-\U0001F7FF"
    "\U0001F800-\U0001F8FF"
    "\U0001F900-\U0001F9FF"
    "\U0001FA70-\U0001FAFF"
    "\u2600-\u27BF"
    "]"
)


def contains_emoji(content):
    text = str(content or "")
    # The OCaml trace path can surface UTF-8 emoji as mojibake such as
    # "ð" or as control-like fragments. Keep the demo predicate robust
    # to those representations too.
    has_mangled_utf8 = "ð" in text or any(
        (ord(ch) < 32 and ch not in "\n\r\t") or 0x80 <= ord(ch) <= 0x9F
        for ch in text
    )
    return 1.0 if _EMOJI_RE.search(text) or has_mangled_utf8 else 0.0


def writes_approval_demo_folder(path):
    normalized = str(path or "").replace("\\", "/").strip()
    if normalized == "approval-demo" or normalized.startswith("approval-demo/"):
        return 1.0
    return 1.0 if "/workspace/group/approval-demo/" in normalized else 0.0
