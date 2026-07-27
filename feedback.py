"""Helper for turning UI feedback submissions into EnfGuard events."""

from __future__ import annotations

from typing import Any

from instrlib import Event


def make_feedback_event(tid: int, kind: str, payload: Any) -> Event:
    """Build the single feedback envelope event declared in ``enfguard_user.sig``."""

    return Event("UserFeedback", int(tid), str(kind or "freeform"), str(payload or ""))
