"""Per-tid capture of ingest-judge calls (added 2026-06-17).

The classify-first architecture runs several gated, fail-safe LLM ingest judges
(``instrlib/tool_judge.py``: unknown-tool, uncertain-action, url-risk,
package-name, webshell, persistence-instruction, secret-material). Until now a
judges-on run recorded only ``judge_status=called|no_match|...`` telemetry, not
WHAT the judge was asked or WHAT it answered. That made it impossible to tell a
prompt-took-effect from a model-limitation when a judge returned ``no_match``
(the central open question for the hybrid claim, see
``docs/handover/2026-06-16-handover.md`` section 7 item 3).

This module is the missing capture. It is a leaf (stdlib only) so both
``tool_mapper`` and ``mappings`` can mark the active ``tid`` around the work that
may invoke a judge, and ``tool_judge`` can append one record per actual model
call. The proxy pops the per-tid list into the session record next to
``classifier_ms``; ``run_eval`` lifts it into ``observed.judge_calls``.

Design mirrors ``tool_mapper._CLASSIFIER_NS``:

  * Per-tid accumulator keyed by ``tid``; ``pop_judge_calls(tid)`` reads and
    resets, so summing across a case's turns is exact and nothing leaks into the
    next case.
  * The active ``tid`` is held in a ``ContextVar`` set by ``capturing(tid)``
    (a context manager). When no tid context is active (e.g. a unit test that
    calls a judge adapter directly), ``record`` is a silent no-op, so capture is
    naturally gated to real proxy runs without a separate enable flag.
  * ``record`` never raises into the judge path (fail-safe), matching the
    fail-open contract of the judges themselves.

A captured record is::

    {
      "adapter":     "unknown_tool",       # which ingest judge ran
      "prompt_sha8": "a1b2c3d4",           # sha1[:8] of the system prompt that ran
      "input":       "tool_name: ...",     # the user message sent to the model
      "reply":       "{\"dim\": ...}",     # the raw model reply (or "")
      "cache_hit":   false,                # ingest judges are uncached today
      "ms":          12.3,                 # wall time of the model call
      "error":       "..."                 # present only if the call raised
    }
"""

from __future__ import annotations

import contextlib
import contextvars
import hashlib
from typing import Dict, List, Optional

# Active tid for the current logical unit of work. ``None`` means "not capturing".
_CURRENT_TID: contextvars.ContextVar[Optional[int]] = contextvars.ContextVar(
    "enfguard_judge_capture_tid", default=None
)

# Per-tid list of captured judge-call records. Popped (and cleared) by the proxy
# when it writes the session record, mirroring ``tool_mapper._CLASSIFIER_NS``.
_JUDGE_CALLS: Dict[int, List[dict]] = {}


def set_tid(tid: Optional[int]):
    """Set the active capture tid; returns a token to pass to ``reset_tid``."""
    return _CURRENT_TID.set(tid)


def reset_tid(token) -> None:
    """Restore the capture tid to its previous value."""
    try:
        _CURRENT_TID.reset(token)
    except Exception:  # pragma: no cover - defensive
        pass


@contextlib.contextmanager
def capturing(tid: Optional[int]):
    """Mark ``tid`` as the active capture target for the enclosed block.

    Any ingest judge that runs inside the block has its model call recorded
    under ``tid``. Always restores the previous tid on exit.
    """
    token = _CURRENT_TID.set(tid)
    try:
        yield
    finally:
        try:
            _CURRENT_TID.reset(token)
        except Exception:  # pragma: no cover - defensive
            pass


def _prompt_sha8(system: str) -> str:
    try:
        return hashlib.sha1((system or "").encode("utf-8")).hexdigest()[:8]
    except Exception:  # pragma: no cover - defensive
        return ""


def record(
    adapter: str,
    system: str,
    user_input: str,
    reply: str,
    *,
    cache_hit: bool = False,
    ms: float = 0.0,
    error: Optional[str] = None,
) -> None:
    """Append one ingest-judge call record under the active tid.

    No-op when no tid context is active (so direct unit-test calls to a judge
    adapter are not captured). Never raises.
    """
    try:
        tid = _CURRENT_TID.get()
        if tid is None:
            return
        rec = {
            "adapter": adapter,
            "prompt_sha8": _prompt_sha8(system),
            "input": user_input,
            "reply": reply,
            "cache_hit": bool(cache_hit),
            "ms": round(float(ms), 4),
        }
        if error:
            rec["error"] = error
        _JUDGE_CALLS.setdefault(int(tid), []).append(rec)
    except Exception:  # pragma: no cover - defensive
        return


def pop_judge_calls(tid: int) -> List[dict]:
    """Return and clear the captured judge-call records for this tid."""
    return _JUDGE_CALLS.pop(tid, [])
