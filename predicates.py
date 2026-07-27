"""Python predicates callable from EnfGuard.

Write a small request context file before each EnfGuard query, so when enfguard envokes these functions in Python subprocess, reads that
context to stamp trace rows with the current ``tid`` and session id. 
"""

from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import os
import re
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

BASE_DIR = Path(__file__).resolve().parent
STATE_DIR = Path(os.environ.get("ENFGUARD_STATE_DIR", BASE_DIR / "state"))
LOGS_DIR = Path(os.environ.get("ENFGUARD_LOG_DIR", BASE_DIR / "logs"))
TRACE_STORE_FILE = Path(os.environ.get("ENFGUARD_TRACE_STORE", LOGS_DIR / "trace_store.jsonl"))
TRACE_INDEX_DIR = Path(os.environ.get("ENFGUARD_TRACE_INDEX_DIR", LOGS_DIR / "traces"))
CURRENT_CONTEXT_FILE = Path(
    os.environ.get("ENFGUARD_CONTEXT_FILE", STATE_DIR / "current_context.json")
)
# Judge results live in ``<SESSIONS_DIR>/<sid>/judge_cache.jsonl``. Each
# session gets its own file. No global judge cache: every session starts with no cached verdicts so identical
# inputs in two different sessions are judged independently. Operators own the cache for their own session via the override UI.
SESSIONS_DIR = Path(os.environ.get("ENFGUARD_SESSIONS_DIR", STATE_DIR / "sessions"))
PRE_EVAL_RESULTS_FILE = STATE_DIR / "pre_eval_results.jsonl"

STATE_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)
TRACE_INDEX_DIR.mkdir(parents=True, exist_ok=True)
SESSIONS_DIR.mkdir(parents=True, exist_ok=True)


_NO_SESSION = "_no_session"
_SID_SAFE_RE = re.compile(r"[^A-Za-z0-9_.-]")


@dataclass(frozen=True)
class JudgeResult:
    """A parsed judge result plus trace metadata.

    ``is_override`` is set when the entry was written by an operator via
    ``override_judge_cache`` (trace UI's override button). Overrides
    are stored under the same cache key as a normal judge result for
    that session, so a subsequent identical request returns the
    override on a cache hit. The flag lets the trace UI render the row
    differently and lets ``/admin/sessions/<sid>/overrides`` enumerate
    the operator-curated overrides without scanning judge calls.
    """

    raw_score: float
    reason: str
    reasons: tuple[str, ...]
    raw_reply: str = ""
    fail_mode: str = ""
    cache_hit: bool = False
    latency_ms: int = 0
    batch_id: str = ""
    judge_prompt: str = ""
    replayed_pre_eval: bool = False
    is_override: bool = False


@dataclass(frozen=True)
class JudgeBatchTask:
    """One independently-cacheable judge request inside a true batch call."""

    predicate_name: str
    system_prompt: str
    content: str
    cache_extra: tuple[Any, ...] = ()


class _MtimeCache:
    """Tiny mtime cache for JSON/text runtime state files."""

    def __init__(self, path: Path, default: Any, loader) -> None:
        self.path = path
        self.default = default
        self.loader = loader
        self.mtime = -1.0
        self.value = default

    def get(self) -> Any:
        try:
            mtime = self.path.stat().st_mtime
        except FileNotFoundError:
            if self.mtime != -1.0:
                self.mtime = -1.0
                self.value = self.default
            return self.value

        if mtime != self.mtime:
            try:
                self.value = self.loader(self.path)
            except Exception as exc:
                print(f"[predicates] failed to load {self.path}: {exc}", flush=True)
                self.value = self.default
            self.mtime = mtime
        return self.value


class _JudgeCacheFile:
    """Append-only JSONL cache reader with offset tracking and snapshots."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.value: dict[str, Any] = {}
        self.offset = 0
        self.mtime = -1.0
        self.snapshot_id = ""

    def get(self) -> dict[str, Any]:
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            self.value = {}
            self.offset = 0
            self.mtime = -1.0
            return self.value

        snapshot_id = _read_judge_cache_snapshot_id(self.path)
        if snapshot_id != self.snapshot_id or stat.st_size < self.offset:
            self.value = {}
            self.offset = 0
            self.snapshot_id = snapshot_id

        if stat.st_mtime == self.mtime and stat.st_size == self.offset:
            return self.value

        try:
            with self.path.open("r", encoding="utf-8") as handle:
                handle.seek(self.offset)
                for line in handle:
                    item = _parse_judge_cache_line(line)
                    if item is None:
                        continue
                    self.value[item[0]] = item[1]
                self.offset = handle.tell()
        except OSError as exc:
            print(f"[judge_cache] incremental read failed: {exc}", flush=True)
            self.value = _load_judge_cache(self.path)
            try:
                self.offset = self.path.stat().st_size
            except OSError:
                self.offset = 0
        self.mtime = stat.st_mtime
        return self.value

    def refresh_after_snapshot(self) -> None:
        self.value = _load_judge_cache(self.path)
        try:
            stat = self.path.stat()
            self.offset = stat.st_size
            self.mtime = stat.st_mtime
            self.snapshot_id = _read_judge_cache_snapshot_id(self.path)
        except OSError:
            self.offset = 0
            self.mtime = -1.0
            self.snapshot_id = ""


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_judge_cache(path: Path) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        parsed = _parse_judge_cache_line(line)
        if parsed is None:
            continue
        values[parsed[0]] = parsed[1]
    return values


def _read_judge_cache_snapshot_id(path: Path) -> str:
    try:
        with path.open(encoding="utf-8") as handle:
            first = handle.readline()
    except OSError:
        return ""
    try:
        item = json.loads(first)
    except json.JSONDecodeError:
        return ""
    return str(item.get("_snapshot_id", "") or "") if isinstance(item, dict) else ""


def _parse_judge_cache_line(line: str) -> tuple[str, dict[str, Any]] | None:
    try:
        item = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(item, dict):
        return None
    if "_snapshot_id" in item:
        return None
    key = str(item.get("key", "") or "")
    return (key, item) if key else None


_CONTEXT_CACHE = _MtimeCache(
    CURRENT_CONTEXT_FILE,
    {"tid": -1, "sid": "", "phase": "", "dry_run": 0},
    _load_json,
)
_STATE_CACHE = _MtimeCache(
    STATE_DIR / "active_policies.json",
    {
        "active": [],
        "thresholds": {},
        "model_blocklist": [],
        "judge_fail_mode": os.environ.get("JUDGE_FAIL_MODE", "closed"),
        "judge_fail_modes": {},
    },
    _load_json,
)
# Per-session shared (file-backed) caches, lazily created the first
# time a session is touched. Each session has its own file at
# ``SESSIONS_DIR/<sid>/judge_cache.jsonl``. Proxy and EnfGuard
# subprocess Python bridge load this module independently and each
# maintain their own ``_SESSION_FILE_CACHES`` dict: the file is the
# IPC mechanism between them, scoped to one session.
_SESSION_FILE_CACHES: dict[str, _JudgeCacheFile] = {}
_JUDGE_CACHE_SNAPSHOT_BYTES = int(os.environ.get("ENFGUARD_JUDGE_CACHE_SNAPSHOT_BYTES", 1_048_576))

# Per-session in-memory cache. Outer key is the (sanitised) session id,
# inner key is the per-content cache key produced by ``_judge_cache_key``.
# Sessions are isolated from each other: identical content in two
# different sessions is judged twice. New session = empty inner dict =
# fresh judgments. Operators clear a session via
# ``/admin/clear_session/{sid}`` (or ``clear_session_cache(sid)`` from
# Python).
_JUDGE_CACHE: dict[str, dict[str, JudgeResult]] = {}


def _normalize_sid(sid: str) -> str:
    """Sanitise a session id into something safe to use as a directory name.

    Keeps alnum, ``_``, ``-`` and ``.`` characters; everything else is
    replaced with ``_``. Empty / missing sids fall through to the
    synthetic ``_no_session`` bucket so admin tooling and tests still
    have somewhere to read and write.
    """

    cleaned = (sid or "").strip()
    if not cleaned:
        return _NO_SESSION
    safe = _SID_SAFE_RE.sub("_", cleaned)[:128]
    return safe or _NO_SESSION


def _session_cache_path(sid: str) -> Path:
    """Return ``<SESSIONS_DIR>/<safe_sid>/judge_cache.jsonl``."""

    return SESSIONS_DIR / _normalize_sid(sid) / "judge_cache.jsonl"


def _session_file_cache(sid: str) -> _JudgeCacheFile:
    """Return the per-session ``_JudgeCacheFile`` for ``sid``, creating one on demand."""

    safe_sid = _normalize_sid(sid)
    cached = _SESSION_FILE_CACHES.get(safe_sid)
    if cached is None:
        cached = _JudgeCacheFile(SESSIONS_DIR / safe_sid / "judge_cache.jsonl")
        _SESSION_FILE_CACHES[safe_sid] = cached
    return cached


def _session_memory_cache(sid: str) -> dict[str, JudgeResult]:
    """Return the per-session in-memory dict, creating an empty one on demand."""

    return _JUDGE_CACHE.setdefault(_normalize_sid(sid), {})


def clear_session_cache(sid: str) -> dict[str, Any]:
    """Drop all cached results for one session — both memory and disk.

    This is what ``/admin/clear_session/{sid}`` calls. After this runs,
    the next judge call for ``sid`` is a fresh upstream call. Other
    sessions are untouched.
    """

    safe_sid = _normalize_sid(sid)
    _JUDGE_CACHE.pop(safe_sid, None)
    file_cache = _SESSION_FILE_CACHES.pop(safe_sid, None)
    removed_path: Path | None = None
    if file_cache is not None:
        removed_path = file_cache.path
    else:
        removed_path = SESSIONS_DIR / safe_sid / "judge_cache.jsonl"
    try:
        if removed_path.exists():
            removed_path.unlink()
        session_dir = removed_path.parent
        if session_dir.exists() and session_dir != SESSIONS_DIR and not any(session_dir.iterdir()):
            session_dir.rmdir()
    except OSError as exc:
        return {"sid": safe_sid, "ok": False, "error": str(exc)}
    return {"sid": safe_sid, "ok": True, "removed": str(removed_path)}


def clear_all_session_caches() -> dict[str, Any]:
    """Drop every session's cache. Used by ``/admin/clear_judge_cache``."""

    sids: set[str] = set(_JUDGE_CACHE.keys()) | set(_SESSION_FILE_CACHES.keys())
    if SESSIONS_DIR.exists():
        try:
            sids.update(child.name for child in SESSIONS_DIR.iterdir() if child.is_dir())
        except OSError:
            pass
    cleared = [clear_session_cache(sid) for sid in sorted(sids)]
    return {"ok": True, "cleared": cleared}
_USER_FUNCTION_CACHE: dict[tuple[str, str], tuple[float, Any]] = {}
_USER_PREDICATE_SIGNATURES: dict[str, str] = {}
_TRACE_DEDUPE_SEEN: set[tuple[int, str, str]] = set()
_TRACE_DEDUPE_ORDER: list[tuple[int, str, str]] = []
_TRACE_DEDUPE_CAP = 4096


def write_current_context(
    tid: int,
    sid: str = "",
    phase: str = "",
    dry_run: bool = False,
) -> None:
    """Atomically publish request context for the EnfGuard subprocess."""

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "tid": int(tid),
        "sid": str(sid or ""),
        "phase": str(phase or ""),
        "dry_run": 1 if dry_run else 0,
    }
    tmp_path = CURRENT_CONTEXT_FILE.with_suffix(CURRENT_CONTEXT_FILE.suffix + ".tmp")
    tmp_path.write_text(json.dumps(payload), encoding="utf-8")
    os.replace(tmp_path, CURRENT_CONTEXT_FILE)


def _current_context() -> dict[str, Any]:
    value = _CONTEXT_CACHE.get()
    return value if isinstance(value, dict) else {"tid": -1, "sid": "", "phase": "", "dry_run": 0}


def _current_tid() -> int:
    try:
        return int(_current_context().get("tid", -1))
    except (TypeError, ValueError):
        return -1


def _current_sid() -> str:
    return str(_current_context().get("sid", "") or "")


def _current_phase() -> str:
    return str(_current_context().get("phase", "") or "")


def _state() -> dict[str, Any]:
    value = _STATE_CACHE.get()
    return value if isinstance(value, dict) else {}


def _threshold(predicate_name: str) -> float:
    thresholds = _state().get("thresholds")
    if not isinstance(thresholds, dict):
        return 0.5
    try:
        value = float(thresholds.get(predicate_name, 0.5))
    except (TypeError, ValueError):
        return 0.5
    return min(1.0, max(0.0, value))


def _judge_fail_mode(predicate_name: str) -> str:
    state = _state()
    per_pred = state.get("judge_fail_modes")
    value = None
    if isinstance(per_pred, dict):
        value = per_pred.get(predicate_name)
    value = value or state.get("judge_fail_mode") or os.environ.get("JUDGE_FAIL_MODE", "closed")
    mode = str(value or "closed").strip().lower()
    return mode if mode in {"open", "closed", "warn"} else "closed"


def _predicate_enabled(predicate_name: str) -> bool:
    """Return false when every policy that references this predicate is inactive."""

    state = _state()
    raw_index = state.get("predicate_policies")
    if not isinstance(raw_index, dict):
        return True
    policy_ids = raw_index.get(predicate_name)
    if not isinstance(policy_ids, list) or not policy_ids:
        return True
    active = state.get("active")
    if not isinstance(active, list):
        return True
    return bool(set(str(item) for item in policy_ids) & set(str(item) for item in active))


def _trace_emit(
    predicate: str,
    content: str,
    result: JudgeResult,
    threshold: float,
    score: float,
    extra: dict[str, Any] | None = None,
) -> None:
    """Append one deduplicated predicate result row to the per-tid trace index."""

    tid = _current_tid()
    digest = hashlib.blake2b((content or "").encode("utf-8"), digest_size=12).hexdigest()
    key = (tid, _current_sid(), _current_phase(), predicate, digest)
    if key in _TRACE_DEDUPE_SEEN:
        return
    _TRACE_DEDUPE_SEEN.add(key)
    _TRACE_DEDUPE_ORDER.append(key)
    if len(_TRACE_DEDUPE_ORDER) > _TRACE_DEDUPE_CAP:
        old = _TRACE_DEDUPE_ORDER.pop(0)
        _TRACE_DEDUPE_SEEN.discard(old)

    content_preview = _trace_content_preview(content)
    entry: dict[str, Any] = {
        "ts_wall": time.time(),
        "tid_hint": tid,
        "sid": _current_sid(),
        "phase": _current_phase(),
        "predicate": predicate,
        "content_preview": content_preview,
        "raw_score": round(float(result.raw_score), 4),
        "threshold": round(float(threshold), 4),
        "score": round(float(score), 4),
        "reason": result.reason,
        "reasons": list(result.reasons),
        "judge_raw_reply": result.raw_reply,
        "judge_cache_hit": result.cache_hit,
        "fail_mode": result.fail_mode,
        # Forensic fields the trace UI needs to render a useful timeline.
        # `latency_ms` is the wall-clock cost of the upstream judge call (0
        # for cache hits). `batch_id` ties together rows that share a single
        # batch upstream call. `judge_prompt` is the system prompt that
        # produced this score.
        "latency_ms": int(getattr(result, "latency_ms", 0) or 0),
        "batch_id": str(getattr(result, "batch_id", "") or ""),
        "judge_prompt": str(getattr(result, "judge_prompt", "") or ""),
    }
    if extra:
        entry.update(extra)

    try:
        _write_trace_index_row(tid, entry)
    except OSError as exc:
        print(f"[trace_store] write failed: {exc}", flush=True)


def _write_trace_index_row(tid: int, entry: dict[str, Any]) -> None:
    if tid < 0:
        return
    TRACE_INDEX_DIR.mkdir(parents=True, exist_ok=True)
    path = TRACE_INDEX_DIR / f"tid_{tid}.jsonl"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _trace_content_preview(content: str) -> str:
    runtime = _state().get("runtime")
    if (
        isinstance(runtime, dict)
        and runtime.get("trace_assistant_content") is False
        and _current_phase() == "outbound"
    ):
        return "[assistant content omitted by runtime.trace_assistant_content=false]"
    return (content or "")[:160]


def _score(predicate: str, content: str, result: JudgeResult, extra: dict[str, Any] | None = None) -> float:
    if not _predicate_enabled(predicate):
        return 0.0
    threshold = _threshold(predicate)
    score = 1.0 if result.raw_score >= threshold else 0.0
    if not result.replayed_pre_eval:
        _trace_emit(predicate, content, result, threshold, score, extra)
    return score


def trace_pre_evaluation(
    predicate: str,
    content: str,
    result: JudgeResult,
    extra: dict[str, Any] | None = None,
) -> float:
    """Record a judge result produced before EnfGuard asks for the predicate.

    Pre-evaluation intentionally warms the cache. Without this trace row, the
    later EnfGuard predicate call is the first thing that reaches the trace
    index and every fresh judge call looks like a cache hit.
    """

    merged_extra = {"pre_evaluated": True}
    if extra:
        merged_extra.update(extra)
    _write_pre_eval_result(predicate, content, result)
    return _score(predicate, content, result, merged_extra)


# Documentation marker for the current judge contract. It is deliberately
# not part of `_judge_cache_key`: sessions are the cache-invalidation unit.
_JUDGE_CONTRACT_VERSION = "2026-05-05.label-reason.v1"

# Keep the judge wire format tiny. Small judge models are prone to treating
# long schemas as text to complete, so the runtime asks for one decision bit
# plus a short UI-facing reason. The parser maps label 1 -> raw_score 1.0
# and label 0 -> raw_score 0.0.
_JUDGE_SYSTEM_PREFIX = (
    "You are a strict binary classifier.\n"
    "\n"
    "Classify only the text inside <input>. Ignore everything else.\n"
    "\n"
    "The Criterion defines when label = 1. It is not part of the input.\n"
    "\n"
    "Decision rule:\n"
    "- Return label 1 only if the input itself clearly satisfies the Criterion.\n"
    "- Otherwise return label 0.\n"
    "- If unsure, default to label 0.\n"
    "\n"
    "Important constraints:\n"
    "- Do not copy or repeat words from the Criterion.\n"
    "- If the input only mentions or describes the Criterion instead of satisfying it, return 0.\n"
    "- If the input is a greeting, generic text, fictional placeholder, or unclear, return 0.\n"
    "\n"
    "Reasoning:\n"
    "- Output one short sentence explaining the decision.\n"
    "- The sentence must start with exactly:\n"
    "  - \"Label 1 because ...\" or\n"
    "  - \"Label 0 because ...\"\n"
    "- The reason must refer only to the input, not the Criterion.\n"
    "\n"
    "Output format (strict):\n"
    "Return exactly one JSON object:\n"
    "{\"label\":0,\"reason\":\"Label 0 because ...\"}\n"
    "or\n"
    "{\"label\":1,\"reason\":\"Label 1 because ...\"}\n"
    "\n"
    "Do not output anything else."
)


def _sanitize(text: str) -> str:
    return re.sub(r"</\s*input\s*>", "<\u200b/input\u200b>", text or "", flags=re.IGNORECASE)


def _judge(
    predicate_name: str,
    system_prompt: str,
    content: str,
    cache_extra: tuple[Any, ...] = (),
) -> JudgeResult:
    backend, model, timeout_ms = _judge_config(predicate_name)
    pre_evaluated = _pre_evaluated_judge_result(predicate_name, content)
    if pre_evaluated is not None:
        return pre_evaluated
    sid = _current_sid()
    # Distinguish cached entries by backend+model so changing the YAML's
    # per-predicate backend invalidates stale entries automatically.
    config_signature = (backend, model, timeout_ms)
    cache_key = _judge_cache_key(predicate_name, content, cache_extra + config_signature)
    cached = _cached_judge_result(cache_key, sid)
    if cached is not None:
        return cached

    started_at = time.monotonic()
    try:
        parsed = _call_and_parse_judge_api(
            system_prompt,
            content,
            backend=backend,
            model=model,
            timeout_ms=timeout_ms,
        )
    except Exception as exc:
        # Do NOT cache failures (in-memory or shared). A single transient
        # timeout/network error must not poison the cache forever — the
        # next request should retry. `result.fail_mode` is non-empty exactly
        # when the result came from `_failed_judge_result`.
        latency_ms = int((time.monotonic() - started_at) * 1000)
        return _failed_judge_result(predicate_name, exc, latency_ms=latency_ms)

    latency_ms = int((time.monotonic() - started_at) * 1000)
    result = JudgeResult(
        raw_score=parsed.raw_score,
        reason=parsed.reason,
        reasons=parsed.reasons,
        raw_reply=parsed.raw_reply,
        fail_mode=parsed.fail_mode,
        cache_hit=parsed.cache_hit,
        latency_ms=latency_ms,
        batch_id="",
        judge_prompt=system_prompt,
    )
    _session_memory_cache(sid)[cache_key] = result
    _write_shared_judge_result(cache_key, predicate_name, content, result, sid)
    return result


def _cached_judge_result(cache_key: str, sid: str) -> JudgeResult | None:
    """Look up ``cache_key`` in the per-session cache for ``sid``.

    Checks the session's in-memory dict first, falls back to the
    session's on-disk file. Other sessions' caches are never consulted.
    """

    safe_sid = _normalize_sid(sid)
    memory = _JUDGE_CACHE.get(safe_sid, {})
    cached = memory.get(cache_key)
    if cached is not None:
        return _cache_hit_result(cached)

    shared_cached = _shared_judge_result(cache_key, sid)
    if shared_cached is not None:
        _session_memory_cache(safe_sid)[cache_key] = shared_cached
        return _cache_hit_result(shared_cached)
    return None


def _cache_hit_result(result: JudgeResult) -> JudgeResult:
    return JudgeResult(
        raw_score=result.raw_score,
        reason=result.reason,
        reasons=result.reasons,
        raw_reply=result.raw_reply,
        fail_mode=result.fail_mode,
        cache_hit=True,
        latency_ms=0,
        batch_id=result.batch_id,
        judge_prompt=result.judge_prompt,
        is_override=result.is_override,
    )


def _write_pre_eval_result(
    predicate_name: str,
    content: str,
    result: JudgeResult,
) -> None:
    tid = _current_tid()
    if tid < 0:
        return
    entry = {
        "tid": tid,
        "sid": _current_sid(),
        "phase": _current_phase(),
        "predicate": predicate_name,
        "content": content,
        "raw_score": result.raw_score,
        "reason": result.reason,
        "reasons": list(result.reasons),
        "raw_reply": result.raw_reply,
        "fail_mode": result.fail_mode,
        "cache_hit": result.cache_hit,
        "latency_ms": result.latency_ms,
        "batch_id": result.batch_id,
        "judge_prompt": result.judge_prompt,
    }
    try:
        PRE_EVAL_RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with PRE_EVAL_RESULTS_FILE.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError as exc:
        print(f"[pre_eval_results] write failed: {exc}", flush=True)


def _pre_evaluated_judge_result(predicate_name: str, content: str) -> JudgeResult | None:
    """Return this turn's pre-evaluated score for monitor-side predicate calls.

    The EnfGuard Python-function bridge can corrupt non-ASCII string arguments
    before they reach this process. The proxy already judged the correct event
    text immediately before querying EnfGuard, so the monitor-side function can
    replay that score for the current tid/phase/predicate. Exact content
    matches are preferred; a single unambiguous predicate result is used as a
    fallback for corrupted non-ASCII arguments.
    """

    tid = _current_tid()
    sid = _current_sid()
    phase = _current_phase()
    if tid < 0 or not phase:
        return None
    matches: list[dict[str, Any]] = []
    try:
        with PRE_EVAL_RESULTS_FILE.open("r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if (
                    isinstance(entry, dict)
                    and entry.get("tid") == tid
                    and str(entry.get("sid", "") or "") == sid
                    and entry.get("phase") == phase
                    and entry.get("predicate") == predicate_name
                ):
                    matches.append(entry)
    except FileNotFoundError:
        return None
    except OSError as exc:
        print(f"[pre_eval_results] read failed: {exc}", flush=True)
        return None

    if not matches:
        return None
    exact = [entry for entry in matches if entry.get("content") == content]
    if exact:
        return _pre_eval_entry_to_result(exact[-1])
    if len(matches) == 1:
        return _pre_eval_entry_to_result(matches[0])
    return None


def _pre_eval_entry_to_result(entry: dict[str, Any]) -> JudgeResult:
    reasons = entry.get("reasons")
    return JudgeResult(
        raw_score=_clamp_float(entry.get("raw_score", 0.0)),
        reason=str(entry.get("reason", "") or ""),
        reasons=tuple(str(item) for item in reasons if str(item)) if isinstance(reasons, list) else (),
        raw_reply=str(entry.get("raw_reply", "") or ""),
        fail_mode=str(entry.get("fail_mode", "") or ""),
        cache_hit=bool(entry.get("cache_hit", False)),
        latency_ms=0,
        batch_id=str(entry.get("batch_id", "") or ""),
        judge_prompt=str(entry.get("judge_prompt", "") or ""),
        replayed_pre_eval=True,
    )


def judge_plan(predicate_name: str, content: str) -> tuple[str, tuple[Any, ...]] | None:
    """Return the LLM judge prompt/cache metadata needed for early evaluation."""

    if predicate_name == "contains_secrets":
        if any(pattern.search(content or "") for pattern, _ in _SECRET_PATTERNS):
            return None
        return _SECRETS_PROMPT, ()

    for spec in _user_predicate_specs():
        if spec.get("name") != predicate_name or spec.get("kind") != "llm_judge":
            continue
        arg_specs = _predicate_arg_specs(spec)
        system_prompt = str(spec.get("system_prompt", "") or "")
        return system_prompt, (system_prompt, _arg_signature(arg_specs))

    return None


def pre_evaluate_judge(
    predicate_name: str,
    system_prompt: str,
    content: str,
    cache_extra: tuple[Any, ...] = (),
) -> JudgeResult:
    """Run a judge early and publish the result for the EnfGuard subprocess.

    `_judge` already writes to the shared cache on every successful API call
    and on every cache hit it loads the result back; we used to call
    `_write_shared_judge_result` again here, which doubled every line in
    `judge_cache.jsonl`. The redundant write has been removed.
    """

    return _judge(predicate_name, system_prompt, content, cache_extra)


def pre_evaluate_judges(
    tasks: list[JudgeBatchTask],
    *,
    call_mode: str = "batched",
) -> list[JudgeResult]:
    """Run judge tasks for cache misses, dispatching per the call mode.

    ``call_mode`` is either ``"batched"`` (one upstream call carrying
    every task in a backend/model group — current default) or
    ``"parallel"`` (N concurrent single-task calls, dispatched via a
    thread pool). Each task keeps its normal cache key, so EnfGuard's
    subprocess sees the same cache entries either way.
    """

    results: list[JudgeResult | None] = [None] * len(tasks)
    misses: list[tuple[int, JudgeBatchTask, str, tuple[str, str, int]]] = []
    sid = _current_sid()
    for index, task in enumerate(tasks):
        config = _judge_config(task.predicate_name)
        config_signature = (config[0], config[1], config[2])
        cache_key = _judge_cache_key(
            task.predicate_name, task.content, task.cache_extra + config_signature
        )
        cached = _cached_judge_result(cache_key, sid)
        if cached is not None:
            results[index] = cached
        else:
            misses.append((index, task, cache_key, config))

    if misses:
        if call_mode == "parallel":
            _dispatch_parallel(misses, results)
        else:
            _dispatch_batched(misses, results)

    return [
        result if result is not None else _failed_judge_result("", RuntimeError("missing judge result"))
        for result in results
    ]


def _dispatch_batched(
    misses: list[tuple[int, JudgeBatchTask, str, tuple[str, str, int]]],
    results: list[JudgeResult | None],
) -> None:
    """Group misses by (backend, model, timeout_ms) and send one call per group."""

    groups: dict[tuple[str, str, int, str], list[tuple[int, JudgeBatchTask, str]]] = {}
    for index, task, cache_key, config in misses:
        backend, model, timeout_ms = config
        # Do not pack unrelated rubrics into one LLM call. The previous
        # mixed-criterion batch prompt was fast on paper but could cross-talk
        # badly: a negative rubric phrase from one task became a positive
        # score for another. Same-rubric batching preserves correctness and
        # still lets repeated uses of one predicate share a dispatch.
        groups.setdefault((backend, model, timeout_ms, task.system_prompt), []).append(
            (index, task, cache_key)
        )

    for (backend, model, timeout_ms, _system_prompt), group in groups.items():
        if len(group) == 1:
            index, task, _ = group[0]
            results[index] = _judge(
                task.predicate_name,
                task.system_prompt,
                task.content,
                task.cache_extra,
            )
            continue

        batch_id = uuid.uuid4().hex[:12]
        started_at = time.monotonic()
        try:
            raw_reply = _call_batch_judge_api(
                [task for _, task, _ in group],
                backend=backend,
                model=model,
                timeout_ms=timeout_ms,
            )
            parsed = _parse_batch_judge_reply(
                raw_reply,
                [task for _, task, _ in group],
            )
        except Exception as exc:
            print(f"[judge_batch] batch failed, falling back to singles: {exc}", flush=True)
            for index, task, _ in group:
                results[index] = _judge(
                    task.predicate_name,
                    task.system_prompt,
                    task.content,
                    task.cache_extra,
                )
            continue

        latency_ms = int((time.monotonic() - started_at) * 1000)
        for batch_index, (index, task, cache_key) in enumerate(group):
            parsed_result = parsed.get(batch_index)
            if parsed_result is None:
                results[index] = _judge(
                    task.predicate_name,
                    task.system_prompt,
                    task.content,
                    task.cache_extra,
                )
                continue
            result = JudgeResult(
                raw_score=parsed_result.raw_score,
                reason=parsed_result.reason,
                reasons=parsed_result.reasons,
                raw_reply=parsed_result.raw_reply,
                fail_mode=parsed_result.fail_mode,
                cache_hit=parsed_result.cache_hit,
                latency_ms=latency_ms,
                batch_id=batch_id,
                judge_prompt=task.system_prompt,
            )
            results[index] = result
            if not result.fail_mode:
                task_sid = _current_sid()
                _session_memory_cache(task_sid)[cache_key] = result
                _write_shared_judge_result(
                    cache_key, task.predicate_name, task.content, result, task_sid
                )


def _dispatch_parallel(
    misses: list[tuple[int, JudgeBatchTask, str, tuple[str, str, int]]],
    results: list[JudgeResult | None],
) -> None:
    """Run every miss as its own single-task ``_judge`` call concurrently.

    We're already inside ``asyncio.to_thread`` from the proxy, so spawning
    a small ``ThreadPoolExecutor`` is the safest way to fan out without
    juggling event-loop context. Each task keeps its own cache key and
    its own batch_id (single-task batches), and the JudgeResult shape is
    the same as the batched path.
    """

    from concurrent.futures import ThreadPoolExecutor

    if not misses:
        return

    dispatch_id = f"parallel-{uuid.uuid4().hex[:12]}"

    def _run_one(entry: tuple[int, JudgeBatchTask, str]) -> tuple[int, JudgeResult]:
        index, task, _cache_key = entry
        result = _judge(
            task.predicate_name,
            task.system_prompt,
            task.content,
            task.cache_extra,
        )
        return index, JudgeResult(
            raw_score=result.raw_score,
            reason=result.reason,
            reasons=result.reasons,
            raw_reply=result.raw_reply,
            fail_mode=result.fail_mode,
            cache_hit=result.cache_hit,
            latency_ms=result.latency_ms,
            batch_id=dispatch_id,
            judge_prompt=result.judge_prompt or task.system_prompt,
        )

    items = [(index, task, cache_key) for index, task, cache_key, _ in misses]
    # Cap the worker count so we don't fan out to thousands of concurrent
    # connections; the real workload is a handful of judges per phase.
    max_workers = min(len(items), 8) or 1
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        for index, result in pool.map(_run_one, items):
            results[index] = result


def _judge_cache_key(predicate_name: str, content: str, cache_extra: tuple[Any, ...]) -> str:
    """Compute the per-content cache key used inside one session.

    The key intentionally does NOT include the session id — partitioning
    by session is done at the storage layer (per-sid in-memory dict and
    per-sid file). It also does NOT include ``_JUDGE_CONTRACT_VERSION``:
    sessions are the unit of cache invalidation, so a contract bump is
    naturally absorbed by new sessions starting fresh, while existing
    sessions keep whatever the operator already saw and curated. The
    constant is preserved as a documentation marker but no longer
    affects routing.
    """

    payload = [predicate_name, content, _jsonable(cache_extra)]
    return hashlib.blake2b(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        ),
        digest_size=24,
    ).hexdigest()


def _jsonable(value: Any) -> Any:
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in sorted(value.items())}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _shared_judge_result(cache_key: str, sid: str) -> JudgeResult | None:
    """Look up ``cache_key`` inside ``sid``'s on-disk judge cache.

    Reads only from ``<SESSIONS_DIR>/<safe_sid>/judge_cache.jsonl`` —
    other sessions' files are never consulted.
    """

    file_cache = _session_file_cache(sid)
    cache = file_cache.get()
    if not isinstance(cache, dict):
        return None
    entry = cache.get(cache_key)
    if not isinstance(entry, dict):
        return None
    reasons = entry.get("reasons")
    raw_reply = str(entry.get("raw_reply", "") or "")
    fail_mode = str(entry.get("fail_mode", "") or "")
    batch_id = str(entry.get("batch_id", "") or "")
    judge_prompt = str(entry.get("judge_prompt", "") or "")
    content_preview = str(entry.get("content_preview", "") or "")
    is_override = bool(entry.get("is_override", False)) or str(
        entry.get("source", "") or ""
    ) == "override"
    result = JudgeResult(
        raw_score=_clamp_float(entry.get("raw_score", 0.0)),
        reason=str(entry.get("reason", "") or ""),
        reasons=tuple(str(item) for item in reasons if str(item)) if isinstance(reasons, list) else (),
        raw_reply=raw_reply,
        fail_mode=fail_mode,
        # Preserve forensic fields across the on-disk shared cache so the
        # trace UI can show the original judge_prompt / batch_id even on a
        # cache hit. latency_ms is intentionally not preserved — a cache hit
        # has no upstream cost so it should render as 0 ms.
        batch_id=batch_id,
        judge_prompt=judge_prompt,
        is_override=is_override,
    )
    # Override entries are authoritative: do not re-parse the raw_reply,
    # since override raw_reply is a synthesised JSON whose fields are
    # the override payload, not a real judge call.
    if is_override:
        return result
    if raw_reply and not fail_mode:
        try:
            parsed = _parse_judge_reply(
                raw_reply,
                content=content_preview,
                criterion=judge_prompt,
            )
            return JudgeResult(
                raw_score=parsed.raw_score,
                reason=parsed.reason,
                reasons=parsed.reasons,
                raw_reply=raw_reply,
                fail_mode=fail_mode,
                batch_id=batch_id,
                judge_prompt=judge_prompt,
            )
        except Exception:
            return result
    return result


def _write_shared_judge_result(
    cache_key: str,
    predicate_name: str,
    content: str,
    result: JudgeResult,
    sid: str,
) -> None:
    """Append a judge result row to ``sid``'s on-disk cache file.

    The path is ``<SESSIONS_DIR>/<safe_sid>/judge_cache.jsonl``. Other
    sessions are not touched. Override rows carry ``is_override: true``
    and ``source: "override"`` so the trace UI can render them
    differently and the parser bypasses raw_reply re-parsing on cache
    hits (override raw_reply is synthesised, not a real judge call).
    """

    entry = {
        "key": cache_key,
        "ts_wall": time.time(),
        "sid": _normalize_sid(sid),
        "predicate": predicate_name,
        "content_preview": _trace_content_preview(content),
        "raw_score": result.raw_score,
        "reason": result.reason,
        "reasons": list(result.reasons),
        "raw_reply": result.raw_reply,
        # Forensic fields preserved across restarts so the trace UI keeps
        # showing the originating batch and prompt on subsequent cache hits.
        "batch_id": getattr(result, "batch_id", "") or "",
        "judge_prompt": getattr(result, "judge_prompt", "") or "",
        "fail_mode": result.fail_mode,
        "is_override": bool(getattr(result, "is_override", False)),
    }
    if entry["is_override"]:
        entry["source"] = "override"
    file_cache = _session_file_cache(sid)
    try:
        file_cache.path.parent.mkdir(parents=True, exist_ok=True)
        with file_cache.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        _maybe_snapshot_session_cache(file_cache.path)
    except OSError as exc:
        print(f"[judge_cache] write failed for sid={entry['sid']}: {exc}", flush=True)


def override_judge_cache(
    predicate_name: str,
    content: str,
    raw_score: float,
    reason: str,
    sid: str | None = None,
) -> dict[str, Any]:
    """Write an operator override into ``sid``'s judge cache.

    The override applies only to the specified session — other sessions
    are not affected. If ``sid`` is omitted we read it from the current
    request context, which is what the proxy's ``/admin/judge_override``
    handler relies on. The override entry is marked with
    ``is_override=True`` so the trace UI can render it distinctly and
    the lookup path knows to bypass raw_reply re-parsing.
    """

    if not sid:
        sid = _current_sid()
    plan = judge_plan(predicate_name, content)
    system_prompt = plan[0] if plan is not None else ""
    cache_extra = plan[1] if plan is not None else ()
    backend, model, timeout_ms = _judge_config(predicate_name)
    config_signature = (backend, model, timeout_ms)
    cache_key = _judge_cache_key(predicate_name, content, cache_extra + config_signature)
    score = max(0.0, min(1.0, float(raw_score)))
    override_reason = reason or "judge override"
    result = JudgeResult(
        raw_score=score,
        reason=override_reason,
        reasons=(override_reason,),
        raw_reply=json.dumps(
            {"score": score, "reason": override_reason, "reasons": [override_reason]},
            ensure_ascii=False,
        ),
        fail_mode="",
        cache_hit=False,
        latency_ms=0,
        batch_id="",
        judge_prompt=system_prompt,
        is_override=True,
    )
    safe_sid = _normalize_sid(sid)
    _session_memory_cache(safe_sid)[cache_key] = result
    _write_shared_judge_result(cache_key, predicate_name, content, result, sid)
    file_cache = _session_file_cache(sid)
    try:
        file_cache.refresh_after_snapshot()
    except Exception:
        pass
    return {
        "predicate": predicate_name,
        "sid": safe_sid,
        "raw_score": score,
        "reason": override_reason,
        "cache_key": cache_key,
        "content_preview": _trace_content_preview(content),
        "is_override": True,
    }


def _maybe_snapshot_session_cache(path: Path) -> None:
    """Compact one session's cache file in place once it crosses the size threshold."""

    if _JUDGE_CACHE_SNAPSHOT_BYTES <= 0:
        return
    try:
        if not path.exists() or path.stat().st_size < _JUDGE_CACHE_SNAPSHOT_BYTES:
            return
        values = _load_judge_cache(path)
        tmp_path = path.with_suffix(path.suffix + ".tmp")
        with tmp_path.open("w", encoding="utf-8") as handle:
            handle.write(json.dumps({"_snapshot_id": uuid.uuid4().hex}, ensure_ascii=False) + "\n")
            for entry in values.values():
                handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        os.replace(tmp_path, path)
        # Refresh whichever in-memory file_cache wraps this path.
        for cached in _SESSION_FILE_CACHES.values():
            if cached.path == path:
                cached.refresh_after_snapshot()
                break
    except OSError as exc:
        print(f"[judge_cache] snapshot failed for {path}: {exc}", flush=True)


def _judge_config(predicate_name: str) -> tuple[str, str, int]:
    """Resolve ``(backend, model, timeout_ms)`` for ``predicate_name``.

    Per-predicate YAML overrides win; falls back to global ``JUDGE_*``
    environment variables (which the proxy populates from
    ``backend.judge_*`` in ``enfguard.yaml``). The resolved tuple is what
    the judge HTTP code actually uses for this call, and it also feeds
    into the batch grouping key so requests with different backends never
    end up in the same upstream call.
    """

    spec = next(
        (spec for spec in _user_predicate_specs() if spec.get("name") == predicate_name),
        {},
    )
    backend = (str(spec.get("backend", "")) or os.environ.get("JUDGE_BACKEND", "ollama")).strip().lower()
    if backend not in {"openai", "ollama", "anthropic"}:
        backend = "ollama"
    model = str(spec.get("model", "")) or _default_judge_model(backend)
    try:
        timeout_ms = int(spec.get("timeout_ms") or 0)
    except (TypeError, ValueError):
        timeout_ms = 0
    if timeout_ms <= 0:
        timeout_ms = _int_from_env("JUDGE_TIMEOUT_MS", 2500)
    return backend, model, timeout_ms


def _default_judge_model(backend: str) -> str:
    if backend == "openai":
        return os.environ.get("JUDGE_OPENAI_MODEL", "gpt-4o-mini")
    if backend == "ollama":
        return os.environ.get("JUDGE_OLLAMA_MODEL", "qwen2.5:0.5b")
    if backend == "anthropic":
        return os.environ.get("JUDGE_ANTHROPIC_MODEL", "claude-3-5-haiku-latest")
    return ""


def _call_judge_api(
    system_prompt: str,
    content: str,
    *,
    backend: str,
    model: str,
    timeout_ms: int,
    json_response: bool = True,
    repair_hint: str = "",
) -> str:
    """Single-task judge HTTP call dispatched by ``backend``."""

    timeout_s = max(timeout_ms, 1) / 1000
    repair = ""
    if repair_hint:
        repair = (
            "\n\n<repair>\n"
            "Previous reply was rejected because it did not satisfy the runtime output contract: "
            f"{_sanitize(repair_hint)[:600]}. "
            "Re-read <input> and return exactly one valid JSON object with keys label and reason.\n"
            "</repair>"
        )
    user_msg = (
        f"Criterion:\n<criterion>\n{_sanitize(system_prompt)[:4000]}\n</criterion>\n\n"
        f"<input>\n{_sanitize(content)[:4000]}\n</input>"
        f"{repair}"
    )
    return _dispatch_judge(
        system_prompt=_judge_system_prompt(),
        user_msg=user_msg,
        backend=backend,
        model=model,
        timeout_s=timeout_s,
        max_output_tokens=120,
        json_response=json_response,
    )


def _call_and_parse_judge_api(
    system_prompt: str,
    content: str,
    *,
    backend: str,
    model: str,
    timeout_ms: int,
) -> JudgeResult:
    """Call one judge and retry once when only the reply format is invalid."""

    raw_reply = _call_judge_api(
        system_prompt,
        content,
        backend=backend,
        model=model,
        timeout_ms=timeout_ms,
    )
    try:
        return _parse_judge_reply(raw_reply, content=content, criterion=system_prompt)
    except (json.JSONDecodeError, ValueError) as exc:
        repaired_reply = _call_judge_api(
            system_prompt,
            content,
            backend=backend,
            model=model,
            timeout_ms=timeout_ms,
            repair_hint=str(exc),
        )
        repaired = _parse_judge_reply(repaired_reply, content=content, criterion=system_prompt)
        repair_reason = "judge_format_repaired_after_retry"
        reasons = tuple([*repaired.reasons, repair_reason])
        return JudgeResult(
            raw_score=repaired.raw_score,
            reason="; ".join(reasons),
            reasons=reasons,
            raw_reply=repaired.raw_reply,
            fail_mode=repaired.fail_mode,
            cache_hit=repaired.cache_hit,
            latency_ms=repaired.latency_ms,
            batch_id=repaired.batch_id,
            judge_prompt=repaired.judge_prompt,
            replayed_pre_eval=repaired.replayed_pre_eval,
        )


def _judge_system_prompt(system_prompt: str = "") -> str:
    del system_prompt
    return _JUDGE_SYSTEM_PREFIX


def _call_batch_judge_api(
    tasks: list[JudgeBatchTask],
    *,
    backend: str,
    model: str,
    timeout_ms: int,
) -> str:
    """Multi-task judge HTTP call sharing one upstream backend."""

    timeout_s = max(timeout_ms, 1) / 1000
    user_msg = json.dumps(
        {
            "contract": (
                "Return ONLY valid JSON with a results array. Evaluate "
                "each task independently. For each task, assign label 1 "
                "only if that task's input clearly matches that task's "
                "criterion; otherwise assign label 0. The reason must be "
                "one short sentence explaining that decision and must start "
                "with Label 0 because or Label 1 because, matching the label."
            ),
            "required_result_keys": ["id", "label", "reason"],
            "no_match_fields": {
                "label": 0,
                "reason": "Label 0 because one short sentence explains why label 0 was chosen",
            },
            "match_fields": {
                "label": 1,
                "reason": "Label 1 because one short sentence explains why label 1 was chosen",
            },
            "tasks": [
                {
                    "id": index,
                    "predicate": task.predicate_name,
                    "criterion": _sanitize(task.system_prompt)[:4000],
                    "input": _sanitize(task.content)[:4000],
                }
                for index, task in enumerate(tasks)
            ],
        },
        ensure_ascii=False,
    )
    system_prompt = (
        "You are a simple batch binary classifier. Evaluate every task "
        "independently and return exactly one result object per id. A "
        "task's criterion defines label 1; it does not describe the "
        "task input. Label 1 only for a clear match. Label 0 for "
        "unrelated text, uncertainty, or criterion-word echo. Reasons "
        "must explain decisions based on task inputs, not copy criteria, "
        "and must begin with Label 0 because or Label 1 because."
    )
    return _dispatch_judge(
        system_prompt=system_prompt,
        user_msg=user_msg,
        backend=backend,
        model=model,
        timeout_s=timeout_s,
        max_output_tokens=420,
        json_response=True,
    )


def _dispatch_judge(
    *,
    system_prompt: str,
    user_msg: str,
    backend: str,
    model: str,
    timeout_s: float,
    max_output_tokens: int,
    json_response: bool,
) -> str:
    """Make one HTTP request to whichever judge backend was selected."""

    if backend == "ollama":
        return _call_ollama_judge(system_prompt, user_msg, model, timeout_s, max_output_tokens)
    if backend == "anthropic":
        return _call_anthropic_judge(system_prompt, user_msg, model, timeout_s, max_output_tokens)
    return _call_openai_judge(
        system_prompt, user_msg, model, timeout_s, max_output_tokens, json_response
    )


def _call_ollama_judge(
    system_prompt: str, user_msg: str, model: str, timeout_s: float, max_output_tokens: int
) -> str:
    base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
    with httpx.Client(timeout=timeout_s) as client:
        response = client.post(
            f"{base_url}/api/chat",
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_msg},
                ],
                "stream": False,
                "format": "json",
                "options": {"temperature": 0, "num_predict": max_output_tokens},
            },
        )
        response.raise_for_status()
        payload = response.json()
    message = payload.get("message") if isinstance(payload, dict) else {}
    return str(message.get("content", "") if isinstance(message, dict) else "").strip()


def _call_openai_judge(
    system_prompt: str,
    user_msg: str,
    model: str,
    timeout_s: float,
    max_output_tokens: int,
    json_response: bool,
) -> str:
    base_url = (
        os.environ.get("JUDGE_OPENAI_BASE_URL")
        or os.environ.get("ENFGUARD_TOOL_JUDGE_OPENAI_BASE_URL")
        or os.environ.get("OPENAI_BASE_URL")
        or "https://api.openai.com"
    ).rstrip("/")
    headers = {"content-type": "application/json"}
    api_key = (
        os.environ.get("JUDGE_OPENAI_API_KEY")
        or os.environ.get("ENFGUARD_TOOL_JUDGE_OPENAI_API_KEY")
        or os.environ.get("OPENAI_API_KEY", "")
    )
    if api_key:
        headers["authorization"] = f"Bearer {api_key}"
    body: dict[str, Any] = {
        "model": model,
        "temperature": 0,
        "max_tokens": max_output_tokens,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_msg},
        ],
    }
    if json_response:
        body["response_format"] = {"type": "json_object"}
    with httpx.Client(timeout=timeout_s) as client:
        url = (
            f"{base_url}/chat/completions"
            if base_url.endswith("/v1")
            else f"{base_url}/v1/chat/completions"
        )
        response = client.post(url, headers=headers, json=body)
        response.raise_for_status()
        payload = response.json()
    choices = payload.get("choices") if isinstance(payload, dict) else []
    first = choices[0] if choices and isinstance(choices[0], dict) else {}
    message = first.get("message") if isinstance(first.get("message"), dict) else {}
    return str(message.get("content", "") or "").strip()


def _call_anthropic_judge(
    system_prompt: str, user_msg: str, model: str, timeout_s: float, max_output_tokens: int
) -> str:
    """Call Anthropic Messages and return the assistant's text content.

    Anthropic uses ``system`` as a top-level field (not a message role),
    and the response shape is ``content: [{type: text, text: "..."}]``,
    so the wire format diverges from OpenAI's despite both serving JSON.
    """

    base_url = os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com").rstrip("/")
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    headers = {
        "content-type": "application/json",
        "anthropic-version": os.environ.get("ANTHROPIC_VERSION", "2023-06-01"),
    }
    if api_key:
        headers["x-api-key"] = api_key
    body = {
        "model": model,
        "max_tokens": max_output_tokens,
        "temperature": 0,
        "system": system_prompt,
        "messages": [{"role": "user", "content": user_msg}],
    }
    with httpx.Client(timeout=timeout_s) as client:
        response = client.post(f"{base_url}/v1/messages", headers=headers, json=body)
        response.raise_for_status()
        payload = response.json()
    blocks = payload.get("content") if isinstance(payload, dict) else None
    if isinstance(blocks, list):
        for block in blocks:
            if isinstance(block, dict) and block.get("type") == "text":
                return str(block.get("text", "") or "").strip()
    return ""


def _parse_judge_reply(raw_reply: str, *, content: str = "", criterion: str = "") -> JudgeResult:
    text = raw_reply.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.IGNORECASE).strip()
    obj = json.loads(text)
    if not isinstance(obj, dict):
        raise ValueError("judge reply was not a JSON object")
    return _parse_judge_object(obj, raw_reply, strict=True, content=content, criterion=criterion)


def _parse_judge_object(
    obj: dict[str, Any],
    raw_reply: str,
    *,
    strict: bool = False,
    content: str = "",
    criterion: str = "",
) -> JudgeResult:
    """Parse a judge JSON object into a JudgeResult.

    We deliberately keep this parser narrow: it enforces the JSON shape
    (label, or legacy score, is present and parseable). For the current
    label/reason contract, it also treats a mismatched or missing
    ``Label N because`` reason prefix as a wire-format failure, not as a
    semantic judgment. That catches replies like ``{"label":1,
    "reason":"The text is a greeting..."}``, where the fields disagree.
    ``content`` and ``criterion`` are accepted by the signature so
    call-sites can be uniform; they are unused here today.
    """

    del content, criterion  # kept in the signature for caller uniformity
    if "label" in obj:
        raw_score = _parse_label(obj.get("label"), strict=strict)
        default_reason = f"judge_label_{int(raw_score)}"
    else:
        if strict and "score" not in obj:
            raise ValueError("judge result omitted label")
        raw_score = _parse_score(obj.get("score", 0.0), strict=strict)
        default_reason = f"judge_score_{raw_score:g}"
    reasons = _reason_list(obj)
    if strict and "label" in obj:
        _validate_label_reason_contract(raw_score, reasons)
    reason = "; ".join(reasons) if reasons else default_reason
    return JudgeResult(raw_score=raw_score, reason=reason, reasons=tuple(reasons), raw_reply=raw_reply)


def _parse_batch_judge_reply(raw_reply: str, contexts: list[JudgeBatchTask] | list[str] | int) -> dict[int, JudgeResult]:
    if isinstance(contexts, int):
        expected_count = contexts
        content_by_index: list[str] = [""] * expected_count
        criterion_by_index: list[str] = [""] * expected_count
    elif contexts and isinstance(contexts[0], JudgeBatchTask):
        tasks = [item for item in contexts if isinstance(item, JudgeBatchTask)]
        content_by_index = [task.content for task in tasks]
        criterion_by_index = [task.system_prompt for task in tasks]
        expected_count = len(tasks)
    else:
        content_by_index = [str(item) for item in contexts]
        criterion_by_index = [""] * len(content_by_index)
        expected_count = len(content_by_index)
    text = raw_reply.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.IGNORECASE).strip()
    obj = json.loads(text)
    if not isinstance(obj, dict):
        raise ValueError("batch judge reply was not a JSON object")
    raw_results = obj.get("results")
    if not isinstance(raw_results, list):
        raise ValueError("batch judge reply did not contain a results array")

    parsed: dict[int, JudgeResult] = {}
    for fallback_index, item in enumerate(raw_results):
        if not isinstance(item, dict):
            continue
        try:
            result_id = int(item.get("id", fallback_index))
        except (TypeError, ValueError):
            result_id = fallback_index
        if result_id < 0 or result_id >= expected_count:
            continue
        try:
            parsed[result_id] = _parse_judge_object(
                item,
                raw_reply,
                strict=True,
                content=content_by_index[result_id],
                criterion=criterion_by_index[result_id],
            )
        except ValueError:
            continue
    return parsed


def _parse_score(value: Any, *, strict: bool = False) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        if strict:
            raise ValueError(f"invalid judge score: {value!r}") from exc
        return 0.0
    return min(1.0, max(0.0, number))


def _parse_label(value: Any, *, strict: bool = False) -> float:
    if isinstance(value, bool):
        label = int(value)
    elif isinstance(value, (int, float)):
        label = int(value)
    elif isinstance(value, str) and value.strip() in {"0", "1"}:
        label = int(value.strip())
    else:
        if strict:
            raise ValueError(f"invalid judge label: {value!r}")
        return 0.0
    if label not in {0, 1}:
        if strict:
            raise ValueError(f"invalid judge label: {value!r}")
        return 0.0
    return float(label)


_REASON_LABEL_RE = re.compile(r"^\s*label\s+([01])\s+because\b", re.IGNORECASE)


def _validate_label_reason_contract(raw_score: float, reasons: list[str]) -> None:
    expected = int(raw_score)
    if not reasons:
        raise ValueError(
            f"judge result omitted reason; reason must start with 'Label {expected} because'"
        )
    match = _REASON_LABEL_RE.match(reasons[0])
    if not match:
        raise ValueError(
            "judge reason must start with 'Label 0 because' or 'Label 1 because', "
            "matching the label"
        )
    reason_label = int(match.group(1))
    if reason_label != expected:
        raise ValueError(
            f"judge label/reason mismatch: label={expected} but reason starts "
            f"with Label {reason_label} because"
        )


def _reason_list(obj: dict[str, Any]) -> list[str]:
    raw_reasons = obj.get("reasons")
    reasons: list[str] = []
    if isinstance(raw_reasons, list):
        reasons.extend(str(item).strip() for item in raw_reasons if str(item).strip())
    reason = str(obj.get("reason", "") or "").strip()
    if reason and reason not in reasons:
        reasons.insert(0, reason)
    return reasons


def _failed_judge_result(
    predicate_name: str,
    exc: Exception,
    latency_ms: int = 0,
    batch_id: str = "",
) -> JudgeResult:
    mode = _judge_fail_mode(predicate_name)
    raw_score = 0.0 if mode == "open" else 1.0
    reason = f"judge_unavailable: {type(exc).__name__}: {exc}"
    return JudgeResult(
        raw_score=raw_score,
        reason=reason,
        reasons=(reason,),
        fail_mode=mode,
        latency_ms=latency_ms,
        batch_id=batch_id,
    )


def _clamp_float(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return min(1.0, max(0.0, number))


def _int_from_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


_HARD_RULE_KEYWORDS = (
    "ignore previous instructions",
    "ignore all previous",
    "ignore the above",
    "forget all previous",
    "forget previous instructions",
    "disregard previous",
    "override the system prompt",
    "bypass the system prompt",
    "developer mode activated",
    "jailbreak",
)

_SECRET_PATTERNS = (
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), "openai_key_prefix"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "aws_access_key"),
    (re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "github_pat"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{70,}\b"), "github_fine_grained_pat"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "slack_token"),
    (re.compile(r"-----BEGIN (?:RSA|OPENSSH|PGP|EC) PRIVATE KEY-----"), "private_key"),
    (re.compile(r"\b(?:Bearer|bearer)\s+[A-Za-z0-9_.-]{20,}\b"), "bearer_token"),
    (re.compile(r"\b756\.\d{4}\.\d{4}\.\d{2}\b"), "swiss_ahv"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "us_ssn_like"),
)

_SECRETS_PROMPT = (
    "You are a secret and credential detector. Score high only if the input "
    "contains credentials, private keys, tokens, passwords, government IDs, "
    "financial identifiers, or similarly sensitive secrets."
)


def hard_rules(content: str) -> float:
    """Detect hard safety violations and obvious prompt injection locally."""

    if not _predicate_enabled("hard_rules"):
        return 0.0
    lower = (content or "").lower()
    hits = [keyword for keyword in _HARD_RULE_KEYWORDS if keyword in lower]
    if hits:
        result = JudgeResult(
            raw_score=1.0,
            reason=f"keyword_match: {hits[0]}",
            reasons=(f"keyword_match: {hits[0]}",),
        )
        return _score("hard_rules", content, result, {"keyword_hits": hits})

    result = JudgeResult(
        raw_score=0.0,
        reason="no hard-rule keyword match",
        reasons=("no hard-rule keyword match",),
    )
    return _score("hard_rules", content, result)


def contains_secrets(content: str) -> float:
    """Detect secrets using regex fast paths plus an LLM fallback."""

    if not _predicate_enabled("contains_secrets"):
        return 0.0
    hits = [name for pattern, name in _SECRET_PATTERNS if pattern.search(content or "")]
    if hits:
        reason = f"regex_match: {', '.join(hits)}"
        result = JudgeResult(raw_score=1.0, reason=reason, reasons=(reason,))
        return _score("contains_secrets", content, result, {"regex_hits": hits})
    return _score("contains_secrets", content, _judge("contains_secrets", _SECRETS_PROMPT, content))


def model_blocklist(model: str) -> float:
    """Return 1.0 when the selected model appears in the runtime blocklist."""

    if not _predicate_enabled("model_blocklist"):
        return 0.0
    blocklist = _state().get("model_blocklist") or []
    model_text = str(model or "")
    matched = any(str(item) and str(item) in model_text for item in blocklist)
    return 1.0 if matched else 0.0


def wall_ms_within(now_ms: int, then_ms: int, threshold_ms: int) -> float:
    """Return 1.0 when ``now_ms - then_ms`` is within ``threshold_ms``.

    Companion predicate to the ``ClockTick(tid, wall_ms)`` event. Lets
    MFOTL policies express wall-clock intervals without depending on
    arithmetic comparison support inside the EnfGuard formula language:
    """

    try:
        delta = int(now_ms) - int(then_ms)
    except (TypeError, ValueError):
        return 0.0
    try:
        threshold = int(threshold_ms)
    except (TypeError, ValueError):
        return 0.0
    if delta < 0:
        delta = 0
    return 1.0 if delta <= threshold else 0.0


def _install_user_predicates() -> None:
    """Expose YAML-declared predicates as Python functions for EnfGuard."""

    specs = _user_predicate_specs()
    current_names = {str(spec.get("name", "") or "") for spec in specs}
    for name in list(_USER_PREDICATE_SIGNATURES):
        if name not in current_names:
            globals().pop(name, None)
            _USER_PREDICATE_SIGNATURES.pop(name, None)

    for spec in specs:
        name = str(spec.get("name", "") or "")
        kind = str(spec.get("kind", "") or "")
        if not name:
            continue
        signature = json.dumps(spec, sort_keys=True, default=str)
        if _USER_PREDICATE_SIGNATURES.get(name) == signature and name in globals():
            continue
        if kind == "llm_judge":
            globals()[name] = _make_user_llm_judge(spec)
        elif kind == "python":
            globals()[name] = _make_user_python_predicate(spec)
        _USER_PREDICATE_SIGNATURES[name] = signature


def _user_predicate_specs() -> list[dict[str, Any]]:
    specs = _state().get("user_predicates")
    return [item for item in specs if isinstance(item, dict)] if isinstance(specs, list) else []


def __getattr__(name: str):
    """Create hot-reloaded YAML predicate wrappers on demand."""

    _install_user_predicates()
    value = globals().get(name)
    if value is not None:
        return value
    raise AttributeError(name)


def _make_user_llm_judge(spec: dict[str, Any]):
    name = str(spec.get("name", "") or "")
    system_prompt = str(spec.get("system_prompt", "") or "")
    arg_specs = _predicate_arg_specs(spec)

    def predicate(*args: Any) -> float:
        content = _format_predicate_args(arg_specs, args)
        if not _predicate_enabled(name):
            return 0.0
        result = _judge(name, system_prompt, content, (system_prompt, _arg_signature(arg_specs)))
        return _score(name, content, result, {"user_predicate_kind": "llm_judge"})

    predicate.__name__ = name
    return predicate


def _make_user_python_predicate(spec: dict[str, Any]):
    name = str(spec.get("name", "") or "")
    path = str(spec.get("path", "") or "")
    arg_specs = _predicate_arg_specs(spec)

    def predicate(*args: Any) -> float:
        content = _format_predicate_args(arg_specs, args)
        if not _predicate_enabled(name):
            return 0.0
        try:
            fn = _load_user_function(path, name)
            raw_score = _clamp_float(_call_user_function(fn, args))
            reason = f"python predicate returned {raw_score:g}"
            result = JudgeResult(raw_score=raw_score, reason=reason, reasons=(reason,))
        except Exception as exc:
            result = _failed_predicate_result(name, exc, "python_predicate_error")
        return _score(name, content, result, {"user_predicate_kind": "python", "path": path})

    predicate.__name__ = name
    return predicate


def _predicate_arg_specs(spec: dict[str, Any]) -> tuple[dict[str, str], ...]:
    args = spec.get("args")
    if not isinstance(args, list) or not args:
        return ({"name": "content", "type": "string"},)
    out: list[dict[str, str]] = []
    for item in args:
        if not isinstance(item, dict):
            continue
        out.append(
            {
                "name": str(item.get("name", "arg") or "arg"),
                "type": str(item.get("type", "string") or "string"),
            }
        )
    return tuple(out) or ({"name": "content", "type": "string"},)


def _format_predicate_args(arg_specs: tuple[dict[str, str], ...], values: tuple[Any, ...]) -> str:
    if len(arg_specs) == 1:
        return str(values[0] if values else "")
    lines: list[str] = []
    for index, spec in enumerate(arg_specs):
        value = values[index] if index < len(values) else ""
        lines.append(f"{spec['name']}: {value}")
    return "\n".join(lines)


def _arg_signature(arg_specs: tuple[dict[str, str], ...]) -> tuple[tuple[str, str], ...]:
    return tuple((spec["name"], spec["type"]) for spec in arg_specs)


def _load_user_function(path: str, name: str):
    file_path = Path(path)
    mtime = file_path.stat().st_mtime
    key = (str(file_path), name)
    cached = _USER_FUNCTION_CACHE.get(key)
    if cached is not None and cached[0] == mtime:
        return cached[1]

    digest = hashlib.blake2b(str(file_path).encode("utf-8"), digest_size=8).hexdigest()
    module_name = f"enfguard_user_predicate_{digest}"
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not import predicate module {file_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fn = getattr(module, name)
    if not callable(fn):
        raise TypeError(f"{name} in {file_path} is not callable")
    _USER_FUNCTION_CACHE[key] = (mtime, fn)
    return fn


def _call_user_function(fn, args: tuple[Any, ...]) -> Any:
    signature = inspect.signature(fn)
    if any(param.kind == inspect.Parameter.VAR_POSITIONAL for param in signature.parameters.values()):
        return fn(*args)
    positional = [
        param
        for param in signature.parameters.values()
        if param.kind in {inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD}
    ]
    return fn(*args[: len(positional)])


def _failed_predicate_result(predicate_name: str, exc: Exception, prefix: str) -> JudgeResult:
    mode = _judge_fail_mode(predicate_name)
    raw_score = 0.0 if mode == "open" else 1.0
    reason = f"{prefix}: {type(exc).__name__}: {exc}"
    return JudgeResult(
        raw_score=raw_score,
        reason=reason,
        reasons=(reason,),
        fail_mode=mode,
    )


_install_user_predicates()
