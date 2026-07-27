#!/usr/bin/env python3
"""Wipe runtime caches so testing starts from a clean slate.

Run with the proxy stopped:

    python scripts/clear_runtime_cache.py

Removes:
- state/judge_cache.jsonl                — legacy global judge cache (kept for
                                            historical layouts; current builds
                                            shard caches per session)
- state/sessions/<sid>/judge_cache.jsonl — per-session judge result caches
                                            (and the empty session dirs left
                                            behind after deletion)
- state/pre_eval_results.jsonl           — proxy-side pre-eval replay file the
                                            EnfGuard subprocess reads to skip
                                            already-judged predicates
- logs/traces/                           — per-tid trace index files
- logs/trace_store.jsonl                 — legacy trace log
- logs/session_*.jsonl / .tokens         — per-session records and token totals
- logs/feedback.jsonl                    — operator feedback log (judge
                                            overrides, freeform notes)

Leaves alone: enfguard.yaml, bench/*.yaml, state/active_policies.json
(regenerated at startup), state/live_policies.json (operator-curated
overlays), state/enfguard_composite.{sig,mfotl,*.map.json}, predicates.py,
signatures.

Pass --dry-run to print what would be deleted without removing anything.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _candidate_paths(base: Path) -> list[Path]:
    state = base / "state"
    logs = base / "logs"
    paths: list[Path] = []
    if (state / "judge_cache.jsonl").exists():
        paths.append(state / "judge_cache.jsonl")
    if (state / "pre_eval_results.jsonl").exists():
        paths.append(state / "pre_eval_results.jsonl")
    sessions = state / "sessions"
    if sessions.exists() and sessions.is_dir():
        for child in sorted(sessions.iterdir()):
            if not child.is_dir():
                continue
            cache = child / "judge_cache.jsonl"
            if cache.exists():
                paths.append(cache)
    traces = logs / "traces"
    if traces.exists() and traces.is_dir():
        paths.extend(sorted(traces.glob("tid_*.jsonl")))
    if (logs / "trace_store.jsonl").exists():
        paths.append(logs / "trace_store.jsonl")
    if (logs / "feedback.jsonl").exists():
        paths.append(logs / "feedback.jsonl")
    if logs.exists():
        paths.extend(sorted(logs.glob("session_*.jsonl")))
        paths.extend(sorted(logs.glob("session_*.tokens")))
    return paths


def _prune_empty_session_dirs(base: Path, dry_run: bool) -> int:
    """Drop empty per-session dirs left behind after their cache was unlinked."""

    sessions = base / "state" / "sessions"
    if not sessions.exists() or not sessions.is_dir():
        return 0
    pruned = 0
    for child in sorted(sessions.iterdir()):
        if not child.is_dir():
            continue
        try:
            if any(child.iterdir()):
                continue
        except OSError:
            continue
        rel = child.relative_to(base)
        if dry_run:
            print(f"[dry-run] would remove empty dir {rel}/")
            pruned += 1
            continue
        try:
            child.rmdir()
            print(f"removed empty dir {rel}/")
            pruned += 1
        except OSError as exc:
            print(f"could not remove {rel}/: {exc}", file=sys.stderr)
    return pruned


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be deleted without removing anything.",
    )
    parser.add_argument(
        "--base",
        default=str(Path(__file__).resolve().parent.parent),
        help="EnfGuardV2 root directory (default: parent of this script).",
    )
    args = parser.parse_args()

    base = Path(args.base).resolve()
    targets = _candidate_paths(base)
    if not targets:
        print(f"Nothing to clear under {base}.")
        _prune_empty_session_dirs(base, args.dry_run)
        return 0

    for path in targets:
        rel = path.relative_to(base)
        if args.dry_run:
            print(f"[dry-run] would delete {rel}")
            continue
        try:
            path.unlink()
            print(f"removed {rel}")
        except OSError as exc:
            print(f"could not remove {rel}: {exc}", file=sys.stderr)

    pruned = _prune_empty_session_dirs(base, args.dry_run)

    if args.dry_run:
        print(
            f"{len(targets)} file(s) and {pruned} empty session dir(s) "
            f"would be removed (dry run)."
        )
    else:
        print(
            f"cleared {len(targets)} file(s) and pruned {pruned} empty "
            f"session dir(s) under {base}."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
