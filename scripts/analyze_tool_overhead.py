#!/usr/bin/env python3
"""End-to-end enforcement-overhead analysis from proxy session logs (RQ3).

Reads the per-turn session records the proxy writes to ``logs/session_*.jsonl``
and reports the enforcement overhead the proxy actually added, split by surface:

* **Agent gate** (`/v1/tool_execute`, action starts ``tool_`` but not
  ``tool_result_``): the per-tool-call monitor cost, ``enfguard_ms.inbound``.
  There is no upstream model call at the gate, so this plus the classifier cost
  (see ``bench_classifier_overhead.py``, about 0.12 ms) is the whole overhead.
* **Agent result** (`/v1/tool_result`, action ``tool_result_*``): observation
  cost after a tool ran.
* **Chat** (action ``response_*`` / ``request_*`` / allowed/blocked/warned):
  ``enfguard_ms.inbound + outbound`` is the engine overhead, ``upstream_ms`` is
  the unavoidable model latency. The overhead fraction = engine / (engine +
  upstream) shows how little the monitor adds on top of the model call.

Judge HTTP latency is NOT in these records (it lives on the per-predicate trace
rows, see ``analyze_bench_results.py`` for the judge CDF). The deterministic
security packs run with zero judges, so for the agent gate the engine number is
the complete enforcement overhead.

Usage:

    python scripts/analyze_tool_overhead.py
    python scripts/analyze_tool_overhead.py logs/session_*.jsonl --csv overhead.csv
"""

from __future__ import annotations

import argparse
import csv
import glob
import json
import statistics
from pathlib import Path
from typing import Any


def _pct(sorted_v: list[float], p: float) -> float:
    if not sorted_v:
        return 0.0
    k = max(0, min(len(sorted_v) - 1, int(round((p / 100.0) * (len(sorted_v) - 1)))))
    return sorted_v[k]


def _surface(action: str) -> str:
    a = (action or "").lower()
    if a.startswith("tool_result"):
        return "agent_result"
    if a.startswith("tool_"):
        return "agent_gate"
    return "chat"


def _engine_ms(rec: dict[str, Any]) -> float:
    e = rec.get("enfguard_ms") or {}
    return float(e.get("inbound", 0) or 0) + float(e.get("outbound", 0) or 0)


def summarise(label: str, vals: list[float]) -> dict[str, Any]:
    s = sorted(vals)
    return {
        "group": label,
        "n": len(s),
        "mean_ms": round(statistics.fmean(s), 2) if s else 0.0,
        "p50_ms": round(_pct(s, 50), 2),
        "p95_ms": round(_pct(s, 95), 2),
        "p99_ms": round(_pct(s, 99), 2),
        "max_ms": round(s[-1], 2) if s else 0.0,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("paths", nargs="*", default=["logs/session_*.jsonl"],
                    help="session log glob(s), default logs/session_*.jsonl")
    ap.add_argument("--csv", default="", help="optional per-record CSV path")
    args = ap.parse_args()

    files: list[str] = []
    for pat in args.paths:
        files.extend(glob.glob(pat))
    if not files:
        print("No session logs matched. Run a live session first, then point this "
              "script at logs/session_*.jsonl.")
        return 1

    by_surface: dict[str, list[float]] = {}
    upstream_by_surface: dict[str, list[float]] = {}
    rows: list[dict[str, Any]] = []
    n_records = 0
    for fp in files:
        with open(fp) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if "enfguard_ms" not in rec and "action" not in rec:
                    continue
                n_records += 1
                surf = _surface(rec.get("action", ""))
                eng = _engine_ms(rec)
                up = float(rec.get("upstream_ms", 0) or 0)
                by_surface.setdefault(surf, []).append(eng)
                upstream_by_surface.setdefault(surf, []).append(up)
                rows.append({"tid": rec.get("tid"), "surface": surf,
                             "action": rec.get("action"), "engine_ms": eng,
                             "upstream_ms": up})

    print(f"# Enforcement overhead from {len(files)} log file(s), {n_records} records\n")
    print("## Engine (EnfGuard monitor) overhead per turn, milliseconds\n")
    header = ["group", "n", "mean_ms", "p50_ms", "p95_ms", "p99_ms", "max_ms"]
    print("| " + " | ".join(header) + " |")
    print("|" + "|".join(["---"] * len(header)) + "|")
    for surf in sorted(by_surface):
        r = summarise(surf, by_surface[surf])
        print("| " + " | ".join(str(r[h]) for h in header) + " |")

    # Overhead as a fraction of total wall time for chat turns (where an upstream
    # model call exists). Agent-gate turns have no upstream call, so the engine
    # time is effectively the whole added latency.
    chat_eng = by_surface.get("chat", [])
    chat_up = [u for u in upstream_by_surface.get("chat", []) if u > 0]
    if chat_eng and chat_up:
        mean_eng = statistics.fmean(chat_eng)
        mean_up = statistics.fmean(chat_up)
        frac = 100.0 * mean_eng / (mean_eng + mean_up) if (mean_eng + mean_up) else 0.0
        print(f"\n## Chat turns: engine vs model")
        print(f"- mean engine overhead: {mean_eng:.1f} ms")
        print(f"- mean upstream model latency: {mean_up:.1f} ms")
        print(f"- engine as share of engine+model: {frac:.2f}%")
        print("- (judge HTTP latency, if any predicates fired, is separate, see "
              "analyze_bench_results.py)")

    agent = by_surface.get("agent_gate", [])
    if agent:
        r = summarise("agent_gate", agent)
        print(f"\n## Agent gate: per-tool-call enforcement overhead")
        print(f"- monitor mean {r['mean_ms']} ms, p95 {r['p95_ms']} ms, "
              f"p99 {r['p99_ms']} ms")
        print(f"- plus classifier mean ~0.12 ms (see bench_classifier_overhead.py)")
        print(f"- no upstream model call at the gate, so this is the full added latency")

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        print(f"\nPer-record rows written to {args.csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
