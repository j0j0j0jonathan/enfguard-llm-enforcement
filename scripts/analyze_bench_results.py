#!/usr/bin/env python3
"""Summarise EnfGuard benchmark CSV output.

Two CSV shapes are supported:

* ``scripts/bench_judges.py`` rows — judge-strategy sweep, with columns
  ``strategy``, ``call_mode``, ``guards``, ``inbound_judge_ms``,
  ``outbound_judge_ms``, ``upstream_ms``, ``inbound_dispatch_count``,
  ``outbound_dispatch_count`` etc. The summary block at the top
  (per strategy / call-mode) is for these.

* ``scripts/bench_provider_specs.py`` rows — provider-spec sweep, with
  columns ``policy_pack``, ``expected_action(s)``, ``observed_action``,
  ``match`` / ``action_match`` / ``predicate_match``, and a
  ``fired_details_json`` blob carrying per-predicate latencies. The
  per-predicate CDF block at the bottom builds a CDF / percentile view
  from that JSON, which is what the thesis's overhead chapter wants
  ("the cheap regex predicates contribute <1ms; the expensive 2-input
  judges dominate at ~1.2 s p50").

Both shapes coexist gracefully: missing columns simply produce empty
sections.
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
from collections import Counter
from pathlib import Path
from typing import Any


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarise EnfGuard benchmark CSVs.")
    parser.add_argument("csv_path", nargs="?", default="bench/results.csv")
    parser.add_argument(
        "--predicate-percentiles",
        action="store_true",
        help=(
            "Also print the per-predicate latency CDF / percentiles (p50, "
            "p90, p99) computed from fired_details_json. Defaults on when "
            "the column is present."
        ),
    )
    args = parser.parse_args()

    path = Path(args.csv_path)
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    if not rows:
        print(f"no rows in {path}")
        return 1

    print(f"rows: {len(rows)}")

    if any("strategy" in row for row in rows):
        print("\nmedian by strategy/call-mode/guards")
        for cell, cell_rows in _group(rows, ["strategy", "call_mode", "guards"]).items():
            totals = [_int(row, "total_ms") for row in cell_rows]
            judges = [
                _int(row, "inbound_judge_ms") + _int(row, "outbound_judge_ms")
                for row in cell_rows
            ]
            upstream = [_int(row, "upstream_ms") for row in cell_rows]
            dispatches = [
                _int(row, "inbound_dispatch_count") + _int(row, "outbound_dispatch_count")
                for row in cell_rows
            ]
            print(
                f"  {cell:65s} n={len(cell_rows):3d} "
                f"total={int(statistics.median(totals)):5d}ms "
                f"judge={int(statistics.median(judges)):5d}ms "
                f"model={int(statistics.median(upstream)):5d}ms "
                f"dispatches={statistics.median(dispatches):3.0f} "
                f"min={min(totals):5d}ms max={max(totals):5d}ms"
            )

    print("\nverdicts by prompt")
    for prompt_id, prompt_rows in _group(rows, ["prompt_id"]).items():
        counts = Counter(
            row.get("verdict_action", row.get("observed_action", "")) for row in prompt_rows
        )
        print(f"  {prompt_id:32s} {dict(counts)}")

    print("\nmedian total_ms by prompt")
    for prompt_id, prompt_rows in _group(rows, ["prompt_id"]).items():
        totals = [_int(row, "total_ms") for row in prompt_rows]
        print(
            f"  {prompt_id:32s} median={int(statistics.median(totals)):5d}ms "
            f"min={min(totals):5d}ms max={max(totals):5d}ms"
        )

    # provider-spec rows: action vs. predicate vs. overall match summary.
    if any("action_match" in row for row in rows):
        print("\nmatch rates")
        verdict_total = len(rows)
        action_match = sum(1 for row in rows if row.get("action_match") == "true")
        overall_match = sum(1 for row in rows if row.get("match") == "true")
        pred_required = sum(1 for row in rows if row.get("expected_predicates"))
        pred_match = sum(
            1
            for row in rows
            if row.get("expected_predicates") and row.get("predicate_match") == "true"
        )
        print(
            f"  verdict-only:        {action_match}/{verdict_total} "
            f"({_pct(action_match, verdict_total)})"
        )
        print(
            f"  verdict + predicate: {overall_match}/{verdict_total} "
            f"({_pct(overall_match, verdict_total)})"
        )
        if pred_required:
            print(
                f"  fired-the-right-predicate: {pred_match}/{pred_required} "
                f"({_pct(pred_match, pred_required)}) of predicate-checked rows"
            )

    # Per-predicate latency CDF / percentiles. We pull every fired detail
    # entry across every row and aggregate by predicate name. This is the
    # core artefact for the overhead chapter — one row per predicate with
    # n / median / p90 / p99 / cache-hit-rate.
    if any("fired_details_json" in row for row in rows):
        if args.predicate_percentiles or _any_predicate_data(rows):
            buckets = _predicate_buckets(rows)
            if buckets:
                print("\nper-predicate latency (ms)")
                print(
                    f"  {'predicate':38s} {'n':>5s} {'median':>7s} "
                    f"{'p90':>6s} {'p99':>6s} {'mean':>6s} {'cache_hit':>10s}"
                )
                rows_sorted = sorted(
                    buckets.items(),
                    key=lambda item: -_percentile(item[1]["latencies"], 50.0),
                )
                for predicate_name, bucket in rows_sorted:
                    latencies = bucket["latencies"]
                    cache_rate = bucket["cache_hits"] / max(1, bucket["count"])
                    print(
                        f"  {predicate_name:38s} {bucket['count']:5d} "
                        f"{int(_percentile(latencies, 50.0)):7d} "
                        f"{int(_percentile(latencies, 90.0)):6d} "
                        f"{int(_percentile(latencies, 99.0)):6d} "
                        f"{int(statistics.fmean(latencies)):6d} "
                        f"{cache_rate:10.1%}"
                    )

    return 0


def _group(rows: list[dict[str, Any]], keys: list[str]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        label = " / ".join(str(row.get(key, "") or "default") for key in keys)
        grouped.setdefault(label, []).append(row)
    return grouped


def _int(row: dict[str, Any], key: str) -> int:
    try:
        return int(float(row.get(key, 0) or 0))
    except (TypeError, ValueError):
        return 0


def _pct(numerator: int, denominator: int) -> str:
    if denominator <= 0:
        return "0.0%"
    return f"{numerator / denominator:.1%}"


def _any_predicate_data(rows: list[dict[str, Any]]) -> bool:
    return any(str(row.get("fired_details_json", "") or "").strip() not in {"", "[]"} for row in rows)


def _predicate_buckets(
    rows: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    buckets: dict[str, dict[str, Any]] = {}
    for row in rows:
        blob = row.get("fired_details_json", "") or ""
        try:
            entries = json.loads(blob)
        except (TypeError, ValueError):
            continue
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("predicate", "") or "")
            if not name:
                continue
            try:
                latency = int(float(entry.get("latency_ms", 0) or 0))
            except (TypeError, ValueError):
                latency = 0
            cache_hit = 1 if entry.get("cache_hit") else 0
            bucket = buckets.setdefault(
                name,
                {"latencies": [], "cache_hits": 0, "count": 0},
            )
            bucket["latencies"].append(latency)
            bucket["cache_hits"] += cache_hit
            bucket["count"] += 1
    return buckets


def _percentile(values: list[int], p: float) -> float:
    """Compute the ``p``-th percentile (0-100) using linear interpolation."""

    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    rank = (p / 100.0) * (len(ordered) - 1)
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    frac = rank - low
    return ordered[low] * (1 - frac) + ordered[high] * frac


if __name__ == "__main__":
    raise SystemExit(main())
