#!/usr/bin/env python3
"""Benchmark judge-batching strategies against a fixed prompt corpus.

Designed to run while the proxy is up, with the bench YAML loaded.

    export ENFGUARD_ADMIN_TOKEN=<your-token>
    export ENFGUARD_YAML=bench/enfguard_bench.yaml
    python -m uvicorn proxy:app --host 127.0.0.1 --port 9000   # in another shell
    python scripts/bench_judges.py --output bench/results.csv

For each (strategy × call_mode) cell the script:
    1. Clears the judge cache so the run is cold.
    2. Sets ``judge_strategy`` and ``judge_call_mode`` switches via the API.
    3. Sends each prompt from ``bench/bench_prompts.yaml``.
    4. Reads ``/trace/{tid}`` and records per-phase judge_ms / enfguard_ms /
       fired-predicates / verdict.
    5. Appends one CSV row per request.

The output CSV is what you take into a notebook or spreadsheet for the
performance chapter. Run with ``--repeat 3`` for a small variance band.
"""

from __future__ import annotations

import argparse
import csv
import os
import statistics
import sys
import time
from pathlib import Path
from typing import Any

import httpx
import yaml

# The matrix the user asked for. Five cells: S0, S1, S2-batched, S2-parallel, S3.
DEFAULT_CONFIGS: list[dict[str, str]] = [
    {"strategy": "off", "call_mode": "batched"},  # call_mode is moot when strategy=off
    {"strategy": "all_firing", "call_mode": "batched"},
    {"strategy": "active_policy", "call_mode": "batched"},
    {"strategy": "active_policy", "call_mode": "parallel"},
    {"strategy": "guard_aware", "call_mode": "batched"},
]


def _phase(phases: list[dict[str, Any]], name: str) -> dict[str, Any]:
    return next((p for p in phases if p.get("phase") == name), {})


def _fired_names(phase: dict[str, Any]) -> str:
    return ", ".join(
        str(entry.get("predicate") or "")
        for entry in phase.get("fired_predicates") or []
    )


def _phase_rows(rows: list[dict[str, Any]], phase: str) -> list[dict[str, Any]]:
    return [row for row in rows if row.get("phase") == phase]


def _dispatch_count(rows: list[dict[str, Any]]) -> int:
    """Count judge dispatches represented by trace rows.

    Rows that share a ``batch_id`` came from one batched or parallel dispatch.
    Rows without a batch id are counted individually.
    """

    batch_ids = {str(row.get("batch_id", "") or "") for row in rows if row.get("batch_id")}
    singles = sum(1 for row in rows if not row.get("batch_id"))
    return len(batch_ids) + singles


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark judge-batching strategies for the EnfGuard proxy.",
    )
    parser.add_argument("--proxy", default="http://127.0.0.1:9000")
    parser.add_argument("--prompts", default="bench/bench_prompts.yaml")
    parser.add_argument("--output", default="bench/results.csv")
    parser.add_argument(
        "--admin-token",
        default=os.environ.get("ENFGUARD_ADMIN_TOKEN"),
        help="Defaults to $ENFGUARD_ADMIN_TOKEN.",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="Send each prompt N times per config (for variance bands).",
    )
    parser.add_argument(
        "--model",
        default="gpt-4o-mini",
        help="Model id sent to the proxy. Used as 'model' in the chat body.",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=160,
        help="Cap chat completion length during the benchmark. Use 0 to omit.",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.0,
        help="Chat model temperature for reproducible benchmark runs.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress per-prompt console output.",
    )
    parser.add_argument(
        "--startup-timeout",
        type=float,
        default=30.0,
        help="Seconds to wait for the proxy health endpoint before failing.",
    )
    parser.add_argument(
        "--switch-sweep",
        action="store_true",
        help=(
            "For each strategy cell, also sweep the allow_emojis × allow_medical "
            "boolean switches. Lets the guard_aware strategy's advantage show up "
            "as a real number (in the off=false / off=false case it does the same "
            "work as active_policy; flipping a switch makes guard_aware skip)."
        ),
    )
    parser.add_argument(
        "--guard-switches",
        default="allow_emojis,allow_medical",
        help=(
            "Comma-separated list of boolean switches to sweep when "
            "--switch-sweep is set. Defaults match the bench YAML."
        ),
    )
    args = parser.parse_args()

    if not args.admin_token:
        print(
            "error: ENFGUARD_ADMIN_TOKEN required (pass --admin-token or set the env var)",
            file=sys.stderr,
        )
        return 2

    prompts_path = Path(args.prompts)
    if not prompts_path.exists():
        print(f"error: prompts file not found: {prompts_path}", file=sys.stderr)
        return 2
    prompts = yaml.safe_load(prompts_path.read_text(encoding="utf-8")).get("prompts", [])
    if not prompts:
        print("error: no prompts in YAML file", file=sys.stderr)
        return 2

    headers = {"x-admin-token": args.admin_token}
    proxy_url = args.proxy.rstrip("/")

    readiness_error = _wait_for_proxy(proxy_url, headers, args.startup_timeout)
    if readiness_error:
        print(readiness_error, file=sys.stderr)
        return 2

    rows: list[dict[str, Any]] = []
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    guard_switches: list[str] = []
    if args.switch_sweep:
        guard_switches = [s.strip() for s in args.guard_switches.split(",") if s.strip()]
    guard_states = _guard_state_sweep(guard_switches)

    with httpx.Client(headers=headers, timeout=120.0) as client:
        clear_traces = True
        for config in DEFAULT_CONFIGS:
            for guard_state in guard_states:
                guard_label = (
                    "/".join(f"{k}={v}" for k, v in guard_state.items())
                    if guard_state
                    else "default-switches"
                )
                cell_label = (
                    f"{config['strategy']:13s} / {config['call_mode']:8s}"
                    f" · {guard_label}"
                )
                if not args.quiet:
                    print(f"\n=== {cell_label} ===")

                # 1. Cold cache.
                r = client.post(
                    f"{proxy_url}/admin/clear_judge_cache",
                    json={"traces": clear_traces},
                )
                _raise_for_status(r, "clear judge cache")
                clear_traces = False

                # 2. Flip strategy + call_mode switches.
                for key in ("strategy", "call_mode"):
                    switch_id = f"judge_{key}"
                    r = client.post(
                        f"{proxy_url}/switches/{switch_id}",
                        json={"value": config[key]},
                    )
                    _raise_for_status(r, f"set {switch_id}={config[key]!r}")

                # 2a. Reset every guard switch the harness can flip to a
                # known baseline (`false`, the YAML default for the bench
                # boolean guards) so each cell starts from a clean state
                # regardless of what a prior cell or prior bench run left
                # behind. Without this reset, a previous --switch-sweep run
                # that ended on `allow_emojis=true` would silently keep
                # guard_aware skipping the emoji judge and bias the
                # comparison against active_policy.
                for switch_id in guard_switches:
                    r = client.post(
                        f"{proxy_url}/switches/{switch_id}",
                        json={"value": "false"},
                    )
                    _raise_for_status(r, f"reset {switch_id}=false")

                # 2b. Apply per-cell guard overrides (only set when running
                # with --switch-sweep). The reset above guarantees switches
                # not in this cell's overrides are at the baseline.
                for switch_id, value in guard_state.items():
                    r = client.post(
                        f"{proxy_url}/switches/{switch_id}",
                        json={"value": value},
                    )
                    _raise_for_status(r, f"set {switch_id}={value!r}")

                # 3. Run the corpus.
                for prompt in prompts:
                    pid = str(prompt.get("id") or "")
                    text = str(prompt.get("text") or "")
                    for rep in range(args.repeat):
                        guard_tag = "_".join(f"{k}{v}" for k, v in guard_state.items()) or "default"
                        sid = (
                            f"bench-{config['strategy']}-{config['call_mode']}"
                            f"-{guard_tag}-{rep}-{pid}"
                        )
                        started = time.monotonic()
                        try:
                            chat_body: dict[str, Any] = {
                                "model": args.model,
                                "messages": [{"role": "user", "content": text}],
                                "temperature": args.temperature,
                            }
                            if args.max_tokens > 0:
                                chat_body["max_tokens"] = args.max_tokens

                            chat = client.post(
                                f"{proxy_url}/v1/chat/completions",
                                headers={
                                    "x-admin-token": args.admin_token,
                                    "x-session-id": sid,
                                    "x-provider": "openai",
                                },
                                json=chat_body,
                            )
                        except Exception as exc:
                            rows.append(
                                _error_row(config, guard_state, pid, rep, sid, args.model, str(exc))
                            )
                            if not args.quiet:
                                print(f"  {pid:30s} ERROR {exc}")
                            continue
                        elapsed_ms = int((time.monotonic() - started) * 1000)
                        tid = chat.headers.get("x-tid", "")
                        action = chat.headers.get("x-enforcement-action", "")
                        inbound: dict[str, Any] = {}
                        outbound: dict[str, Any] = {}
                        inbound_rows: list[dict[str, Any]] = []
                        outbound_rows: list[dict[str, Any]] = []
                        if tid:
                            try:
                                trace = client.get(f"{proxy_url}/trace/{tid}").json()
                                phases = trace.get("phases") or []
                                predicate_rows = trace.get("predicate_rows") or []
                                inbound = _phase(phases, "inbound")
                                outbound = _phase(phases, "outbound")
                                inbound_rows = _phase_rows(predicate_rows, "inbound")
                                outbound_rows = _phase_rows(predicate_rows, "outbound")
                            except Exception as exc:
                                inbound = {"error": str(exc)}

                        row = {
                            "strategy": config["strategy"],
                            "call_mode": config["call_mode"],
                            "guards": _format_guard_state(guard_state),
                            "model": args.model,
                            "max_tokens": args.max_tokens,
                            "temperature": args.temperature,
                            "prompt_id": pid,
                            "rep": rep,
                            "tid": tid,
                            "verdict_action": action,
                            "total_ms": elapsed_ms,
                            "inbound_judge_ms": int(inbound.get("judge_ms", 0) or 0),
                            "inbound_judge_row_ms": int(inbound.get("judge_row_ms", 0) or 0),
                            "inbound_enfguard_ms": int(inbound.get("enfguard_ms", 0) or 0),
                            "inbound_predicate_count": int(inbound.get("predicate_count", 0) or 0),
                            "inbound_dispatch_count": _dispatch_count(inbound_rows),
                            "inbound_fired": _fired_names(inbound),
                            "outbound_judge_ms": int(outbound.get("judge_ms", 0) or 0),
                            "outbound_judge_row_ms": int(outbound.get("judge_row_ms", 0) or 0),
                            "outbound_enfguard_ms": int(outbound.get("enfguard_ms", 0) or 0),
                            "upstream_ms": int(outbound.get("upstream_ms", 0) or 0),
                            "outbound_predicate_count": int(outbound.get("predicate_count", 0) or 0),
                            "outbound_dispatch_count": _dispatch_count(outbound_rows),
                            "outbound_fired": _fired_names(outbound),
                        }
                        rows.append(row)
                        if not args.quiet:
                            in_ms = row["inbound_judge_ms"]
                            out_ms = row["outbound_judge_ms"]
                            print(
                                f"  {pid:30s} {action:18s} total={elapsed_ms:5d}ms "
                                f"inbound_judge={in_ms:5d}ms outbound_judge={out_ms:5d}ms"
                            )

    # Write CSV.
    if not rows:
        print("no rows recorded; not writing CSV", file=sys.stderr)
        return 1
    fieldnames = list(rows[0].keys())
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nwrote {len(rows)} rows → {output_path}")

    # Summary table per cell.
    print("\n──── summary (median ms per cell, across all prompts × repeats) ────")
    by_cell: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for row in rows:
        cell = (str(row["strategy"]), str(row["call_mode"]), str(row.get("guards", "")))
        by_cell.setdefault(cell, []).append(row)
    for (strategy, call_mode, guards), cell_rows in by_cell.items():
        if not cell_rows:
            continue
        values = [int(row["total_ms"]) for row in cell_rows]
        median = int(statistics.median(values))
        judge = int(
            statistics.median(
                int(row["inbound_judge_ms"]) + int(row["outbound_judge_ms"])
                for row in cell_rows
            )
        )
        dispatches = statistics.median(
            int(row["inbound_dispatch_count"]) + int(row["outbound_dispatch_count"])
            for row in cell_rows
        )
        mn = min(values)
        mx = max(values)
        n = len(values)
        guard_label = guards or "default"
        print(
            f"  {strategy:13s} / {call_mode:8s} · {guard_label:30s} "
            f"n={n:3d}  total={median:5d}ms  judge={judge:5d}ms  "
            f"dispatches={dispatches:3.0f}  min={mn:5d}ms  max={mx:5d}ms"
        )

    return 0


def _guard_state_sweep(switch_ids: list[str]) -> list[dict[str, str]]:
    """Build the cartesian product of {true,false} over the listed switches.

    Empty list → one cell with no overrides (script keeps proxy defaults).
    Three switches → 8 cells, etc. ``"true"`` and ``"false"`` are the
    canonical strings the switch endpoint expects for boolean kinds.
    """

    if not switch_ids:
        return [{}]
    out: list[dict[str, str]] = [{}]
    for switch_id in switch_ids:
        nxt: list[dict[str, str]] = []
        for state in out:
            for value in ("false", "true"):
                merged = dict(state)
                merged[switch_id] = value
                nxt.append(merged)
        out = nxt
    return out


def _format_guard_state(state: dict[str, str]) -> str:
    if not state:
        return ""
    return ",".join(f"{k}={v}" for k, v in state.items())


def _error_row(
    config: dict[str, str],
    guard_state: dict[str, str],
    pid: str,
    rep: int,
    sid: str,
    model: str,
    err: str,
) -> dict[str, Any]:
    return {
        "strategy": config["strategy"],
        "call_mode": config["call_mode"],
        "guards": _format_guard_state(guard_state),
        "model": model,
        "max_tokens": "",
        "temperature": "",
        "prompt_id": pid,
        "rep": rep,
        "tid": "",
        "verdict_action": f"error: {err}",
        "total_ms": 0,
        "inbound_judge_ms": 0,
        "inbound_judge_row_ms": 0,
        "inbound_enfguard_ms": 0,
        "inbound_predicate_count": 0,
        "inbound_dispatch_count": 0,
        "inbound_fired": "",
        "outbound_judge_ms": 0,
        "outbound_judge_row_ms": 0,
        "outbound_enfguard_ms": 0,
        "upstream_ms": 0,
        "outbound_predicate_count": 0,
        "outbound_dispatch_count": 0,
        "outbound_fired": "",
    }


def _wait_for_proxy(
    proxy_url: str,
    headers: dict[str, str],
    startup_timeout: float,
) -> str:
    """Wait for uvicorn/proxy startup, then validate bench prerequisites."""

    deadline = time.monotonic() + max(0.0, startup_timeout)
    last_error = ""
    with httpx.Client(headers=headers, timeout=5.0) as client:
        while True:
            try:
                client.get(f"{proxy_url}/health").raise_for_status()
                break
            except Exception as exc:
                last_error = str(exc)
                if time.monotonic() >= deadline:
                    return f"error: proxy not reachable at {proxy_url}: {last_error}"
                time.sleep(0.25)

        try:
            switches_response = client.get(f"{proxy_url}/switches")
        except Exception as exc:
            return f"error: proxy admin routes not reachable at {proxy_url}: {exc}"
        if switches_response.status_code == 401:
            return (
                "error: invalid admin token for running proxy. Start uvicorn and "
                "bench_judges.py with the same ENFGUARD_ADMIN_TOKEN."
            )
        if switches_response.status_code >= 400:
            return (
                f"error: proxy admin readiness check failed: "
                f"{switches_response.status_code} {switches_response.text}"
            )
        try:
            switch_ids = {
                str(item.get("id", ""))
                for item in switches_response.json().get("switches", [])
                if isinstance(item, dict)
            }
        except Exception as exc:
            return f"error: could not parse /switches response: {exc}"
        required = {"judge_strategy", "judge_call_mode"}
        missing = sorted(required - switch_ids)
        if missing:
            return (
                "error: running proxy is not using the bench YAML; missing switches "
                f"{missing}. Restart with ENFGUARD_YAML=bench/enfguard_bench.yaml."
            )
    return ""


def _raise_for_status(response: httpx.Response, action: str) -> None:
    """Raise with proxy response text included."""

    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        detail = response.text.strip()
        raise RuntimeError(
            f"failed to {action}: HTTP {response.status_code}: {detail}"
        ) from exc


if __name__ == "__main__":
    sys.exit(main())
