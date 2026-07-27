#!/usr/bin/env python3
"""Run a provider-spec prompt suite directly against the chat model.

This is the *no-proxy* baseline that the writing plan's chapter 7 ("compare
with NeMo Guardrails, Guardrails AI") calls for. It sends the same prompt
suite the EnfGuard bench uses (``bench/openai_model_spec_prompts.yaml`` etc.)
straight to the upstream chat API, without any enforcement layer in between,
and writes a CSV row per prompt with:

* the model's reply text, latency, and HTTP status,
* a coarse heuristic verdict (``allowed`` vs. ``model_refused``) so the
  baseline can be aggregated alongside proxy runs,
* the prompt's expected_action / expected_predicates fields, so the
  analysis script can join the two CSVs and produce a side-by-side
  "model alone vs. model + proxy" comparison.

The baseline does NOT attempt to grade whether the model "did the right
thing" by spec. That requires either an external judge layer (which we
already have in the proxy) or human labelling. What this script gives you
is the latency floor, the refusal rate, and the raw output text — enough
to back the thesis claim that the proxy's overhead is N ms over a Y%
refusal-rate baseline.

Multi-turn prompts (with ``turns:``) are walked sequentially the same way
the proxy harness walks them, so multi-turn latency comparisons are
apples-to-apples.

Usage::

    python scripts/bench_no_proxy_baseline.py \\
        --prompts bench/openai_model_spec_prompts.yaml \\
        --output bench/openai_model_spec_no_proxy_baseline.csv \\
        --provider openai --model gpt-4o-mini

For Anthropic::

    python scripts/bench_no_proxy_baseline.py \\
        --prompts bench/anthropic_constitution_prompts.yaml \\
        --output bench/anthropic_constitution_no_proxy_baseline.csv \\
        --provider anthropic --model claude-3-5-haiku-latest
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import statistics
import sys
import time
from pathlib import Path
from typing import Any

import httpx
import yaml

# Reuse the loader and helpers from the proxy bench so the schema check
# stays identical.
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent))

from scripts.bench_provider_specs import (  # noqa: E402  (import after sys.path)
    EXPECTED_ACTIONS,
    expected_actions_for,
    load_prompt_suite,
)


JsonObject = dict[str, Any]


# Very simple refusal heuristic. Models phrase refusals differently, but the
# point of this column is to give the analysis script a comparable feature,
# not to ground-truth refusal detection. If you need precise labels, run the
# proxy with the corresponding policy pack — that is what produces the
# rigorous verdict.
_REFUSAL_RE = re.compile(
    r"(?:^|\b)(?:i\s+can(?:not|'t)|i\s+won'?t|i'?m\s+(?:not\s+able|unable)|"
    r"i\s+have\s+to\s+decline|i\s+must\s+decline|i\s+won'?t\s+be\s+able\s+to\s+help|"
    r"sorry,?\s+(?:but\s+)?i\s+can(?:not|'t))",
    re.IGNORECASE,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="No-proxy baseline runner for provider-spec prompt suites.",
    )
    parser.add_argument("--prompts", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--provider",
        choices=("openai", "anthropic"),
        default="openai",
    )
    parser.add_argument(
        "--model",
        default="gpt-4o-mini",
    )
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--max-tokens", type=int, default=180)
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument(
        "--openai-base-url",
        default=os.environ.get("OPENAI_BASE_URL", "https://api.openai.com"),
    )
    parser.add_argument(
        "--anthropic-base-url",
        default=os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com"),
    )
    parser.add_argument(
        "--openai-api-key",
        default=os.environ.get("OPENAI_API_KEY"),
    )
    parser.add_argument(
        "--anthropic-api-key",
        default=os.environ.get("ANTHROPIC_API_KEY"),
    )
    parser.add_argument(
        "--anthropic-version",
        default=os.environ.get("ANTHROPIC_VERSION", "2023-06-01"),
    )
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    if args.provider == "openai" and not args.openai_api_key:
        print("error: OPENAI_API_KEY required", file=sys.stderr)
        return 2
    if args.provider == "anthropic" and not args.anthropic_api_key:
        print("error: ANTHROPIC_API_KEY required", file=sys.stderr)
        return 2

    try:
        suite, prompts = load_prompt_suite(Path(args.prompts))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rows: list[JsonObject] = []
    with httpx.Client(timeout=180.0) as client:
        for rep in range(args.repeat):
            for prompt in prompts:
                row = run_prompt(
                    client=client,
                    suite=suite,
                    prompt=prompt,
                    rep=rep,
                    args=args,
                )
                rows.append(row)
                if not args.quiet:
                    print(
                        f"{row['prompt_id']:34s} status={row['http_status']:3d}  "
                        f"refusal={row['heuristic_refusal']!s:5s}  "
                        f"total={row['total_ms']}ms"
                    )

    if not rows:
        print("error: no rows recorded", file=sys.stderr)
        return 1

    write_csv(output_path, rows)
    print_summary(rows, output_path)
    return 0


def run_prompt(
    *,
    client: httpx.Client,
    suite: JsonObject,
    prompt: JsonObject,
    rep: int,
    args: argparse.Namespace,
) -> JsonObject:
    pid = str(prompt["id"])
    accepted = expected_actions_for(prompt)
    expected_predicates = [
        str(item) for item in (prompt.get("expected_predicates") or []) if str(item)
    ]

    turns_field = prompt.get("turns")
    if isinstance(turns_field, list) and turns_field:
        return run_multi_turn_prompt(
            client=client,
            suite=suite,
            prompt=prompt,
            turns=turns_field,
            rep=rep,
            args=args,
        )

    text = str(prompt["text"])
    started = time.monotonic()
    try:
        http_status, response_text = _post_chat(
            client=client,
            args=args,
            history=None,
            user_text=text,
        )
        total_ms = int((time.monotonic() - started) * 1000)
    except Exception as exc:
        return _error_row(suite, prompt, rep, accepted, expected_predicates, str(exc))

    return {
        "suite": str(suite.get("suite", "")),
        "policy_pack": str(suite.get("policy_pack", "")),
        "provider": args.provider,
        "model": args.model,
        "prompt_id": pid,
        "rep": rep,
        "category": str(prompt.get("category", "")),
        "expected_action": accepted[0] if accepted else "",
        "expected_actions": ";".join(accepted),
        "expected_predicates": ";".join(expected_predicates),
        "http_status": http_status,
        "total_ms": total_ms,
        "response_text": response_text,
        "response_chars": len(response_text),
        "heuristic_refusal": _looks_like_refusal(response_text),
        "turns_count": 1,
        "notes": str(prompt.get("notes", "")),
    }


def run_multi_turn_prompt(
    *,
    client: httpx.Client,
    suite: JsonObject,
    prompt: JsonObject,
    turns: list[JsonObject],
    rep: int,
    args: argparse.Namespace,
) -> JsonObject:
    pid = str(prompt["id"])
    accepted = expected_actions_for(prompt)
    expected_predicates = [
        str(item) for item in (prompt.get("expected_predicates") or []) if str(item)
    ]
    history: list[JsonObject] = []
    final_text = ""
    final_status = 0
    started = time.monotonic()
    try:
        for turn in turns:
            user_text = str(turn.get("text", ""))
            status, response_text = _post_chat(
                client=client,
                args=args,
                history=history,
                user_text=user_text,
            )
            history.append({"role": "user", "content": user_text})
            history.append({"role": "assistant", "content": response_text})
            final_text = response_text
            final_status = status
        total_ms = int((time.monotonic() - started) * 1000)
    except Exception as exc:
        return _error_row(suite, prompt, rep, accepted, expected_predicates, str(exc))

    return {
        "suite": str(suite.get("suite", "")),
        "policy_pack": str(suite.get("policy_pack", "")),
        "provider": args.provider,
        "model": args.model,
        "prompt_id": pid,
        "rep": rep,
        "category": str(prompt.get("category", "")),
        "expected_action": accepted[0] if accepted else "",
        "expected_actions": ";".join(accepted),
        "expected_predicates": ";".join(expected_predicates),
        "http_status": final_status,
        "total_ms": total_ms,
        "response_text": final_text,
        "response_chars": len(final_text),
        "heuristic_refusal": _looks_like_refusal(final_text),
        "turns_count": len(turns),
        "notes": str(prompt.get("notes", "")),
    }


def _post_chat(
    *,
    client: httpx.Client,
    args: argparse.Namespace,
    history: list[JsonObject] | None,
    user_text: str,
) -> tuple[int, str]:
    messages = list(history or [])
    messages.append({"role": "user", "content": user_text})
    if args.provider == "anthropic":
        url = f"{args.anthropic_base_url.rstrip('/')}/v1/messages"
        body = {
            "model": args.model,
            "max_tokens": args.max_tokens,
            "temperature": args.temperature,
            "messages": messages,
        }
        headers = {
            "x-api-key": args.anthropic_api_key,
            "anthropic-version": args.anthropic_version,
            "content-type": "application/json",
        }
    else:
        url = f"{args.openai_base_url.rstrip('/')}/v1/chat/completions"
        body = {
            "model": args.model,
            "max_tokens": args.max_tokens,
            "temperature": args.temperature,
            "messages": messages,
        }
        headers = {
            "Authorization": f"Bearer {args.openai_api_key}",
            "content-type": "application/json",
        }

    response = client.post(url, headers=headers, json=body)
    if response.status_code < 200 or response.status_code >= 300:
        return response.status_code, ""
    payload = response.json()
    return response.status_code, _extract_text(payload, args.provider)


def _extract_text(payload: JsonObject, provider: str) -> str:
    if not isinstance(payload, dict):
        return ""
    if provider == "anthropic":
        for block in payload.get("content", []) or []:
            if isinstance(block, dict) and block.get("type") == "text":
                return str(block.get("text", "") or "")
        return ""
    choices = payload.get("choices")
    if isinstance(choices, list) and choices:
        message = choices[0].get("message") if isinstance(choices[0], dict) else None
        if isinstance(message, dict):
            return str(message.get("content", "") or "")
    return ""


def _looks_like_refusal(text: str) -> bool:
    return bool(_REFUSAL_RE.search(text or ""))


def _error_row(
    suite: JsonObject,
    prompt: JsonObject,
    rep: int,
    accepted: list[str],
    expected_predicates: list[str],
    error: str,
) -> JsonObject:
    return {
        "suite": str(suite.get("suite", "")),
        "policy_pack": str(suite.get("policy_pack", "")),
        "provider": "",
        "model": "",
        "prompt_id": str(prompt.get("id", "")),
        "rep": rep,
        "category": str(prompt.get("category", "")),
        "expected_action": accepted[0] if accepted else "",
        "expected_actions": ";".join(accepted),
        "expected_predicates": ";".join(expected_predicates),
        "http_status": 0,
        "total_ms": 0,
        "response_text": f"error: {error}",
        "response_chars": 0,
        "heuristic_refusal": False,
        "turns_count": 0,
        "notes": str(prompt.get("notes", "")),
    }


def write_csv(path: Path, rows: list[JsonObject]) -> None:
    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def print_summary(rows: list[JsonObject], output_path: Path) -> None:
    total = len(rows)
    refusals = sum(1 for row in rows if row.get("heuristic_refusal"))
    latency_values = [int(row.get("total_ms", 0) or 0) for row in rows]
    median_ms = int(statistics.median(latency_values)) if latency_values else 0
    print(f"\nwrote {total} rows -> {output_path}")
    print(f"heuristic refusals: {refusals}/{total} ({refusals / total:.1%})")
    print(f"median total latency: {median_ms}ms")


if __name__ == "__main__":
    sys.exit(main())
