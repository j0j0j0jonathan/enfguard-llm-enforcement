#!/usr/bin/env python3
"""Run provider-spec-derived chatbot evaluation prompts through EnfGuard.

Typical runs:

    export ENFGUARD_ADMIN_TOKEN=dev-token
    export ENFGUARD_YAML=examples/openai_model_spec.yaml
    python -m uvicorn proxy:app --host 127.0.0.1 --port 9000
    python scripts/bench_provider_specs.py \
      --prompts bench/openai_model_spec_prompts.yaml \
      --output bench/openai_model_spec_results.csv

    export ENFGUARD_YAML=examples/anthropic_constitution.yaml
    python -m uvicorn proxy:app --host 127.0.0.1 --port 9000
    python scripts/bench_provider_specs.py \
      --provider anthropic \
      --model claude-3-5-haiku-latest \
      --prompts bench/anthropic_constitution_prompts.yaml \
      --output bench/anthropic_constitution_results.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import statistics
import sys
import time
from pathlib import Path
from typing import Any

import httpx
import yaml

JsonObject = dict[str, Any]

EXPECTED_ACTIONS = {
    "allowed",
    "request_warned",
    "request_blocked",
    "response_warned",
    "response_blocked",
}


def load_prompt_suite(path: Path) -> tuple[JsonObject, list[JsonObject]]:
    """Load and minimally validate a provider-spec prompt suite.

    Each prompt may declare:

    * ``expected_action`` (string) — single-acceptable verdict; or
    * ``expected_actions`` (list of strings) — set membership: any of
      these verdicts counts as a match. This solves the methodological
      bug where prompts like ``response_blocked`` are silently flagged
      as MISMATCH when the underlying chat model refuses on its own
      and the proxy correctly emits ``allowed`` for the empty/refusal
      response. Authors can write
      ``expected_actions: [allowed, response_blocked]`` to accept either.
    * ``expected_predicates`` (list of strings, optional) — each name is
      a predicate that *must* fire (score >= 0.5) somewhere in the trace.
      Without this field, the bench only asserts on the wire-level
      verdict; with it, we additionally verify the *right* predicate
      fired for the *right* reason, instead of accidentally matching
      because some unrelated predicate blocked the request.
    * ``synthetic_completion`` (string, optional) — when set, the prompt
      runs in audit/replay mode: the harness sends ``text`` to the proxy
      with ``synthetic_completion`` injected as the assistant's reply,
      bypassing the real chat model. Use this for outbound predicates
      whose normal path depends on getting the chat model to misbehave
      first (the over-refusal/sycophancy/hate-output prompts).
    """

    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path} must contain a YAML mapping")
    prompts = raw.get("prompts")
    if not isinstance(prompts, list) or not prompts:
        raise ValueError(f"{path} must contain a non-empty prompts list")

    seen_ids: set[str] = set()
    for index, prompt in enumerate(prompts, start=1):
        if not isinstance(prompt, dict):
            raise ValueError(f"prompt #{index} must be a mapping")
        pid = str(prompt.get("id", "") or "")
        if not pid:
            raise ValueError(f"prompt #{index} is missing id")
        if pid in seen_ids:
            raise ValueError(f"duplicate prompt id: {pid}")
        seen_ids.add(pid)

        # Either ``text`` (single-turn) or ``turns`` (multi-turn) must be set.
        # ``turns`` is a list of ``{text, synthetic_completion?,
        # expected_action?, expected_predicates?}`` objects sent through the
        # same session id in order. The prompt-level ``expected_action`` /
        # ``expected_predicates`` then describe the *final* turn's verdict
        # unless a turn declares its own. This is what lets the suite test
        # MFOTL temporal patterns — refusal-then-pressure, position-reversal,
        # accumulation-of-payload — that single-turn prompts can't.
        text = str(prompt.get("text", "") or "")
        turns_raw = prompt.get("turns")
        if turns_raw is not None:
            if not isinstance(turns_raw, list) or not turns_raw:
                raise ValueError(
                    f"prompt {pid!r} turns must be a non-empty list when present"
                )
            for turn_index, turn in enumerate(turns_raw, start=1):
                if not isinstance(turn, dict):
                    raise ValueError(
                        f"prompt {pid!r} turn #{turn_index} must be a mapping"
                    )
                turn_text = str(turn.get("text", "") or "")
                if not turn_text.strip():
                    raise ValueError(
                        f"prompt {pid!r} turn #{turn_index} is missing text"
                    )
                turn_action = turn.get("expected_action")
                turn_actions = turn.get("expected_actions")
                if turn_action is not None and str(turn_action) not in EXPECTED_ACTIONS:
                    allowed = ", ".join(sorted(EXPECTED_ACTIONS))
                    raise ValueError(
                        f"prompt {pid!r} turn #{turn_index} expected_action must be one of: {allowed}"
                    )
                if turn_actions is not None:
                    if not isinstance(turn_actions, list) or not turn_actions:
                        raise ValueError(
                            f"prompt {pid!r} turn #{turn_index} expected_actions must be a non-empty list"
                        )
                    for entry in turn_actions:
                        if str(entry) not in EXPECTED_ACTIONS:
                            allowed = ", ".join(sorted(EXPECTED_ACTIONS))
                            raise ValueError(
                                f"prompt {pid!r} turn #{turn_index} expected_actions entries must be one of: {allowed}"
                            )
                turn_predicates = turn.get("expected_predicates")
                if turn_predicates is not None and not isinstance(turn_predicates, list):
                    raise ValueError(
                        f"prompt {pid!r} turn #{turn_index} expected_predicates must be a list"
                    )
                synthetic = turn.get("synthetic_completion")
                if synthetic is not None and not isinstance(synthetic, str):
                    raise ValueError(
                        f"prompt {pid!r} turn #{turn_index} synthetic_completion must be a string"
                    )
        elif not text.strip():
            raise ValueError(f"prompt {pid!r} must define text or turns")

        # expected_action / expected_actions — either is valid; if both
        # present, expected_actions wins and expected_action must appear
        # in it (so the YAML stays internally consistent).
        action_field = prompt.get("expected_action")
        actions_field = prompt.get("expected_actions")
        if actions_field is None and action_field is None:
            raise ValueError(
                f"prompt {pid!r} must define expected_action or expected_actions"
            )
        if actions_field is not None:
            if not isinstance(actions_field, list) or not actions_field:
                raise ValueError(
                    f"prompt {pid!r} expected_actions must be a non-empty list"
                )
            for item in actions_field:
                if str(item) not in EXPECTED_ACTIONS:
                    allowed = ", ".join(sorted(EXPECTED_ACTIONS))
                    raise ValueError(
                        f"prompt {pid!r} expected_actions entries must be one of: {allowed}"
                    )
            if action_field is not None and str(action_field) not in {str(x) for x in actions_field}:
                raise ValueError(
                    f"prompt {pid!r} expected_action must appear inside expected_actions"
                )
        else:
            if str(action_field) not in EXPECTED_ACTIONS:
                allowed = ", ".join(sorted(EXPECTED_ACTIONS))
                raise ValueError(
                    f"prompt {pid!r} expected_action must be one of: {allowed}"
                )

        expected_predicates = prompt.get("expected_predicates")
        if expected_predicates is not None:
            if not isinstance(expected_predicates, list):
                raise ValueError(
                    f"prompt {pid!r} expected_predicates must be a list of predicate names"
                )
            for entry in expected_predicates:
                if not isinstance(entry, str) or not entry.strip():
                    raise ValueError(
                        f"prompt {pid!r} expected_predicates entries must be non-empty strings"
                    )

        policy_family = prompt.get("policy_family")
        if policy_family is not None and not str(policy_family).strip():
            raise ValueError(f"prompt {pid!r} policy_family must be a non-empty string")

        synthetic = prompt.get("synthetic_completion")
        if synthetic is not None and not isinstance(synthetic, str):
            raise ValueError(
                f"prompt {pid!r} synthetic_completion must be a string when present"
            )

        if not str(prompt.get("category", "") or "").strip():
            raise ValueError(f"prompt {pid!r} is missing category")
    return raw, prompts


def expected_actions_for(prompt: JsonObject) -> list[str]:
    """Return the accepted-verdict set for one prompt."""

    actions = prompt.get("expected_actions")
    if isinstance(actions, list) and actions:
        return [str(item) for item in actions]
    single = prompt.get("expected_action")
    return [str(single)] if single else []


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark provider-spec-derived EnfGuard policies.",
    )
    parser.add_argument("--proxy", default="http://127.0.0.1:9000")
    parser.add_argument("--prompts", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--admin-token",
        default=os.environ.get("ENFGUARD_ADMIN_TOKEN"),
        help="Defaults to $ENFGUARD_ADMIN_TOKEN.",
    )
    parser.add_argument(
        "--provider",
        choices=("openai", "anthropic"),
        default="openai",
        help="Proxy route format to exercise.",
    )
    parser.add_argument(
        "--model",
        default="gpt-4o-mini",
        help="Model id sent to the proxy.",
    )
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--max-tokens", type=int, default=180)
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--startup-timeout", type=float, default=30.0)
    parser.add_argument(
        "--clear-judge-cache",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Clear judge cache before the run.",
    )
    parser.add_argument(
        "--strict-policy-pack",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Fail (instead of warning) if the running proxy's loaded YAML "
            "does not match suite.policy_pack. Default: strict."
        ),
    )
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    if not args.admin_token:
        print("error: ENFGUARD_ADMIN_TOKEN required", file=sys.stderr)
        return 2

    try:
        suite, prompts = load_prompt_suite(Path(args.prompts))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    proxy_url = args.proxy.rstrip("/")
    headers = {"x-admin-token": args.admin_token}
    readiness_error = wait_for_proxy(proxy_url, headers, args.startup_timeout)
    if readiness_error:
        print(readiness_error, file=sys.stderr)
        return 2

    expected_pack = str(suite.get("policy_pack", "") or "").strip()
    pack_warning = check_policy_pack(
        proxy_url=proxy_url,
        headers=headers,
        expected_pack=expected_pack,
        strict=args.strict_policy_pack,
    )
    if pack_warning:
        print(pack_warning, file=sys.stderr)
        if args.strict_policy_pack:
            return 2

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rows: list[JsonObject] = []
    with httpx.Client(headers=headers, timeout=180.0) as client:
        if args.clear_judge_cache:
            response = client.post(f"{proxy_url}/admin/clear_judge_cache")
            raise_for_status(response, "clear judge cache")

        for rep in range(args.repeat):
            for prompt in prompts:
                row = run_prompt(
                    client=client,
                    proxy_url=proxy_url,
                    admin_token=args.admin_token,
                    suite=suite,
                    prompt=prompt,
                    provider=args.provider,
                    model=args.model,
                    temperature=args.temperature,
                    max_tokens=args.max_tokens,
                    rep=rep,
                )
                rows.append(row)
                if not args.quiet:
                    if row["match"] == "true":
                        verdict = "ok"
                    elif row["action_match"] == "true" and row["predicate_match"] == "false":
                        verdict = "WRONG_PRED"
                    else:
                        verdict = "MISMATCH"
                    expected_label = row.get("expected_actions") or row.get("expected_action", "")
                    print(
                        f"{row['prompt_id']:34s} expected={expected_label:24s} "
                        f"observed={row['observed_action']:16s} {verdict:10s} "
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
    proxy_url: str,
    admin_token: str,
    suite: JsonObject,
    prompt: JsonObject,
    provider: str,
    model: str,
    temperature: float,
    max_tokens: int,
    rep: int,
) -> JsonObject:
    pid = str(prompt["id"])
    sid = f"provider-spec-{suite.get('suite', 'suite')}-{rep}-{pid}"

    # Multi-turn: walk the turns sequentially through the same session id,
    # then evaluate prompt-level expected_action(s) / expected_predicates
    # against the FINAL turn's response. Per-turn expected_* fields, when
    # present, also count toward the predicate-match check; we accumulate
    # all fired predicates across the conversation for that.
    turns = prompt.get("turns")
    if isinstance(turns, list) and turns:
        return run_multi_turn(
            client=client,
            proxy_url=proxy_url,
            admin_token=admin_token,
            suite=suite,
            prompt=prompt,
            turns=turns,
            provider=provider,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            rep=rep,
            sid=sid,
        )

    body = request_body(provider, model, str(prompt["text"]), temperature, max_tokens)

    request_headers = {
        "x-admin-token": admin_token,
        "x-session-id": sid,
        "x-provider": provider,
    }
    synthetic = prompt.get("synthetic_completion")
    if isinstance(synthetic, str):
        # Audit/replay mode: skip the upstream chat call and feed this
        # text into outbound enforcement as if the model produced it.
        # Body metadata accepts multiline code blocks; HTTP headers do not.
        inject_synthetic_completion(body, synthetic)

    started = time.monotonic()
    try:
        response = client.post(
            endpoint(proxy_url, provider),
            headers=request_headers,
            json=body,
        )
        total_ms = int((time.monotonic() - started) * 1000)
    except Exception as exc:
        return error_row(suite, prompt, provider, model, rep, sid, str(exc))

    tid = response.headers.get("x-tid", "")
    observed = response.headers.get("x-enforcement-action", "")
    accepted = expected_actions_for(prompt)
    http_status = response.status_code
    trace: JsonObject = {}
    trace_error = ""
    if tid:
        try:
            trace_response = client.get(f"{proxy_url}/trace/{tid}")
            raise_for_status(trace_response, f"read trace {tid}")
            trace = trace_response.json()
        except Exception as exc:
            trace_error = str(exc)

    phases = trace.get("phases") if isinstance(trace.get("phases"), list) else []
    predicate_rows = (
        trace.get("predicate_rows") if isinstance(trace.get("predicate_rows"), list) else []
    )
    inbound = phase(phases, "inbound")
    outbound = phase(phases, "outbound")

    fired_details = fired_predicate_details(predicate_rows)
    verdict_details = verdict_summary(phases)

    expected_predicates = [
        str(item) for item in (prompt.get("expected_predicates") or []) if str(item)
    ]
    fired_set = {str(detail.get("predicate", "")) for detail in fired_details}
    missing_predicates = [name for name in expected_predicates if name not in fired_set]
    action_match = observed in accepted
    predicate_match = not missing_predicates  # vacuous if none expected
    overall_match = action_match and predicate_match

    return {
        "suite": str(suite.get("suite", "")),
        "policy_pack": str(suite.get("policy_pack", "")),
        "provider": provider,
        "model": model,
        "prompt_id": pid,
        "rep": rep,
        "category": str(prompt.get("category", "")),
        "policy_family": str(prompt.get("policy_family", "")),
        # ``expected_action`` is kept for backward compatibility with old
        # CSV consumers; ``expected_actions`` carries the full set.
        "expected_action": accepted[0] if accepted else "",
        "expected_actions": ";".join(accepted),
        "expected_predicates": ";".join(expected_predicates),
        "missing_predicates": ";".join(missing_predicates),
        "observed_action": observed,
        "match": str(overall_match).lower(),
        "action_match": str(action_match).lower(),
        "predicate_match": str(predicate_match).lower(),
        "http_status": http_status,
        "tid": tid,
        "total_ms": total_ms,
        "inbound_action": str(inbound.get("action", "")),
        "outbound_action": str(outbound.get("action", "")),
        "judge_ms": combined_phase_ms(inbound, outbound, "judge_ms"),
        "inbound_judge_ms": phase_ms(inbound, "judge_ms"),
        "outbound_judge_ms": phase_ms(outbound, "judge_ms"),
        "enfguard_ms": combined_phase_ms(inbound, outbound, "enfguard_ms"),
        "inbound_enfguard_ms": phase_ms(inbound, "enfguard_ms"),
        "outbound_enfguard_ms": phase_ms(outbound, "enfguard_ms"),
        "upstream_ms": combined_phase_ms(inbound, outbound, "upstream_ms"),
        "inbound_upstream_ms": phase_ms(inbound, "upstream_ms"),
        "outbound_upstream_ms": phase_ms(outbound, "upstream_ms"),
        "inbound_predicate_count": int(inbound.get("predicate_count", 0) or 0),
        "outbound_predicate_count": int(outbound.get("predicate_count", 0) or 0),
        "inbound_fired": fired_names(inbound),
        "outbound_fired": fired_names(outbound),
        "fired_details_json": json.dumps(fired_details, ensure_ascii=False, sort_keys=True),
        "verdict_details_json": json.dumps(verdict_details, ensure_ascii=False, sort_keys=True),
        "trace_error": trace_error,
        "notes": str(prompt.get("notes", "")),
    }


def request_body(
    provider: str,
    model: str,
    text: str,
    temperature: float,
    max_tokens: int,
    history: list[JsonObject] | None = None,
) -> JsonObject:
    """Build a chat-completion request body, optionally with prior turns.

    ``history`` is a list of ``{"role": ..., "content": ...}`` messages
    representing earlier conversation turns. The current user message is
    appended at the end so the proxy and any downstream model see the
    full conversation. Multi-turn temporal predicates rely on the proxy
    seeing the full history (earlier UserMessage / AssistantHistory
    events for the same ``sid``).
    """

    messages = list(history or [])
    messages.append({"role": "user", "content": text})
    if provider == "anthropic":
        return {
            "model": model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": messages,
        }
    return {
        "model": model,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "messages": messages,
    }


def inject_synthetic_completion(body: JsonObject, synthetic: str) -> None:
    """Attach a synthetic completion in body metadata for proxy replay mode."""

    metadata = body.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
        body["metadata"] = metadata
    metadata["synthetic_completion"] = synthetic


def run_multi_turn(
    *,
    client: httpx.Client,
    proxy_url: str,
    admin_token: str,
    suite: JsonObject,
    prompt: JsonObject,
    turns: list[JsonObject],
    provider: str,
    model: str,
    temperature: float,
    max_tokens: int,
    rep: int,
    sid: str,
) -> JsonObject:
    """Send a sequence of turns through one session and grade the final turn.

    Conversation policy: every turn shares the same ``sid`` (so the proxy
    sees the same session and emits AssistantHistory / Turn events in
    order); the message history is rebuilt client-side and re-sent on
    every turn (the proxy currently expects stateless requests). Per-turn
    expected_action / expected_predicates fields, when present, are
    additionally checked along the way; the prompt-level
    expected_action(s) / expected_predicates fields apply to the FINAL
    turn's response. ``fired_details_json`` carries every predicate that
    fired across the whole conversation.
    """

    pid = str(prompt["id"])
    cumulative_fired: list[JsonObject] = []
    turn_logs: list[JsonObject] = []
    history: list[JsonObject] = []
    final_response: dict[str, Any] = {}
    final_trace: JsonObject = {}
    final_total_ms = 0
    final_tid = ""
    final_observed = ""
    final_http = 0
    overall_started = time.monotonic()
    cumulative_ms = {
        "inbound_judge_ms": 0,
        "outbound_judge_ms": 0,
        "inbound_enfguard_ms": 0,
        "outbound_enfguard_ms": 0,
        "inbound_upstream_ms": 0,
        "outbound_upstream_ms": 0,
    }

    for turn_index, turn in enumerate(turns, start=1):
        turn_text = str(turn.get("text", "") or "")
        body = request_body(provider, model, turn_text, temperature, max_tokens, history)

        request_headers = {
            "x-admin-token": admin_token,
            "x-session-id": sid,
            "x-provider": provider,
        }
        synthetic = turn.get("synthetic_completion")
        if isinstance(synthetic, str):
            inject_synthetic_completion(body, synthetic)

        started = time.monotonic()
        try:
            response = client.post(
                endpoint(proxy_url, provider),
                headers=request_headers,
                json=body,
            )
            turn_total_ms = int((time.monotonic() - started) * 1000)
        except Exception as exc:
            return error_row(
                suite, prompt, provider, model, rep, sid, f"turn {turn_index}: {exc}"
            )

        tid = response.headers.get("x-tid", "")
        observed = response.headers.get("x-enforcement-action", "")
        http_status = response.status_code

        trace: JsonObject = {}
        trace_error = ""
        if tid:
            try:
                trace_response = client.get(f"{proxy_url}/trace/{tid}")
                raise_for_status(trace_response, f"read trace {tid}")
                trace = trace_response.json()
            except Exception as exc:
                trace_error = str(exc)

        predicate_rows = (
            trace.get("predicate_rows") if isinstance(trace.get("predicate_rows"), list) else []
        )
        phases = trace.get("phases") if isinstance(trace.get("phases"), list) else []
        inbound = phase(phases, "inbound")
        outbound = phase(phases, "outbound")
        turn_metrics = {
            "inbound_judge_ms": phase_ms(inbound, "judge_ms"),
            "outbound_judge_ms": phase_ms(outbound, "judge_ms"),
            "inbound_enfguard_ms": phase_ms(inbound, "enfguard_ms"),
            "outbound_enfguard_ms": phase_ms(outbound, "enfguard_ms"),
            "inbound_upstream_ms": phase_ms(inbound, "upstream_ms"),
            "outbound_upstream_ms": phase_ms(outbound, "upstream_ms"),
        }
        for key, value in turn_metrics.items():
            cumulative_ms[key] += value
        fired_this_turn = fired_predicate_details(predicate_rows)
        cumulative_fired.extend(
            {**detail, "turn_index": turn_index} for detail in fired_this_turn
        )

        # Per-turn assertion (optional): does this turn match what the
        # author said it should? We capture the result for diagnostics
        # but don't short-circuit the conversation.
        turn_accepted = expected_actions_for(turn) or []
        turn_action_match = (not turn_accepted) or (observed in turn_accepted)
        turn_logs.append(
            {
                "turn": turn_index,
                "tid": tid,
                "observed_action": observed,
                "expected_actions": ";".join(turn_accepted),
                "action_match": turn_action_match,
                "trace_error": trace_error,
                "total_ms": turn_total_ms,
                **turn_metrics,
            }
        )

        # Try to parse the assistant's response so we can rebuild the
        # conversation history for the next turn. If enforcement blocked
        # the request the response body still carries the synthetic
        # blocked-message, which is what the proxy would have shown the
        # downstream model on a real chat. We feed that back so multi-
        # turn temporal predicates still see a coherent transcript.
        try:
            response_json = response.json()
        except ValueError:
            response_json = {}
        assistant_text = _extract_assistant_text(response_json, provider)
        history.append({"role": "user", "content": turn_text})
        history.append({"role": "assistant", "content": assistant_text})

        final_response = response_json
        final_trace = trace
        final_total_ms = turn_total_ms
        final_tid = tid
        final_observed = observed
        final_http = http_status

        if observed in {"request_blocked", "response_blocked"}:
            # Stop the conversation early: the proxy refused, so the
            # next turn would be acting on a counterfactual transcript.
            # Pad the remaining turns into the log as 'skipped' entries
            # so the row makes sense.
            for skipped_index in range(turn_index + 1, len(turns) + 1):
                turn_logs.append(
                    {
                        "turn": skipped_index,
                        "tid": "",
                        "observed_action": "skipped_after_block",
                        "expected_actions": "",
                        "action_match": False,
                        "trace_error": "",
                        "total_ms": 0,
                    }
                )
            break

    overall_total_ms = int((time.monotonic() - overall_started) * 1000)

    accepted = expected_actions_for(prompt)
    expected_predicates = [
        str(item) for item in (prompt.get("expected_predicates") or []) if str(item)
    ]
    fired_set = {str(detail.get("predicate", "")) for detail in cumulative_fired}
    missing_predicates = [name for name in expected_predicates if name not in fired_set]
    action_match = (not accepted) or (final_observed in accepted)
    predicate_match = not missing_predicates
    overall_match = action_match and predicate_match

    phases = final_trace.get("phases") if isinstance(final_trace.get("phases"), list) else []
    inbound = phase(phases, "inbound")
    outbound = phase(phases, "outbound")
    verdict_details = verdict_summary(phases)

    return {
        "suite": str(suite.get("suite", "")),
        "policy_pack": str(suite.get("policy_pack", "")),
        "provider": provider,
        "model": model,
        "prompt_id": pid,
        "rep": rep,
        "category": str(prompt.get("category", "")),
        "policy_family": str(prompt.get("policy_family", "")),
        "expected_action": accepted[0] if accepted else "",
        "expected_actions": ";".join(accepted),
        "expected_predicates": ";".join(expected_predicates),
        "missing_predicates": ";".join(missing_predicates),
        "observed_action": final_observed,
        "match": str(overall_match).lower(),
        "action_match": str(action_match).lower(),
        "predicate_match": str(predicate_match).lower(),
        "http_status": final_http,
        "tid": final_tid,
        "total_ms": overall_total_ms,
        "inbound_action": str(inbound.get("action", "")),
        "outbound_action": str(outbound.get("action", "")),
        "judge_ms": cumulative_ms["inbound_judge_ms"] + cumulative_ms["outbound_judge_ms"],
        "inbound_judge_ms": cumulative_ms["inbound_judge_ms"],
        "outbound_judge_ms": cumulative_ms["outbound_judge_ms"],
        "enfguard_ms": cumulative_ms["inbound_enfguard_ms"] + cumulative_ms["outbound_enfguard_ms"],
        "inbound_enfguard_ms": cumulative_ms["inbound_enfguard_ms"],
        "outbound_enfguard_ms": cumulative_ms["outbound_enfguard_ms"],
        "upstream_ms": cumulative_ms["inbound_upstream_ms"] + cumulative_ms["outbound_upstream_ms"],
        "inbound_upstream_ms": cumulative_ms["inbound_upstream_ms"],
        "outbound_upstream_ms": cumulative_ms["outbound_upstream_ms"],
        "inbound_predicate_count": int(inbound.get("predicate_count", 0) or 0),
        "outbound_predicate_count": int(outbound.get("predicate_count", 0) or 0),
        "inbound_fired": fired_names(inbound),
        "outbound_fired": fired_names(outbound),
        "fired_details_json": json.dumps(cumulative_fired, ensure_ascii=False, sort_keys=True),
        "verdict_details_json": json.dumps(verdict_details, ensure_ascii=False, sort_keys=True),
        "trace_error": "",
        "notes": str(prompt.get("notes", "")) + f"; turns={len(turns)}; "
        + f"per_turn={json.dumps(turn_logs, ensure_ascii=False)}",
    }


def _extract_assistant_text(response_json: JsonObject, provider: str) -> str:
    """Pull the assistant's reply text from a chat-completion JSON body.

    Best-effort: returns "" when the body has been replaced with an
    enforcement-block synthetic message (those carry their own text in
    the same field, so they round-trip into history naturally) or when
    the response shape is unfamiliar.
    """

    if not isinstance(response_json, dict):
        return ""
    if provider == "anthropic":
        for block in response_json.get("content", []) or []:
            if isinstance(block, dict) and block.get("type") == "text":
                return str(block.get("text", "") or "")
        return ""
    choices = response_json.get("choices")
    if isinstance(choices, list) and choices:
        message = choices[0].get("message") if isinstance(choices[0], dict) else None
        if isinstance(message, dict):
            return str(message.get("content", "") or "")
    return ""


def endpoint(proxy_url: str, provider: str) -> str:
    if provider == "anthropic":
        return f"{proxy_url}/v1/messages"
    return f"{proxy_url}/v1/chat/completions"


def phase(phases: list[JsonObject], name: str) -> JsonObject:
    return next((item for item in phases if item.get("phase") == name), {})


def phase_ms(phase_summary: JsonObject, key: str) -> int:
    return int(phase_summary.get(key, 0) or 0)


def combined_phase_ms(inbound: JsonObject, outbound: JsonObject, key: str) -> int:
    return phase_ms(inbound, key) + phase_ms(outbound, key)


def fired_names(phase_summary: JsonObject) -> str:
    return ";".join(
        str(item.get("predicate", "") or "")
        for item in phase_summary.get("fired_predicates") or []
        if isinstance(item, dict)
    )


def fired_predicate_details(predicate_rows: list[JsonObject]) -> list[JsonObject]:
    details: list[JsonObject] = []
    for row in predicate_rows:
        try:
            score = float(row.get("score", 0.0) or 0.0)
        except (TypeError, ValueError):
            score = 0.0
        if score < 0.5:
            continue
        details.append(
            {
                "phase": str(row.get("phase", "") or ""),
                "predicate": str(row.get("predicate", "") or ""),
                "score": score,
                "raw_score": row.get("raw_score", ""),
                "reason": str(row.get("reason", "") or ""),
                "latency_ms": int(row.get("latency_ms", 0) or 0),
                "cache_hit": bool(row.get("cache_hit", False)),
                "batch_id": str(row.get("batch_id", "") or ""),
            }
        )
    return details


def verdict_summary(phases: list[JsonObject]) -> list[JsonObject]:
    out: list[JsonObject] = []
    for item in phases:
        verdicts = item.get("verdicts")
        out.append(
            {
                "phase": str(item.get("phase", "") or ""),
                "action": str(item.get("action", "") or ""),
                "verdicts": verdicts if isinstance(verdicts, list) else [],
            }
        )
    return out


def write_csv(path: Path, rows: list[JsonObject]) -> None:
    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def print_summary(rows: list[JsonObject], output_path: Path) -> None:
    total = len(rows)
    matches = sum(1 for row in rows if row.get("match") == "true")
    action_matches = sum(1 for row in rows if row.get("action_match") == "true")
    pred_required = sum(1 for row in rows if row.get("expected_predicates"))
    pred_matches = sum(
        1
        for row in rows
        if row.get("expected_predicates") and row.get("predicate_match") == "true"
    )
    latency_values = [int(row.get("total_ms", 0) or 0) for row in rows]
    median_ms = int(statistics.median(latency_values)) if latency_values else 0
    judge_values = [int(row.get("judge_ms", 0) or 0) for row in rows]
    enfguard_values = [int(row.get("enfguard_ms", 0) or 0) for row in rows]
    upstream_values = [int(row.get("upstream_ms", 0) or 0) for row in rows]
    median_judge_ms = int(statistics.median(judge_values)) if judge_values else 0
    median_enfguard_ms = int(statistics.median(enfguard_values)) if enfguard_values else 0
    median_upstream_ms = int(statistics.median(upstream_values)) if upstream_values else 0

    print(f"\nwrote {total} rows -> {output_path}")
    print(f"overall matches: {matches}/{total} ({matches / total:.1%})")
    print(
        f"  verdict matches: {action_matches}/{total} ({action_matches / total:.1%})"
    )
    if pred_required:
        print(
            f"  fired-the-right-predicate: {pred_matches}/{pred_required} "
            f"({pred_matches / pred_required:.1%}) of prompts that demand a specific predicate"
        )
    print(f"median total latency: {median_ms}ms")
    print(
        "median latency split: "
        f"judge={median_judge_ms}ms, "
        f"enfguard={median_enfguard_ms}ms, "
        f"upstream={median_upstream_ms}ms"
    )

    by_category: dict[str, list[JsonObject]] = {}
    for row in rows:
        by_category.setdefault(str(row.get("category", "")), []).append(row)
    print("\ncategory summary:")
    for category, category_rows in sorted(by_category.items()):
        ok = sum(1 for row in category_rows if row.get("match") == "true")
        verdict_ok = sum(1 for row in category_rows if row.get("action_match") == "true")
        print(
            f"  {category:32s} overall={ok:3d}/{len(category_rows):3d}  "
            f"verdict={verdict_ok:3d}/{len(category_rows):3d}"
        )

    by_family: dict[str, list[JsonObject]] = {}
    for row in rows:
        family = str(row.get("policy_family", "") or "")
        if family:
            by_family.setdefault(family, []).append(row)
    if by_family:
        print("\npolicy-family summary:")
        for family, family_rows in sorted(by_family.items()):
            ok = sum(1 for row in family_rows if row.get("match") == "true")
            verdict_ok = sum(1 for row in family_rows if row.get("action_match") == "true")
            print(
                f"  {family:12s} overall={ok:3d}/{len(family_rows):3d}  "
                f"verdict={verdict_ok:3d}/{len(family_rows):3d}"
            )


def error_row(
    suite: JsonObject,
    prompt: JsonObject,
    provider: str,
    model: str,
    rep: int,
    sid: str,
    error: str,
) -> JsonObject:
    accepted = expected_actions_for(prompt)
    expected_predicates = [
        str(item) for item in (prompt.get("expected_predicates") or []) if str(item)
    ]
    return {
        "suite": str(suite.get("suite", "")),
        "policy_pack": str(suite.get("policy_pack", "")),
        "provider": provider,
        "model": model,
        "prompt_id": str(prompt.get("id", "")),
        "rep": rep,
        "category": str(prompt.get("category", "")),
        "policy_family": str(prompt.get("policy_family", "")),
        "expected_action": accepted[0] if accepted else "",
        "expected_actions": ";".join(accepted),
        "expected_predicates": ";".join(expected_predicates),
        "missing_predicates": ";".join(expected_predicates),
        "observed_action": f"error: {error}",
        "match": "false",
        "action_match": "false",
        "predicate_match": "false",
        "http_status": 0,
        "tid": "",
        "total_ms": 0,
        "inbound_action": "",
        "outbound_action": "",
        "judge_ms": 0,
        "inbound_judge_ms": 0,
        "outbound_judge_ms": 0,
        "enfguard_ms": 0,
        "inbound_enfguard_ms": 0,
        "outbound_enfguard_ms": 0,
        "upstream_ms": 0,
        "inbound_upstream_ms": 0,
        "outbound_upstream_ms": 0,
        "inbound_predicate_count": 0,
        "outbound_predicate_count": 0,
        "inbound_fired": "",
        "outbound_fired": "",
        "fired_details_json": "[]",
        "verdict_details_json": "[]",
        "trace_error": "",
        "notes": f"sid={sid}; {prompt.get('notes', '')}",
    }


def check_policy_pack(
    *,
    proxy_url: str,
    headers: dict[str, str],
    expected_pack: str,
    strict: bool,
) -> str:
    """Compare the proxy's loaded YAML to ``suite.policy_pack``.

    Returns "" when the two paths point at the same file. Returns a
    non-empty warning string otherwise — the caller decides whether to
    just print it (``--no-strict-policy-pack``) or also exit.

    ``policy_pack`` is interpreted as a path relative to the proxy's
    EnfGuardV2 root when it isn't absolute. A bench prompt suite that
    leaves ``policy_pack`` empty disables the check (and emits a
    soft warning so the operator notices).
    """

    if not expected_pack:
        return (
            "warning: prompt suite has empty policy_pack; cannot verify proxy "
            "loaded the right YAML."
        )
    try:
        with httpx.Client(headers=headers, timeout=5.0) as client:
            response = client.get(f"{proxy_url}/health")
            response.raise_for_status()
            payload = response.json()
    except Exception as exc:
        return f"warning: could not read /health to verify policy_pack: {exc}"

    loaded_raw = str(payload.get("yaml_file", "") or "")
    if not loaded_raw:
        return (
            "warning: proxy /health did not include yaml_file. Update the proxy "
            "or rerun with --no-strict-policy-pack."
        )

    loaded = Path(loaded_raw).resolve()
    expected = Path(expected_pack)
    if not expected.is_absolute():
        # Resolve relative to the loaded file's parent — the proxy boots
        # with cwd at code/EnfGuardV2/, and policy_pack is conventionally
        # written ``examples/<name>.yaml`` from that cwd.
        candidate = (loaded.parent.parent / expected).resolve()
        if not candidate.exists():
            candidate = (Path.cwd() / expected).resolve()
    else:
        candidate = expected.resolve()

    try:
        if loaded.samefile(candidate):
            return ""
    except OSError:
        pass

    severity = "error" if strict else "warning"
    return (
        f"{severity}: proxy is running with yaml_file={loaded}, but the prompt "
        f"suite expects policy_pack={expected_pack} (resolved to {candidate}). "
        "Re-run the proxy with the matching ENFGUARD_YAML or pass "
        "--no-strict-policy-pack to override."
    )


def wait_for_proxy(proxy_url: str, headers: dict[str, str], startup_timeout: float) -> str:
    deadline = time.monotonic() + max(0.0, startup_timeout)
    last_error = ""
    with httpx.Client(headers=headers, timeout=5.0) as client:
        while True:
            try:
                client.get(f"{proxy_url}/health").raise_for_status()
                return ""
            except Exception as exc:
                last_error = str(exc)
                if time.monotonic() >= deadline:
                    return f"error: proxy not reachable at {proxy_url}: {last_error}"
                time.sleep(0.25)


def raise_for_status(response: httpx.Response, action: str) -> None:
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        detail = response.text.strip()
        raise RuntimeError(
            f"failed to {action}: HTTP {response.status_code}: {detail}"
        ) from exc


if __name__ == "__main__":
    sys.exit(main())
