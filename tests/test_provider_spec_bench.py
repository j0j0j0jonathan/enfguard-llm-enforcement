import json
from pathlib import Path

import yaml

from scripts import bench_provider_specs


EXPECTED_ACTIONS = {
    "allowed",
    "request_warned",
    "request_blocked",
    "response_warned",
    "response_blocked",
}


def test_provider_spec_prompt_suites_are_labeled_and_balanced():
    for path in (
        Path("bench/openai_model_spec_prompts.yaml"),
        Path("bench/anthropic_constitution_prompts.yaml"),
    ):
        suite, prompts = bench_provider_specs.load_prompt_suite(path)

        assert suite["policy_pack"].startswith("examples/")
        assert 95 <= len(prompts) <= 150
        assert len({prompt["id"] for prompt in prompts}) == len(prompts)
        assert {prompt["expected_action"] for prompt in prompts} <= EXPECTED_ACTIONS
        assert any(prompt["expected_action"] == "allowed" for prompt in prompts)
        assert any(prompt["expected_action"] == "request_blocked" for prompt in prompts)
        assert any(prompt["expected_action"] == "response_warned" for prompt in prompts)


def test_provider_spec_policy_packs_stay_focused():
    for path in (
        Path("examples/openai_model_spec.yaml"),
        Path("examples/anthropic_constitution.yaml"),
    ):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        policies = raw.get("policies", [])
        predicates = raw.get("predicates", [])

        assert 12 <= len(policies) <= 15
        assert len({policy["id"] for policy in policies}) == len(policies)
        assert len({predicate["name"] for predicate in predicates}) == len(predicates)
        assert raw["switches"][0]["id"] == "enforcement_mode"
        assert raw["switches"][0]["default"] == "enforce"


def test_trace_helpers_extract_fired_predicate_and_verdict_details():
    predicate_rows = [
        {
            "phase": "inbound",
            "predicate": "p_block",
            "score": 1.0,
            "raw_score": 0.92,
            "reason": "matched",
            "latency_ms": 31,
            "cache_hit": False,
            "batch_id": "b1",
        },
        {"phase": "outbound", "predicate": "p_clear", "score": 0.0},
    ]
    phases = [
        {
            "phase": "inbound",
            "action": "request_blocked",
            "verdicts": [{"action": "BlockRequest", "category": "safety"}],
        }
    ]

    fired = bench_provider_specs.fired_predicate_details(predicate_rows)
    verdicts = bench_provider_specs.verdict_summary(phases)

    assert fired == [
        {
            "phase": "inbound",
            "predicate": "p_block",
            "score": 1.0,
            "raw_score": 0.92,
            "reason": "matched",
            "latency_ms": 31,
            "cache_hit": False,
            "batch_id": "b1",
        }
    ]
    assert verdicts == [
        {
            "phase": "inbound",
            "action": "request_blocked",
            "verdicts": [{"action": "BlockRequest", "category": "safety"}],
        }
    ]
    assert json.loads(json.dumps(fired))[0]["predicate"] == "p_block"


def test_latency_helpers_sum_phase_summaries():
    inbound = {"judge_ms": 11, "enfguard_ms": 7, "upstream_ms": 0}
    outbound = {"judge_ms": 13, "enfguard_ms": 5, "upstream_ms": 101}

    assert bench_provider_specs.phase_ms(inbound, "judge_ms") == 11
    assert bench_provider_specs.phase_ms({}, "judge_ms") == 0
    assert bench_provider_specs.combined_phase_ms(inbound, outbound, "judge_ms") == 24
    assert bench_provider_specs.combined_phase_ms(inbound, outbound, "enfguard_ms") == 12
    assert bench_provider_specs.combined_phase_ms(inbound, outbound, "upstream_ms") == 101
