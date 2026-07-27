from handlers import (
    handle_block_response,
    handle_warn_response,
    normalize_anthropic,
    normalize_openai,
    serialize_anthropic,
    serialize_openai,
    surface_warning_on_block,
    synthetic_anthropic,
    synthetic_openai,
)


def test_openai_block_response_replaces_all_choices():
    raw = {
        "choices": [
            {"message": {"role": "assistant", "content": "first"}, "finish_reason": "stop"},
            {"message": {"role": "assistant", "content": "second"}, "finish_reason": "stop"},
        ],
        "usage": {"prompt_tokens": 2, "completion_tokens": 4, "total_tokens": 6},
    }

    response = normalize_openai(raw)
    response = handle_block_response(response, [(1, "safety", "not allowed")])
    out = serialize_openai(response)

    assert out["choices"][0]["message"]["content"] == response.block_reason
    assert out["choices"][1]["message"]["content"] == response.block_reason
    assert all(choice["finish_reason"] == "stop" for choice in out["choices"])


def test_openai_warning_is_prepended_to_each_choice():
    raw = {
        "choices": [
            {"message": {"role": "assistant", "content": "first"}, "finish_reason": "stop"},
            {"message": {"role": "assistant", "content": "second"}, "finish_reason": "stop"},
        ],
    }

    response = normalize_openai(raw)
    response = handle_warn_response(response, [(1, "token_budget", "too long")])
    out = serialize_openai(response)

    assert out["choices"][0]["message"]["content"].endswith("\n\nfirst")
    assert out["choices"][1]["message"]["content"].endswith("\n\nsecond")
    assert out["choices"][0]["message"]["content"].startswith("Policy warning")


def test_anthropic_normalization_counts_cache_tokens():
    raw = {
        "content": [{"type": "text", "text": "answer"}],
        "usage": {
            "input_tokens": 10,
            "cache_creation_input_tokens": 2,
            "cache_read_input_tokens": 3,
            "output_tokens": 4,
        },
    }

    response = normalize_anthropic(raw)

    assert response.content == "answer"
    assert response.prompt_tokens == 15
    assert response.completion_tokens == 4
    assert response.total_tokens == 19


def test_anthropic_warning_inserts_text_block_when_needed():
    raw = {
        "content": [{"type": "tool_use", "id": "call_1", "name": "x", "input": {}}],
        "usage": {"input_tokens": 1, "output_tokens": 1},
    }

    response = normalize_anthropic(raw)
    response = handle_warn_response(response, [(1, "safety", "careful")])
    out = serialize_anthropic(response)

    assert out["content"][0]["type"] == "text"
    assert out["content"][0]["text"].startswith("Policy warning")
    assert out["content"][1]["type"] == "tool_use"


def test_synthetic_blocked_responses_are_api_shaped():
    anthropic = synthetic_anthropic("blocked")
    openai = synthetic_openai("blocked")

    assert anthropic["content"][0]["text"] == "blocked"
    assert anthropic["role"] == "assistant"
    assert openai["choices"][0]["message"]["content"] == "blocked"
    assert openai["choices"][0]["message"]["role"] == "assistant"


def test_warning_details_stay_visible_when_block_overrides():
    raw = {"choices": [{"message": {"role": "assistant", "content": "first"}}]}

    response = normalize_openai(raw)
    response = handle_block_response(response, [(1, "safety", "not allowed")])
    response = surface_warning_on_block(response, "Policy warning: [token_budget] too long")
    out = serialize_openai(response)

    assert "Response blocked" in response.block_reason
    assert "Also fired" in response.block_reason
    assert "token_budget" in response.block_reason
    assert out["choices"][0]["message"]["content"] == response.block_reason
