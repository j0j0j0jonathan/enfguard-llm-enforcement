"""OpenAI streaming buffer-then-release (2026-07-01).

The proxy previously returned 501 for any streaming OpenAI Chat Completions request
(`_run_streaming_request` only handled Anthropic). OpenClaw streams by default, so
every call got 501 and no response. The proxy now buffers the upstream OpenAI SSE,
reconstructs the full completion, runs outbound enforcement, and releases either the
original stream (allowed) or an EnfGuard replacement (blocked), mirroring the
Anthropic path.

These unit tests cover the two new pure helpers (reconstruct + re-emit). End-to-end
enforcement still needs the running proxy on the Mac.

    python -m pytest tests/test_openai_streaming_2026_07_01.py -q
"""

from __future__ import annotations

import pytest


def _proxy():
    try:
        import proxy
    except Exception:  # pragma: no cover - env without web deps
        pytest.skip("proxy not importable in this environment")
    return proxy


def test_reconstruct_content_across_chunks():
    proxy = _proxy()
    sse = "".join([
        'data: {"id":"c1","object":"chat.completion.chunk","created":123,"model":"gpt-4o-mini",'
        '"choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}\n\n',
        'data: {"id":"c1","choices":[{"index":0,"delta":{"content":"Your SSN "},"finish_reason":null}]}\n\n',
        'data: {"id":"c1","choices":[{"index":0,"delta":{"content":"is 123-45-6789"},"finish_reason":null}]}\n\n',
        'data: {"id":"c1","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n',
        'data: {"id":"c1","usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}\n\n',
        "data: [DONE]\n\n",
    ])
    msg = proxy._openai_stream_to_message(sse, "gpt-4o-mini")
    assert proxy.normalize_openai(msg).content == "Your SSN is 123-45-6789"
    assert msg["choices"][0]["finish_reason"] == "stop"
    assert msg["usage"]["total_tokens"] == 15
    assert msg["model"] == "gpt-4o-mini"


def test_reconstruct_tool_call_arguments():
    proxy = _proxy()
    sse = "".join([
        'data: {"id":"c2","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":'
        '[{"index":0,"id":"call_a","function":{"name":"write_file","arguments":"{\\"path\\":"}}]},'
        '"finish_reason":null}]}\n\n',
        'data: {"id":"c2","choices":[{"index":0,"delta":{"tool_calls":'
        '[{"index":0,"function":{"arguments":"\\"/tmp/x\\"}"}}]},"finish_reason":"tool_calls"}]}\n\n',
        "data: [DONE]\n\n",
    ])
    msg = proxy._openai_stream_to_message(sse, "gpt-4o-mini")
    tc = msg["choices"][0]["message"]["tool_calls"]
    assert tc[0]["id"] == "call_a"
    assert tc[0]["function"]["name"] == "write_file"
    assert tc[0]["function"]["arguments"] == '{"path":"/tmp/x"}'


def test_reemit_is_valid_sse_and_round_trips():
    proxy = _proxy()
    message = {
        "id": "c3",
        "model": "gpt-4o-mini",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "[blocked] privacy"},
                     "finish_reason": "stop"}],
    }
    sse = proxy._openai_message_to_sse(message)
    assert sse.strip().endswith("data: [DONE]")
    assert '"chat.completion.chunk"' in sse
    # a client (or our own reconstructor) can parse it back to the same content
    assert proxy.normalize_openai(proxy._openai_stream_to_message(sse)).content == "[blocked] privacy"


def test_empty_stream_does_not_crash():
    proxy = _proxy()
    msg = proxy._openai_stream_to_message("", "gpt-4o-mini")
    assert msg["choices"][0]["message"]["content"] == ""
