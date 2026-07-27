import pytest

from mappings import extract_inbound_events, extract_outbound_events


def _event_args(events, name):
    return [event.args for event in events if event.name == name]


def test_openai_format_keeps_provider_as_metadata():
    request = {
        "model": "llama3",
        "messages": [{"role": "user", "content": "hello"}],
    }

    events = extract_inbound_events(
        tid=1,
        request=request,
        api_format="openai",
        sid="s-test",
        provider="ollama",
    )

    assert _event_args(events, "Message") == [(1, "user", "hello", 1)]
    assert _event_args(events, "ModelSelection") == [(1, "ollama", "llama3")]


def test_provider_name_is_not_an_api_format():
    request = {
        "model": "llama3",
        "messages": [{"role": "user", "content": "hello"}],
    }

    with pytest.raises(ValueError, match="Unsupported api_format"):
        extract_inbound_events(
            tid=1,
            request=request,
            api_format="ollama",
            sid="s-test",
            provider="ollama",
        )


def test_openai_endpoint_alias_falls_back_to_openai_provider():
    request = {
        "model": "gpt-test",
        "messages": [{"role": "user", "content": "hello"}],
    }

    events = extract_inbound_events(
        tid=1,
        request=request,
        api_format="/v1/chat/completions",
        sid="s-test",
    )

    assert _event_args(events, "ModelSelection") == [(1, "openai", "gpt-test")]


def test_anthropic_text_blocks_and_cache_usage_are_observed():
    request = {
        "model": "claude-test",
        "system": [{"type": "text", "text": "be brief"}],
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "document",
                        "source": {"type": "text", "data": "doc text"},
                    },
                    {
                        "type": "search_result",
                        "content": [{"type": "text", "text": "search text"}],
                    },
                    {"type": "text", "text": "question"},
                ],
            }
        ],
    }
    response = {
        "content": [{"type": "text", "text": "answer"}],
        "usage": {
            "input_tokens": 10,
            "cache_creation_input_tokens": 2,
            "cache_read_input_tokens": 3,
            "output_tokens": 4,
        },
    }

    inbound = extract_inbound_events(2, request, "anthropic", "s-test")
    outbound = extract_outbound_events(
        2,
        request,
        response,
        "anthropic",
        active_policies=["outbound_block_emoji"],
    )

    # v4 unified Message event with role argument.
    system_msgs = [args for args in _event_args(inbound, "Message") if args[1] == "system"]
    user_msgs = [args for args in _event_args(inbound, "Message") if args[1] == "user"]
    assert system_msgs == [(2, "system", "be brief", 2)]
    assert user_msgs == [(2, "user", "doc text\nsearch text\nquestion", 7)]
    assert _event_args(outbound, "PolicyActive") == [(2, "outbound_block_emoji")]
    assert _event_args(outbound, "Completion") == [(2, "answer", 4)]
    # v4 drops TokenUsage from the formal stream.
    assert _event_args(outbound, "TokenUsage") == []


def test_anthropic_tool_use_blocks_are_mapped_to_semantic_events():
    request = {"model": "claude-test", "messages": [{"role": "user", "content": "clean temp"}]}
    response = {
        "content": [
            {
                "type": "tool_use",
                "id": "toolu_01",
                "name": "bash",
                "input": {"command": "rm -rf /tmp/demo"},
            }
        ],
        "usage": {"input_tokens": 12, "output_tokens": 6},
    }

    events = extract_outbound_events(3, request, response, "anthropic")

    # v4 emits one ToolCall(tid, call_id, canonical_tool_name, input_preview).
    # Since the classify-first vocabulary expansion (2026-05-30) every call also
    # emits tool_family + tool_name, so assert the dominant risk dimension is
    # PRESENT rather than the only Classify fact.
    assert _event_args(events, "ToolCall") == [
        (3, "toolu_01", "bash", '{"command": "rm -rf /tmp/demo"}')
    ]
    assert (3, "toolu_01", "command_risk", "critical") in _event_args(events, "Classify")
    assert _event_args(events, "Completion") == [(3, "", 6)]


def test_openai_tool_calls_are_mapped_to_semantic_events():
    request = {"model": "gpt-test", "messages": [{"role": "user", "content": "read env"}]}
    response = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_123",
                            "type": "function",
                            "function": {
                                "name": "read_file",
                                "arguments": '{"path": "/home/user/project/.env"}',
                            },
                        }
                    ],
                }
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 3, "total_tokens": 13},
    }

    events = extract_outbound_events(4, request, response, "openai")

    # v4 carries the path-classification dimension on a Classify event. Since the
    # classify-first vocabulary expansion (2026-05-30) a credential file_read also
    # emits tool_family/tool_name and action_class=credential_access, so assert the
    # path-sensitivity fact is PRESENT rather than the only Classify fact.
    assert _event_args(events, "ToolCall") == [
        (4, "call_123", "file_read", '{"path": "/home/user/project/.env"}')
    ]
    assert (4, "call_123", "path_sensitivity", "credentials") in _event_args(events, "Classify")
    # v4 drops TokenUsage from the formal stream.
    assert _event_args(events, "TokenUsage") == []


def test_inbound_tool_results_are_observed_for_anthropic_and_openai():
    anthropic_request = {
        "model": "claude-test",
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "toolu_01",
                        "content": [{"type": "text", "text": "file contents\nline two"}],
                    }
                ],
            }
        ],
    }
    openai_request = {
        "model": "gpt-test",
        "messages": [
            {
                "role": "tool",
                "tool_call_id": "call_123",
                "content": "command output\nline two",
            }
        ],
    }

    anthropic_events = extract_inbound_events(5, anthropic_request, "anthropic", "s-test")
    openai_events = extract_inbound_events(6, openai_request, "openai", "s-test")

    # v4: ToolResult(tid, call_id, content, exit_code).
    # Anthropic carries is_error -> 0/1 exit code.
    # OpenAI has no error field; the proxy infers 0 (success) or 1 (error)
    # from content prefixes via _infer_openai_exit_code.
    # "command output\nline two" has no error prefix → exit_code 0.
    assert _event_args(anthropic_events, "ToolResult") == [
        (5, "toolu_01", "file contents line two", 0)
    ]
    assert _event_args(openai_events, "ToolResult") == [
        (6, "call_123", "command output line two", 0)
    ]
    # By default every ToolResult is paired with Untrusted because the
    # proposing tool name cannot be resolved without state from a prior call.
    assert _event_args(anthropic_events, "Untrusted") == [(5, "tool_result")]
    assert _event_args(openai_events, "Untrusted") == [(6, "tool_result")]


def test_tool_results_from_trusted_tools_omit_untrusted():
    """A ToolCallResult whose proposing tool is on the trust allowlist
    must NOT be paired with an Untrusted event."""

    request = {
        "model": "claude-test",
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "toolu_safe",
                        "content": [{"type": "text", "text": "1 + 1 = 2"}],
                    }
                ],
            }
        ],
    }

    events = extract_inbound_events(
        tid=7,
        request=request,
        api_format="anthropic",
        sid="s-test",
        proposing_tool_for_call_id={"toolu_safe": "internal_calculator"},
        trusted_tool_names=("internal_calculator",),
    )

    assert _event_args(events, "ToolResult") == [(7, "toolu_safe", "1 + 1 = 2", 0)]
    assert _event_args(events, "Untrusted") == []


def test_tool_results_from_unlisted_tools_are_untrusted():
    """A ToolCallResult whose proposing tool is known but NOT in the trust
    allowlist must still be tagged Untrusted."""

    request = {
        "model": "gpt-test",
        "messages": [
            {
                "role": "tool",
                "tool_call_id": "call_web",
                "content": "fetched page contents",
            }
        ],
    }

    events = extract_inbound_events(
        tid=8,
        request=request,
        api_format="openai",
        sid="s-test",
        proposing_tool_for_call_id={"call_web": "web_fetch"},
        trusted_tool_names=("internal_calculator",),
    )

    # "fetched page contents" has no error prefix → inferred exit_code 0.
    assert _event_args(events, "ToolResult") == [
        (8, "call_web", "fetched page contents", 0)
    ]
    assert _event_args(events, "Untrusted") == [(8, "tool_result")]


def test_openai_tool_result_error_prefix_sets_exit_code_1():
    """OpenAI tool results whose content starts with a known error prefix
    should be inferred as exit_code=1 so MFOTL policies can match failures."""

    error_contents = [
        "Error: file not found",
        "Exception: timeout exceeded",
        "Traceback (most recent call last):\n  ...",
        "Failed: connection refused",
        "PermissionError: denied",
    ]
    for content in error_contents:
        request = {
            "model": "gpt-test",
            "messages": [{"role": "tool", "tool_call_id": "call_err", "content": content}],
        }
        events = extract_inbound_events(9, request, "openai", "s-test")
        tool_results = _event_args(events, "ToolResult")
        assert len(tool_results) == 1
        exit_code = tool_results[0][3]
        assert exit_code == 1, f"Expected exit_code=1 for content {content!r}, got {exit_code}"


def test_openai_tool_result_normal_content_keeps_exit_code_0():
    """OpenAI tool results with no error prefix should have exit_code=0."""

    request = {
        "model": "gpt-test",
        "messages": [{"role": "tool", "tool_call_id": "call_ok", "content": "42"}],
    }
    events = extract_inbound_events(10, request, "openai", "s-test")
    assert _event_args(events, "ToolResult") == [(10, "call_ok", "42", 0)]


def test_blocked_call_denial_echo_not_reingested_anthropic():
    """The echo of EnfGuard's own block reason for an already-blocked call must
    record ToolResult but NOT be re-ingested as Untrusted/content-risk content."""
    request = {
        "model": "claude-test",
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "call_blocked",
                        "is_error": True,
                        "content": "dangerous action follows a risk-flagged untrusted tool result in session",
                    }
                ],
            }
        ],
    }
    events = extract_inbound_events(
        tid=20, request=request, api_format="anthropic", sid="s-test",
        proposing_tool_for_call_id={"call_blocked": "bash"},
        blocked_call_ids=("call_blocked",),
    )
    assert _event_args(events, "ToolResult") == [
        (20, "call_blocked", "dangerous action follows a risk-flagged untrusted tool result in session", 1)
    ]
    assert _event_args(events, "Untrusted") == []
    assert _event_args(events, "Classify") == []


def test_blocked_call_denial_echo_not_reingested_openai():
    request = {
        "model": "gpt-test",
        "messages": [
            {"role": "tool", "tool_call_id": "call_blocked",
             "content": "write installs a persistence foothold (keys/sudoers/cron/service/import-hook)"}
        ],
    }
    events = extract_inbound_events(
        tid=21, request=request, api_format="openai", sid="s-test",
        proposing_tool_for_call_id={"call_blocked": "bash"},
        blocked_call_ids=("call_blocked",),
    )
    assert _event_args(events, "Untrusted") == []
    assert _event_args(events, "Classify") == []
    # control: same result NOT in the blocked set is still tagged Untrusted
    events2 = extract_inbound_events(
        tid=22, request=request, api_format="openai", sid="s-test",
        proposing_tool_for_call_id={"call_blocked": "bash"},
    )
    assert _event_args(events2, "Untrusted") == [(22, "tool_result")]
