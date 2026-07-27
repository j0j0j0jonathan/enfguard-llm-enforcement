"""Source-based Untrusted tagging: gate provenance on where the result bytes
came from (external network / out-of-workspace read) rather than on the
proposing tool's name. ``trusted_tool_names`` becomes the unknown-origin
fallback only.

See wiki concept [[event-signature]] / the 2026-06-11 log entry.
"""
from instrlib.tool_mapper import classify_result_origin
from mappings import (
    _tool_result_is_untrusted,
    collect_tool_origins,
    extract_inbound_events,
)
from instrlib.event import Event


def _args(events, name):
    return [e.args for e in events if e.name == name]


# --- origin classifier ----------------------------------------------------

def test_origin_external_for_network_and_out_of_workspace():
    assert classify_result_origin("bash", {"command": "curl https://x.com/a"}) == "external"
    assert classify_result_origin("bash", {"command": "cat /etc/passwd"}) == "external"
    assert classify_result_origin("bash", {"command": "cat ../../secret"}) == "external"
    assert classify_result_origin("web_fetch", {"url": "https://x.com"}) == "external"
    assert classify_result_origin("bash", {"command": "ssh host uptime"}) == "external"


def test_origin_local_for_in_workspace_reads_and_compute():
    assert classify_result_origin("bash", {"command": "cat ./notes.txt"}) == "local"
    assert classify_result_origin("bash", {"command": "echo hi"}) == "local"
    assert classify_result_origin("file_read", {"path": "./app/config.py"}) == "local"
    assert classify_result_origin(
        "gateway", {"action": "config.schema.lookup", "path": "agents.defaults"}
    ) == "local"


def test_origin_unknown_for_unrecognised_tool():
    assert classify_result_origin("mystery_tool", {"foo": "bar"}) == "unknown"


# --- trust decision -------------------------------------------------------

def test_external_origin_is_untrusted_even_if_tool_allowlisted():
    # origin overrides the allowlist in the SAFE direction: an allowlisted
    # web_fetch that returns external bytes must still be Untrusted.
    assert _tool_result_is_untrusted(
        "c1", {"c1": "web_fetch"}, frozenset({"web_fetch"}),
        origins={"c1": "external"},
    ) is True


def test_local_origin_is_trusted_even_if_tool_not_allowlisted():
    # the FP fix: an in-workspace read by a non-allowlisted tool is no longer
    # tainted just because the allowlist is empty.
    assert _tool_result_is_untrusted(
        "c1", {"c1": "file_read"}, frozenset(),
        origins={"c1": "local"},
    ) is False


def test_unknown_origin_falls_back_to_allowlist():
    assert _tool_result_is_untrusted(
        "c1", {"c1": "internal_calc"}, frozenset({"internal_calc"}),
        origins={"c1": "unknown"},
    ) is False
    assert _tool_result_is_untrusted(
        "c1", {"c1": "internal_calc"}, frozenset(),
        origins={"c1": "unknown"},
    ) is True


def test_no_origins_map_is_legacy_behaviour():
    # back-compat: with no origins recorded everything is unknown -> allowlist.
    assert _tool_result_is_untrusted("c1", {"c1": "web_fetch"}, frozenset()) is True
    assert _tool_result_is_untrusted("c1", {"c1": "calc"}, frozenset({"calc"})) is False


# --- collect_tool_origins from ToolCall events ----------------------------

def test_collect_tool_origins_from_toolcall_events():
    events = [
        Event("ToolCall", 1, "c_local", "bash", '{"command": "cat ./a.txt"}'),
        Event("ToolCall", 1, "c_ext", "bash", '{"command": "curl https://x.com"}'),
    ]
    origins = collect_tool_origins(events)
    assert origins == {"c_local": "local", "c_ext": "external"}


# --- end to end through the inbound extractor ------------------------------

def _openai_tool_result_request(call_id, content):
    return {"model": "gpt-x", "messages": [
        {"role": "tool", "tool_call_id": call_id, "content": content}]}


def test_inbound_local_result_not_untrusted():
    events = extract_inbound_events(
        tid=1, request=_openai_tool_result_request("c1", "file body"),
        api_format="openai", sid="s",
        proposing_tool_for_call_id={"c1": "file_read"},
        trusted_tool_names=(),
        origin_for_call_id={"c1": "local"},
    )
    assert _args(events, "ToolResult") == [(1, "c1", "file body", 0)]
    assert _args(events, "Untrusted") == []


def test_inbound_external_result_untrusted():
    events = extract_inbound_events(
        tid=2, request=_openai_tool_result_request("c2", "fetched page"),
        api_format="openai", sid="s",
        proposing_tool_for_call_id={"c2": "web_fetch"},
        trusted_tool_names=("web_fetch",),  # allowlisted, but origin wins
        origin_for_call_id={"c2": "external"},
    )
    assert _args(events, "Untrusted") == [(2, "tool_result")]
