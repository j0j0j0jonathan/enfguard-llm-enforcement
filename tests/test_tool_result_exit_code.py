"""Regression test for M1 (security audit 2026-06-10).

`/v1/tool_result` parsed ``exit_code`` with a bare ``int(...)`` guarded only by
``isinstance(..., (int, str))`` — a non-numeric string (``"abc"``) passed the
guard and ``int("abc")`` raised, returning a 500 from the result hook. A 500 on
the gate is a fail-open in practice. The parse is now wrapped and defaults to -1.

The assertion is "never 500 for a malformed exit_code", which holds whether or
not the OCaml enforcer binary is present (503 enforcer-not-started without it,
200 with it) — the point is that body parsing no longer crashes.

    python -m pytest tests/test_tool_result_exit_code.py -q
"""

from __future__ import annotations

import os

import pytest


@pytest.mark.parametrize("bad_exit_code", ["abc", [1, 2], {"x": 1}, "", "1.5"])
def test_tool_result_malformed_exit_code_does_not_500(monkeypatch, bad_exit_code):
    monkeypatch.setenv("ENFGUARD_ADMIN_TOKEN", "t")
    try:
        from starlette.testclient import TestClient
        import proxy
    except Exception:  # pragma: no cover - environment without web deps
        pytest.skip("web deps / proxy not importable in this environment")

    client = TestClient(proxy.app)
    resp = client.post(
        "/v1/tool_result",
        headers={"X-Admin-Token": "t", "X-Session-ID": "s"},
        json={"call_id": "x", "tool_response": "ok", "exit_code": bad_exit_code},
    )
    # The crash path produced a 500; the fix must avoid that regardless of whether
    # the enforcer is running (503) or fully wired (200).
    assert resp.status_code != 500, (bad_exit_code, resp.text[:200])
