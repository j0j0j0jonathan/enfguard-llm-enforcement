"""Tests for ``config.cors_allow_origins``.

The helper drives the FastAPI ``CORSMiddleware`` allow-list. Default is
loopback-only on the chat-page port plus the Vite dev server. Operators
can override via ``$ENFGUARD_CORS_ALLOW_ORIGINS`` (comma-separated, set
to ``*`` to opt back into the permissive default of older builds).
"""

from __future__ import annotations

import config


def test_default_is_loopback_only(monkeypatch):
    """When the env var is unset, only loopback origins are allowed."""

    monkeypatch.delenv("ENFGUARD_CORS_ALLOW_ORIGINS", raising=False)
    origins = config.cors_allow_origins(9000)

    # No wildcard sneaks in.
    assert "*" not in origins
    # The chat page and Vite dev server are reachable in their normal flow.
    assert "http://127.0.0.1:9000" in origins
    assert "http://localhost:9000" in origins
    assert "http://127.0.0.1:5173" in origins
    assert "http://localhost:5173" in origins


def test_default_uses_supplied_proxy_port(monkeypatch):
    """The proxy_port argument flows into the loopback default URLs."""

    monkeypatch.delenv("ENFGUARD_CORS_ALLOW_ORIGINS", raising=False)
    origins = config.cors_allow_origins(8080)
    assert "http://127.0.0.1:8080" in origins
    assert "http://127.0.0.1:9000" not in origins


def test_env_var_overrides_default(monkeypatch):
    """A comma-separated env var replaces the default list verbatim."""

    monkeypatch.setenv(
        "ENFGUARD_CORS_ALLOW_ORIGINS",
        "https://thesis.example.com, http://internal.lan:9000",
    )
    origins = config.cors_allow_origins(9000)
    assert origins == [
        "https://thesis.example.com",
        "http://internal.lan:9000",
    ]


def test_env_var_wildcard_passes_through(monkeypatch):
    """``*`` re-enables the wide-open behaviour for operators who insist."""

    monkeypatch.setenv("ENFGUARD_CORS_ALLOW_ORIGINS", "*")
    assert config.cors_allow_origins(9000) == ["*"]


def test_env_var_strips_blank_entries(monkeypatch):
    """Trailing commas and whitespace do not produce empty origin strings."""

    monkeypatch.setenv(
        "ENFGUARD_CORS_ALLOW_ORIGINS",
        ",  http://a , ,, http://b ,",
    )
    assert config.cors_allow_origins(9000) == ["http://a", "http://b"]


def test_empty_env_var_yields_empty_list(monkeypatch):
    """Setting the env var to '' explicitly disables every origin.

    This is a deliberately strict deployment ('this proxy is consumed
    by same-origin requests only, no CORS fallback'). The default
    branch only fires when the variable is *unset*.
    """

    monkeypatch.setenv("ENFGUARD_CORS_ALLOW_ORIGINS", "")
    assert config.cors_allow_origins(9000) == []
