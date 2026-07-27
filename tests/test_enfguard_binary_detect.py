"""Tests for the EnfGuard binary auto-detect + fail-loud boot check.

Covers ``config.detect_enfguard_binary`` (the resolution order: env var,
``$PATH`` lookup, fallback) and ``proxy._ensure_enfguard_binary`` (the
boot-time check that raises a descriptive ``RuntimeError`` when the
resolved path does not point at an executable file).
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

import config
import proxy


def _make_executable(path: Path) -> Path:
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def test_detect_uses_env_var_verbatim_when_set(tmp_path, monkeypatch):
    """``$ENFGUARD_BIN`` overrides every other lookup, missing or not."""

    target = tmp_path / "explicit-enfguard"
    monkeypatch.setenv("ENFGUARD_BIN", str(target))
    monkeypatch.setattr(config.shutil, "which", lambda _: "/should/be/ignored")

    assert config.detect_enfguard_binary() == target


def test_detect_expands_user_in_env_var(tmp_path, monkeypatch):
    """``~`` in ``$ENFGUARD_BIN`` is expanded to the user's home."""

    monkeypatch.setenv("ENFGUARD_BIN", "~/my-enfguard")
    expanded = config.detect_enfguard_binary()
    assert str(expanded).startswith(str(Path.home()))
    assert expanded.name == "my-enfguard"


def test_detect_falls_back_to_path_lookup(tmp_path, monkeypatch):
    """When ``$ENFGUARD_BIN`` is unset, ``shutil.which`` is consulted."""

    monkeypatch.delenv("ENFGUARD_BIN", raising=False)
    binary = _make_executable(tmp_path / "enfguard")

    def fake_which(name):
        return str(binary) if name == "enfguard" else None

    monkeypatch.setattr(config.shutil, "which", fake_which)
    assert config.detect_enfguard_binary() == binary


def test_detect_accepts_exe_suffix_on_path(tmp_path, monkeypatch):
    """The OCaml build's ``.exe`` suffix is honoured even on POSIX."""

    monkeypatch.delenv("ENFGUARD_BIN", raising=False)
    binary = _make_executable(tmp_path / "enfguard.exe")

    def fake_which(name):
        return str(binary) if name == "enfguard.exe" else None

    monkeypatch.setattr(config.shutil, "which", fake_which)
    assert config.detect_enfguard_binary() == binary


def test_detect_returns_default_fallback_when_nothing_resolves(monkeypatch):
    """With no env var and no PATH match, the historical fallback wins."""

    monkeypatch.delenv("ENFGUARD_BIN", raising=False)
    monkeypatch.setattr(config.shutil, "which", lambda _: None)
    assert config.detect_enfguard_binary() == config.DEFAULT_ENFGUARD_BIN


def test_time_mode_defaults_to_logical(monkeypatch):
    monkeypatch.delenv("ENFGUARD_TIME_MODE", raising=False)

    assert config.enfguard_time_mode() == "logical"


def test_time_mode_accepts_wall_seconds(monkeypatch):
    monkeypatch.setenv("ENFGUARD_TIME_MODE", "wall_seconds")

    assert config.enfguard_time_mode() == "wall_seconds"


def test_time_mode_rejects_unknown_value(monkeypatch):
    monkeypatch.setenv("ENFGUARD_TIME_MODE", "milliseconds")

    with pytest.raises(ValueError, match="ENFGUARD_TIME_MODE"):
        config.enfguard_time_mode()


def test_ensure_binary_returns_silently_when_executable(tmp_path):
    """The check is a no-op when the resolved path is a real binary."""

    binary = _make_executable(tmp_path / "enfguard.exe")
    proxy._ensure_enfguard_binary(binary)


def test_ensure_binary_raises_on_missing_path(tmp_path, monkeypatch):
    """Missing binaries raise a ``RuntimeError`` with the search trail."""

    monkeypatch.delenv("ENFGUARD_BIN", raising=False)
    monkeypatch.setattr(proxy.shutil, "which", lambda _: None)
    bogus = tmp_path / "does-not-exist"

    with pytest.raises(RuntimeError) as info:
        proxy._ensure_enfguard_binary(bogus)

    message = str(info.value)
    assert "EnfGuard binary not found" in message
    assert str(bogus) in message
    # The diagnostic spells out every fallback tried so the operator can
    # see exactly why we did not find the binary.
    assert "$ENFGUARD_BIN" in message
    assert "PATH lookup" in message
    assert str(config.DEFAULT_ENFGUARD_BIN) in message
    assert "enfguard.yaml" in message


def test_ensure_binary_raises_when_path_is_not_executable(tmp_path, monkeypatch):
    """Existing-but-not-executable files also fail the check."""

    monkeypatch.delenv("ENFGUARD_BIN", raising=False)
    monkeypatch.setattr(proxy.shutil, "which", lambda _: None)
    not_executable = tmp_path / "enfguard.exe"
    not_executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    not_executable.chmod(0o644)  # readable, not executable

    with pytest.raises(RuntimeError) as info:
        proxy._ensure_enfguard_binary(not_executable)

    assert "not found or not executable" in str(info.value)


def test_ensure_binary_reports_env_var_when_set(tmp_path, monkeypatch):
    """The error surfaces a misconfigured env var so the operator can fix it."""

    monkeypatch.setenv("ENFGUARD_BIN", "/totally/wrong/path")
    monkeypatch.setattr(proxy.shutil, "which", lambda _: None)
    bogus = Path("/totally/wrong/path")

    with pytest.raises(RuntimeError) as info:
        proxy._ensure_enfguard_binary(bogus)

    assert "/totally/wrong/path" in str(info.value)
