"""Rate-limit recovery for the parallel AgentHazard judge path."""

from __future__ import annotations

import threading
import time

import instrlib.tool_judge as tj


class _Response:
    def __init__(self, status_code: int = 200, retry_after: str = ""):
        self.status_code = status_code
        self.headers = {"retry-after": retry_after} if retry_after else {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"status {self.status_code}")


def test_post_judge_retries_429_then_returns_success(monkeypatch):
    monkeypatch.setenv("ENFGUARD_TOOL_JUDGE_MAX_ATTEMPTS", "2")
    monkeypatch.setenv("ENFGUARD_TOOL_JUDGE_RETRY_INITIAL_SECONDS", "0")
    monkeypatch.setenv("ENFGUARD_TOOL_JUDGE_MAX_CONCURRENT", "0")
    calls = []

    def fake_post(*_args, **_kwargs):
        calls.append(1)
        return _Response(429) if len(calls) == 1 else _Response(200)

    monkeypatch.setattr(tj.httpx, "post", fake_post)
    assert tj._post_judge("https://example.test", {}, {}, 1.0).status_code == 200
    assert len(calls) == 2


def test_post_judge_serializes_when_slot_enabled(monkeypatch):
    monkeypatch.setenv("ENFGUARD_TOOL_JUDGE_MAX_ATTEMPTS", "1")
    monkeypatch.setenv("ENFGUARD_TOOL_JUDGE_MAX_CONCURRENT", "1")
    monkeypatch.setattr(tj, "_JUDGE_SLOT", None)
    monkeypatch.setattr(tj, "_JUDGE_SLOT_LIMIT", None)
    active = 0
    peak = 0
    lock = threading.Lock()

    def fake_post(*_args, **_kwargs):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        time.sleep(0.02)
        with lock:
            active -= 1
        return _Response(200)

    monkeypatch.setattr(tj.httpx, "post", fake_post)
    threads = [threading.Thread(target=tj._post_judge, args=("https://example.test", {}, {}, 1.0)) for _ in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert peak == 1
