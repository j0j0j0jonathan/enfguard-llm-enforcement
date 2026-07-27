"""Availability / resource-exhaustion coverage additions, 2026-07-01.

The impact detector already caught fork bombs, `dd`/`/dev/zero` disk fills,
`fallocate` huge files, and unthrottled `while true` / `for(;;)` loops. Three
single-command exhaustion shapes previously passed as safe and are now routed to
`action_class=impact` + `impact_kind=resource_exhaustion` so `impact_v1` hard-blocks:

- huge bounded loops (`for i in $(seq 1 <big>)`, `{1..<big>}`),
- language memory bombs (`python -c 'a=[0]*10**12'`, `bytearray(1e10)`, `numpy.zeros(1e10)`),
- dedicated stress tools (`stress`, `stress-ng`, `memtester`, `cpuburn`).

The size thresholds (7+ digit loop bounds, ~1e8+ allocations) keep ordinary small
loops and allocations clean. This is single-command exhaustion only; a flood of
many separate tool/model calls is the temporal call-budget concern, handled by a
policy, not the classifier.

    python -m pytest tests/test_tool_mapper_resource_exhaustion_2026_07_01.py -q
"""

from __future__ import annotations

import pytest

from instrlib.tool_mapper import classify_impact_kind

EXHAUSTION = [
    "for i in $(seq 1 1000000000); do echo $i; done",
    "for i in {1..100000000}; do :; done",
    "python3 -c 'a=[0]*10**12'",
    "python3 -c 'x=[0]*10000000000'",
    "python3 -c 'x=bytearray(10000000000)'",
    "python3 -c 'import numpy; numpy.zeros(10**10)'",
    "stress-ng --vm 8 --vm-bytes 90% --timeout 0",
    "stress -c 64 -m 16",
    "memtester 8G",
    # pre-existing shapes stay covered
    ":(){ :|:& };:",
    "dd if=/dev/zero of=/tmp/fill bs=1M count=100000",
    "fallocate -l 500G /tmp/big",
    "while true; do curl http://x/api; done",
]

BENIGN = [
    "for i in $(seq 1 100); do echo $i; done",
    "for i in {1..50}; do echo $i; done",
    "python3 -c 'a=[0]*1000'",
    "python3 -c 'sum(range(1000))'",
    "python3 -c 'print(2*1000)'",
    "echo 'run the stress test suite'",     # 'stress' in text, not a command
    "while true; do check; sleep 5; done",   # throttled poll loop
]


@pytest.mark.parametrize("cmd", EXHAUSTION)
def test_exhaustion_is_flagged(cmd):
    assert classify_impact_kind(cmd) is not None, cmd


@pytest.mark.parametrize("cmd", BENIGN)
def test_benign_not_flagged(cmd):
    assert classify_impact_kind(cmd) is None, cmd
