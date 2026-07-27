"""Guard: no runtime PEP 604 `isinstance(x, A | B)` in py39-critical modules.

The EnfGuard enforcer embeds a Python 3.9 interpreter (`.venv-py39`) to evaluate
policy predicates. A runtime `A | B` type union (PEP 604) only works on Python
3.10+, so `isinstance(x, int | float)` raises
`TypeError: unsupported operand type(s) for |: 'type' and 'type'` under 3.9. When
that happens inside a judge predicate the enforcer produces no verdict, the request
times out after 20s, and the gate FAILS OPEN, silently allowing the traffic. This
bit the live private-data judge demo (2026-07-01): the judge crashed and every
chat message was allowed.

Signature annotations are safe because these modules use
`from __future__ import annotations` (they become strings). Only RUNTIME unions,
i.e. `isinstance(...)` calls, are dangerous. This test fails if one reappears, on
any Python version, so a developer on 3.10+ cannot reintroduce a 3.9 fail-open.

    python -m pytest tests/test_py39_isinstance_union_guard_2026_07_01.py -q
"""

from __future__ import annotations

import pathlib
import re

import pytest

# Modules whose code runs inside the embedded Python 3.9 predicate interpreter,
# plus the shared classifier/loader they import.
_ROOT = pathlib.Path(__file__).resolve().parent.parent
_CRITICAL = [
    "predicates.py",
    "yaml_loader.py",
    "mappings.py",
    "instrlib/tool_mapper.py",
    "instrlib/path_confinement.py",
    "instrlib/event.py",
]

# isinstance( ... A | B ... ) where the union is a runtime type expression.
_RUNTIME_UNION = re.compile(r"isinstance\s*\([^)]*[A-Za-z_]\s*\|\s*[A-Za-z_]")


@pytest.mark.parametrize("rel", _CRITICAL)
def test_no_runtime_isinstance_union(rel):
    path = _ROOT / rel
    if not path.exists():
        pytest.skip(f"{rel} not present")
    hits = [
        f"{rel}:{i}: {line.strip()}"
        for i, line in enumerate(path.read_text().splitlines(), 1)
        if _RUNTIME_UNION.search(line)
    ]
    assert not hits, (
        "PEP 604 `isinstance(x, A | B)` crashes the Python 3.9 enforcer "
        "(fail-open). Use isinstance(x, (A, B)) instead:\n  " + "\n  ".join(hits)
    )
