# EnfGuard for LLM agent systems

A runtime enforcement layer that gates an LLM agent's tool calls before they
execute, against policies written in metric first-order temporal logic (MFOTL).

This is the implementation from the Bachelor's thesis *Runtime Enforcement of
Safety Policies for LLM Applications Using EnfGuard* (ETH Zürich). Evaluation
evidence lives in a separate repository, linked below.

## What it does

A FastAPI proxy sits between an agent runtime and the model provider, and a pair
of runtime hooks sit at the tool boundary. Every chat request, model response,
planned tool call, and tool result becomes a typed event. A deterministic mapper
classifies each action into a small fixed vocabulary of `Classify(dimension,
level)` facts. MFOTL policies match those constants and return `Block`, `Warn`,
`Approve`, or `Allow` before the action runs.

Two properties are the point of the design:

- **Policies see the session, not one call.** A file written from untrusted
  content and executed three steps later is blocked on the execution, because a
  temporal clause joins the two events on the shared path.
- **Semantic work happens at the instrumentation layer.** Policies match fixed
  constants, so they stay small and auditable. Optional gated LLM judges emit the
  same kind of facts where command structure alone is not enough.

## Requirements

- Python 3.12 or newer
- The EnfGuard OCaml enforcer (external, see below)
- Node 18+ only if you want to build the enforcement console UI

## Installing the EnfGuard enforcer

The MFOTL enforcement core is a separate project by Hublet, Lima, Krstić,
Traytel and Basin: <https://github.com/runtime-enforcement/enfguard> (LGPL-3.0).

```bash
# Debian/Ubuntu
apt-get install opam libgmp-dev

opam init -y
opam switch create 4.13.1
eval $(opam env --switch=4.13.1)
opam install dune core_kernel base zarith menhir js_of_ocaml js_of_ocaml-ppx \
             zarith_stubs_js dune-build-info qcheck pyml calendar

git clone https://github.com/runtime-enforcement/enfguard ~/enfguard
cd ~/enfguard && dune build     # produces bin/enfguard.exe
```

This proxy locates the binary in the following order: `$ENFGUARD_BIN`, then
`enfguard` on `PATH`, then `enfguard.exe` on `PATH`, then
`~/enfguard/bin/enfguard.exe`. Cloning to `~/enfguard` as above therefore needs
no further configuration. Otherwise set the path explicitly:

```bash
export ENFGUARD_BIN=/path/to/enfguard.exe
```

The enforcer is invoked as a subprocess, so its LGPL-3.0 licence does not extend
to this repository.

## Quick start

```bash
pip install -e ".[dev]"

# run the proxy against a policy pack
ENFGUARD_YAML=bench/security_bench_testing/openclaw_live/combined_demo_policies.yaml \
  uvicorn proxy:app --port 9000

# point an agent runtime at it
export ANTHROPIC_BASE_URL=http://localhost:9000
export OPENAI_BASE_URL=http://localhost:9000/v1
```

A plain chat page is served at `/chat` and the enforcement console at
`/enforcement`.

## Running the tests

```bash
pytest tests/ -q
```

The suite covers the mapper per attack category, the policy loader, the proxy
trace helpers, path confinement, and judge parsing. Formula syntax checks are
skipped when the OCaml binary is absent.

## Layout

| Path | Contents |
|---|---|
| `instrlib/` | Event mapping, classify-first tool mapper, judge tier, PEP, enforcer bridge |
| `proxy.py`, `predicates.py`, `mappings.py`, … | Proxy, hybrid predicates, provider adapters, policy loader |
| `bench/` | Policy packs, including the thirteen attack-category suite, and the live harness |
| `tests/` | Test suites |
| `examples/` | Runnable demos and policy presets |
| `scripts/` | Overhead measurement, RedCode scoring, false-positive probe |
| `frontend/` | Enforcement console source (run `npm install && npm run build`) |
| `docs/` | Classify vocabulary, design notes, threat model |

## Policy packs

`bench/security_bench_testing/openclaw_live/` holds one pack per attack category
plus `combined_demo_policies.yaml`, which loads the categories that were
live-tested together. `docs/CLASSIFY_VOCABULARY.md` is the authoring contract:
it lists every dimension and the levels a policy may match.

## Scope

Cloning this repository lets you run the proxy, load policy packs, execute the
test suite, and reproduce the demonstration scenarios. It does **not** by itself
reproduce the thesis benchmark numbers. Those runs additionally require the
agent runtimes, paid model access, and the frozen case selections and scoring
artefacts, which are published separately:

- Evaluation evidence: <https://github.com/j0j0j0jonathan/EnfGuard-evaluation-evidence>

Enforcement observes what crosses its instrumented boundaries. Actions a runtime
takes without calling the hooks, and actions executed on another host, are
outside the enforceable surface by construction.

## Citing

If you use this work, please cite the thesis (see `CITATION.cff`) and the
EnfGuard enforcer:

```bibtex
@inproceedings{Hublet2025,
  author    = {François Hublet and Leonardo Lima and David Basin and
               Srdjan Krstic and Dmitriy Traytel},
  title     = {Scaling Up Proactive Enforcement},
  booktitle = {Proceedings of the 37th International Conference on
               Computer Aided Verification (CAV)},
  year      = {2025},
  publisher = {Springer},
}
```

## Licence

MIT, see `LICENSE`. The EnfGuard enforcer is separately licensed under LGPL-3.0.
