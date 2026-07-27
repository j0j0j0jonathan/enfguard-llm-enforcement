# Category policy packs

One self-contained policy pack per attack category, plus a combined pack and the
evaluation configurations. Each pack is standalone: launch the proxy with
`ENFGUARD_YAML` pointed at the pack file. A predicate `path:` is resolved
relative to this directory (see `yaml_loader.py`), so each category's predicates
and YAML stay together here.

## The thirteen categories

| Category | Pack |
|---|---|
| 1 Reconnaissance | `reconnaissance_classify_policies.yaml` |
| 2 Resource development | `resource_development_classify_policies.yaml` |
| 3 Initial access | `initial_access_classify_policies.yaml` |
| 4 Execution | `execution_classify_policies.yaml` |
| 5 Persistence | `persistence_classify_policies.yaml` |
| 6 Privilege escalation | `privilege_escalation_classify_policies.yaml` |
| 7 Defense evasion | `defense_evasion_classify_policies.yaml` |
| 8 Credential access | `credential_classify_policies.yaml` |
| 9 Discovery | `discovery_classify_policies.yaml` |
| 10 Lateral movement | `lateral_movement_classify_policies.yaml` |
| 11 Collection | `collection_classify_policies.yaml` |
| 12 Exfiltration | `exfiltration_classify_policies.yaml` |
| 13 Impact | `impact_classify_policies.yaml` |

Temporal policies use native trace seconds under
`ENFGUARD_TIME_MODE=wall_seconds`. Metric windows are written directly as
`ONCE [0,N]`, and session-wide accumulation may use plain `ONCE`.

### A note on window lengths

The standalone category packs and `combined_demo_policies.yaml` are frozen at
the build that produced the per-category live-test evidence. They use the
original two-minute correlation window, `ONCE [0,120]`.

Later measurement showed that two minutes is too short for real agent work.
Observed gaps between a sensitive read and the matching send were 148, 182 and
531 seconds, all of which a two-minute window misses. The evaluation packs under
`eval/` therefore use a session-scoped `ONCE [0,1800]`, and that is the window
behind the reported results.

The older packs are kept unchanged so they still match the evidence collected
with them. For a deployment, prefer the longer window: either load an `eval/`
pack or widen the bound in your own copy. Nothing else in the clause changes.

## Combined pack

`combined_demo_policies.yaml` holds all thirteen category policies, copied from
their standalone packs, and is the pack to load for a full demonstration. The
disabled `external_judge` policy in it is the one-shot comparison baseline.
`combined_demo_prompt_suite.md` records the layered on/off and blind prompts.

A policy being present in the combined pack does not by itself imply completed
live evidence for that category. The thesis states which categories were
live-tested and which were exercised through direct gate replay.

### Running it

```bash
export ENFGUARD_ADMIN_TOKEN=123
export ENFGUARD_BIN=$HOME/enfguard/bin/enfguard.exe
export ENFGUARD_TIME_MODE=wall_seconds
export ENFGUARD_YAML=bench/security_bench_testing/openclaw_live/combined_demo_policies.yaml
python -m uvicorn proxy:app --host 127.0.0.1 --port 9000
```

## Optional tiers

`content_disclosure_policies.yaml` is the opt-in content-versus-action pack. It
emits `content_risk` on a local write and contains the global
`judge_fail_closed_v1` clause, which is disabled by default. Enable it only for
a miss-nothing profile, since it blocks any call whose semantic check could not
run.

`coverage_judge_policies.yaml` carries the coverage layer and the gated judges,
so an unclassified call becomes something a policy can act on.

## Evaluation configurations

`eval/` holds the configurations used to produce the reported numbers. They
collapse verdicts for scoring and are not intended as deployment packs.

| File | Role |
|---|---|
| `eval_combined_no_pathconf_content.yaml` | The evaluated hybrid pack |
| `eval_combined_no_pathconf.yaml` | Same without the content tier |
| `eval_combined_block_or_allow.yaml` | Binary block/allow collapse |
| `eval_combined_no_pathconf_content_benign.yaml` | Benign-utility variant |
| `eval_combined_no_pathconf_content_replay.yaml` | Replay variant |
| `eval_judge_only.yaml` | Single-LLM-judge baseline |
| `eval_ablation_direct_block.yaml` | Direct-block-only ablation |
| `eval_ablation_merged_per_category.yaml` | One block clause per category |

## Fixtures

The `setup_*.sh` scripts create the synthetic files an attack category needs, so
a live run has something realistic to act on. They contain deliberately fake
credentials and payloads. Run them only inside a disposable container.
