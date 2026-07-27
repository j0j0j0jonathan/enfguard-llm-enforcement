# Examples

The root `enfguard.yaml` is the small starter. This folder is the cookbook. Copy
snippets into your own config, or start the proxy with a complete file:

```bash
export ENFGUARD_YAML=examples/presets/baseline_monitor.yaml
python -m uvicorn proxy:app --host 127.0.0.1 --port 9000
```

Nothing here loads automatically.

## Presets

Complete, runnable policy packs. The first is the security suite the thesis
evaluates. The rest are governance packs over the same event signature, which
show that the mechanism is not limited to attack blocking.

- `presets/agentic-security.yaml` - the thirteen-category workstation-agent security pack.
- `presets/baseline_monitor.yaml` - minimal enforcement, maximum traceability.
- `presets/company_safe.yaml` - enterprise compliance and company data safety.
- `presets/personal_lockdown.yaml` - strong privacy and personal safety defaults.
- `presets/privacy_shield.yaml` - personal-data protection before model calls.
- `presets/cost_control.yaml` - token and model budget controls.
- `presets/local_only.yaml` - force local/Ollama-style model usage.
- `presets/model_and_provider_control.yaml` - govern which providers and models an agent may use.
- `presets/escalation_demo.yaml` - same predicate, different verdicts by safety level.

## Building blocks

Snippets to paste into a config of your own.

- `switches.yaml` - the global `audit | warn | enforce` mode plus int, boolean, float, and choice switches.
- `predicates.yaml` - builtin, Python, and LLM-judge predicates.
- `policies.yaml` - warn, block, approval, temporal, and model policies.
- `inspiration_policies.mfotl` - nine worked MFOTL clauses to start from.
- `labeled_security_level.mfotl` - policy labels for newer EnfGuard binaries.
- `demo_predicates.py` - the Python predicates the starter config uses.

## Case studies

Policy packs written against published vendor rules, used in the chatbot case
study.

- `anthropic_constitution.yaml`
- `openai_model_spec.yaml`

## Runtime demos

Configs for the two integration surfaces.

- `live-demo/enfguard.demo-approve-writes.yaml` - tool surface, approve every file write.
- `live-demo/enfguard.demo-private-data.yaml` - model and chat surface, block on private data in the input or the output.
- `nanoclaw/enfguard.nanoclaw-smoke.yaml` - minimal smoke test.
- `nanoclaw/enfguard.nanoclaw-three-points.yaml` - inbound, outbound, and pre-tool enforcement in one run.
- `nanoclaw/enfguard.nanoclaw-tools.yaml` - tool-execution demo.
