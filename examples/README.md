# EnfGuard Examples

The root `enfguard.yaml` is the small starter. This folder is the cookbook.
Copy snippets from here into `enfguard.yaml`, or start the proxy with a full
example file via:

```bash
export ENFGUARD_YAML=examples/presets/baseline_monitor.yaml
python -m uvicorn proxy:app --host 127.0.0.1 --port 9000
```

## Presets

- `presets/baseline_monitor.yaml` - minimal enforcement, maximum traceability.
- `presets/company_safe.yaml` - enterprise compliance and company data safety.
- `presets/personal_lockdown.yaml` - strong privacy and personal safety defaults.
- `presets/escalation_demo.yaml` - same predicate, different verdicts by safety level.
- `presets/cost_control.yaml` - token and model budget controls.
- `presets/privacy_shield.yaml` - personal-data protection before model calls.
- `presets/local_only.yaml` - force local/Ollama-style model usage.

## Building Blocks

- `switches.yaml` - examples for the global `audit | warn | enforce` mode plus int, boolean, float, and choice switches.
- `predicates.yaml` - builtin, Python, and LLM-judge predicates.
- `policies.yaml` - warn, block, approval, temporal, and model policies.
- `labeled_security_level.mfotl` - policy labels for newer EnfGuard binaries.

None of these files are loaded automatically.
