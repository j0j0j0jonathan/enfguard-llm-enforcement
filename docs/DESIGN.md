# EnfGuard v2 — current state and what's next

> **v4 signature migration (2026-05-13).** The codebase moved to the v4 signature
> in one cut-over. The 22-event v4 contract is the authoritative description of
> what the proxy emits today. The architecture below is unchanged; only the
> event names and arities are different. When in doubt, read
> `enfguard_user.sig` directly. The supervisor-facing summary lives in
> `../../../writing/appendices/policy-and-signature/policy_and_signature_appendix.tex`; the migration changelog is in the
> wiki at `wiki/outputs/2026-05-13-v4-migration.md`.
>
> Quick v4 substitutions for anyone reading older sections of this doc:
>
> - `UserMessage(t,c,n)` / `AssistantHistory(t,c,n)` / `SystemPrompt(t,c,n)`
>   → `Message(t, role, c, n)` with `role` in `{"user","assistant","system","developer"}`.
> - `CompletionObserved` → `Completion`. The redaction triangle is
>   `Completion-` (suppressible) → `CompletionRedacted+` (causable) →
>   `CompletionReleased`.
> - `ClockTick(t, ms)` → `Clock(t, phase, ms)` with `phase` in
>   `{"request","response","tool"}`.
> - `SwitchInt` / `SwitchBool` / `SwitchString` → `SettingInt` / `SettingBool` /
>   `SettingString`. `SwitchFloat` is dropped (`kind: float` YAML coerces to
>   `SettingInt` basis points).
> - `BlockRequest` / `BlockResponse` / `BlockToolCall` → `Block(t, phase, ...)`
>   with `phase` in `{"request","response","tool"}`. Same shape for `Warn` and
>   for `Approve` (which replaces `RequireApproval`).
> - The 11 per-tool-kind events (`BashExec`, `FileRead`, `FileWrite`,
>   `FileDelete`, `NetworkRequest`, `CodeExec`, `ComputerAction`,
>   `ToolCallObserved`, `ToolCallResult`, `CommandRisk`, `PathSensitivity`,
>   `NetworkRisk`) are replaced by `ToolCall(-)` + `ToolPlanned(-)` +
>   `ToolResult` + `Classify(t, call_id, dim, level)`.
> - `Untrusted(tid, source)` is the new provenance primitive, emitted alongside
>   every `ToolResult` whose proposing tool is not in
>   `backend.trusted_tool_names`.
> - Audit pairs (`Request{Allowed,Blocked,Warned}` /
>   `Response{Allowed,Blocked,Warned}`) and `TokenUsage` were dropped from the
>   formal stream per the "one fact, one location" rule. The proxy's trace UI
>   reconstructs these for display.
> - `Turn(tid, sid)` → `Turn(tid, rid, sid)` with `rid` grouping multiple LLM
>   calls of one user-facing request.

This doc replaces the original v2 spec (lots had drifted). Hand it to a
fresh Claude window so it can pick up exactly where we are.

The next concrete task is **smart judge batching** — see the *Next up*
section at the bottom and the strategy memo in
`JUDGE_BATCHING_STRATEGIES.md`. The current `static_analysis.py` +
`batch_judge.py` pair is being **parked** (kept compiling, no longer the
plan) until the new strategy is decided.

> **Classify-first agent layer (now a primary case study).** Beyond the chat
> proxy this doc was written around, the system gained a full agent-enforcement
> surface. `instrlib/tool_mapper.py` classifies every tool call into
> `Classify(dim, level)` facts across all 13 OpenClaw attack categories at
> ingest, so policies match constants instead of calling a judge inside the
> formula. `instrlib/path_confinement.py` adds the realpath workspace-escape
> signal, and `instrlib/tool_judge.py` provides 7 gated, fail-open ingest judges
> for the long tail. The runtime gate is `POST /v1/tool_execute` (pre-execution)
> plus `POST /v1/tool_result` (observation). Vocabulary:
> `notes/CLASSIFY_VOCABULARY.md`. Trust model: `notes/THREAT_MODEL.md`. Live
> packs and results: `bench/security_bench_testing/openclaw_live/`.
>
> **Recent hardening (2026-06-10).** The mapper's shared canonicalizer was
> extended so the deterministic classifiers see through more obfuscation before
> matching: `${IFS}` word-splitting, `$(echo …)` and backtick assembly,
> backslash-letter splitting (`\c\a\t`), and hex/octal escape clusters are all
> normalized, and `classify_command` now canonicalizes too. `has_encoded_execution`
> gained base32 and whitespace-wrapped base64 decoders at depth 3. Path
> confinement extracts quoted and `$VAR`-built path tokens. A malformed
> `exit_code` on `/v1/tool_result` no longer 500s. Held-out adversarial coverage
> is `tests/test_tool_mapper_adversarial_heldout.py`. Full audit and rationale:
> `wiki/outputs/2026-06-10-security-audit-enfguard-v2.md`.

---

## 1. Architecture at a glance

```
        ┌──────────────────┐              ┌──────────────────┐
Browser │  /chat           │◄──iframe────►│  /enforcement    │ Browser
        │  (vanilla HTML)  │  postMessage │  (React)         │
        └────────┬─────────┘              └────────┬─────────┘
                 │ HTTP                            │ HTTP
                 ▼                                 ▼
        ┌────────────────────────────────────────────────────┐
        │        FastAPI proxy (proxy.py)                    │
        │                                                    │
        │  /v1/messages /v1/chat/completions[/ollama]        │
        │  /trace/{tid} /traces  /pending_approvals          │
        │  /switches /switches/{id}                          │
        │  /admin/policies /admin/dryrun/{mode}              │
        │  /admin/reload  /feedback                          │
        └─────┬──────────────────────────────┬───────────────┘
              │ subprocess (stdin/stdout)    │ HTTP
              ▼                              ▼
        ┌──────────────┐                ┌──────────────────┐
        │ EnfGuard     │                │ Judge LLM        │
        │ OCaml binary │                │ (openai|ollama|  │
        │ (1 process)  │                │  anthropic)      │
        └──────────────┘                └──────────────────┘
```

Single-tenant, single-EnfGuard-process. No sidecar / test-button
infrastructure; the React "Test" button shipped, was never wired, was
removed. Approval gates use long-polling, not SSE.

## 2. The authoring model

The user owns everything. Three layers, top-down:

**MFOTL policies in `enfguard.yaml`.** Each has an `id`, an `enabled`
flag, and an `mfotl` body. Every policy must reference
`PolicyActive(t, "<id>")` so the dashboard toggle works without
recompiling. Composite formula = the snippets joined by `\nAND\n` (no
auto-prepended built-in policies any more).

**Predicates in `enfguard.yaml`.** Three kinds:
- `kind: builtin` — opt in to a Python helper that ships with the proxy
  (`hard_rules`, `contains_secrets`, `model_blocklist`).
- `kind: llm_judge` — judge-style predicate; the YAML provides the
  `system_prompt`. Per-predicate `backend` / `model` / `timeout_ms` /
  `on_fail` overrides the global `backend.judge_*` defaults.
- `kind: python` — load a function from a user-controlled `.py`.

**Switches in `enfguard.yaml`** for runtime knobs the operator can flip
without restarting. Each declared switch becomes (a) a UI control in
the Switches tab and (b) an MFOTL event emitted at the start of every
phase, so policies can match on it directly. Four kinds:
- `kind: int`     → integer slider     · event: `SettingInt(t, name, value)`
- `kind: float`   → fractional slider  · event: `SettingInt(t, name, value)` in basis points
- `kind: boolean` → toggle             · event: `SettingBool(t, name, value)`  (0/1)
- `kind: choice`  → dropdown           · event: `SettingString(t, name, value)`

`kind: number` is accepted as a back-compat alias for `int`. An
`enforcement_mode` choice switch (`audit | warn | enforce`) is
auto-synthesised if the YAML omits it.

**No `features:` block.** Removed — the loader rejects it and points
the user at `switches:`.

## 3. Verdict types and operational mode

EnfGuard policies fire one of three verdicts in their `IMPLIES` clause:
- `Block(t, phase, category, reason)` — hard block, no upstream call, no response release, or no tool execution depending on `phase`
- `Warn(t, phase, category, reason)`  — release/allow with a warning
- `Approve(t, phase, label)`          — pause, prompt, wait for the user

After EnfGuard returns a verdict the proxy applies a small fixed set of
*operational-mode* rules before responding to the chat client:
- **audit** → no user-facing block/warn mutation; useful for shadow-mode deployments.
- **warn** → all blocks demote to warns.
- **warn/audit + `Approve`** → auto-approve, log a synthetic `UserFeedback("approve", "non-enforcing mode …")`.
- **`human_approval.enabled = false`** → `Approve` becomes `Block`.
- **judge fail-mode = warn** → if the judge LLM call fails, demote that
  predicate's block to a warn for this turn.

These translations apply uniformly to *every* policy. They're not
expressible in MFOTL on purpose: forcing the user to repeat
"`AND SettingString(t, "enforcement_mode", "enforce")` …" in every clause would be miserable
boilerplate. Switches are still events though, so a sufficiently motivated
user *can* override Layer B from inside Layer A.

## 4. Request lifecycle

```
POST /v1/messages or /v1/chat/completions[/ollama]
│
├─ tid = next int from process counter; sid from X-Session-ID
├─ active_policies = read state/active_policies.json (mtime-cached)
│
├─ PHASE 1 (inbound)
│  inbound_events = mappings.extract_inbound_events(body)
│  inbound_events = state.switches.emit_events(tid) ++ inbound_events
│  pre_evaluate(inbound_events, predicate_calls)        ← TO BE REWORKED
│  write_current_context(); logger.log(inbound_events)
│  cau_in = EnfGuard verdict
│  cau_in = _resolve_approvals(tid, sid, cau_in, "inbound")
│  cau_in = _demote_warn_failures(cau_in)
│  apply enforcement_mode (audit strips verdicts; warn demotes blocks)
│  if BlockRequest in cau_in:
│     emit RequestBlocked + WarnRequest events; synthetic response; return
│
├─ upstream call to provider
│
├─ PHASE 2 (outbound)
│  outbound_events = mappings.extract_outbound_events(body, response)
│  outbound_events = state.switches.emit_events(tid) ++ outbound_events
│  pre_evaluate(...); logger.log(outbound_events)
│  cau_out = _resolve_approvals(tid, sid, cau_out, "outbound")
│  cau_out = _demote_warn_failures(cau_out)
│  apply enforcement_mode (audit strips verdicts; warn demotes blocks)
│  apply BlockResponse / WarnResponse / allow path
│
└─ write per-session record (verdict_events included for the trace UI)
```

Approval gates pause inside `_resolve_approvals` on an
`asyncio.Event` keyed by `tid`; `POST /feedback` with `kind=approve|deny`
resolves it. Long-polling endpoint for the UI is `GET /pending_approvals`.

## 5. File-by-file map (current state)

| File | Purpose | Notes |
|---|---|---|
| `proxy.py` | FastAPI app, request lifecycle, all admin endpoints | `_run_enforced_request` is the spine; helpers organised below it |
| `yaml_loader.py` | Parse + validate `enfguard.yaml`, write `state/active_policies.json`, build composite `.sig`/`.mfotl` | rejects `features:`, validates per-predicate backend |
| `switch_state.py` | Thread-safe in-memory store for switches; `emit_events(tid)` | dispatches int/float/bool/choice → matching event type |
| `predicates.py` | Built-in + user predicate wrappers, judge HTTP, batched judge cache | now supports per-predicate `(backend, model, timeout_ms)` resolution; Anthropic backend implemented |
| `mappings.py` | OpenAI/Anthropic chat → EnfGuard events | unchanged shape, well-tested |
| `handlers.py` | Apply verdicts to a `NormalizedResponse` | unchanged shape |
| `feedback.py` | `make_feedback_event` | one-liner; `/feedback` endpoint lives in `proxy.py` |
| `event_schema.py` | Python type registry mirroring `enfguard_user.sig` | docstring spells out the invariant |
| `enfguard_user.sig` | Source of truth for the event signature | current 22-event signature with `ToolPlanned`, `Setting*`, and phase-tagged `Block` / `Warn` / `Approve` |
| `static_analysis.py` | Regex-based predicate-call extractor | **PARKED** — see §7 |
| `batch_judge.py` | Pre-evaluate judge calls before EnfGuard sees them | **PARKED** — see §7 |
| `frontend/src/App.jsx` | React enforcement console: Policies / Switches / Trace / Feedback tabs + approval modal | switches lifted to App-level state; trace lives primarily in chat.html now |
| `static/chat.html` | Vanilla chat page with system prompt input + per-turn trace card | reads `X-Tid` from response, fetches `/trace/{tid}` lazily |
| `instrlib/` | Logger / Enforcer / PEP / Schema (unchanged from v1 fork) | |
| `instrlib/tool_mapper.py` | Classify-first ingest. `map_tool_call` emits `Classify(dim, level)` for all 13 OpenClaw categories. Shared canonicalizer deobfuscates before matching | the heart of the agent surface |
| `instrlib/tool_judge.py` | 7 gated, fail-open ingest judges for ambiguous/unknown tool calls | off unless registered, never in-formula |
| `instrlib/path_confinement.py` | Realpath workspace-escape signal, quote/`$VAR`-aware path tokens | fail-open, resolves on the proxy host |
| `scripts/clear_runtime_cache.py` | Wipe `judge_cache.jsonl`, traces, session logs | run with proxy stopped between tests |

## 6. What's actually shipped

A non-exhaustive but honest checklist of features that *work today*:

- **Two-phase enforcement** for OpenAI Chat Completions, Anthropic
  Messages, and an Ollama adapter that maps to the OpenAI shape.
- **User-authored composite formula** — no auto-included built-ins.
- **`kind: builtin` / `kind: llm_judge` / `kind: python`** predicates.
- **Per-predicate judge backend** (`openai` / `ollama` / `anthropic`)
  with model + timeout + fail-mode overrides.
- **Switches** (int / float / boolean / choice) with full UI parity and
  worked YAML examples (`max_tokens`, `model_tier`, `safety_level`).
- **Human-approval gates**: `Approve` verdict, async pause-and-resume,
  long-polling endpoint, top-right approval card stack with countdown.
- **Trace UI** in two places:
  - inline below every assistant message in the chat (verdict pill →
    expand → phase blocks → per-predicate table with judge prompt /
    raw reply / latency / cache state / batch ref);
  - a Trace tab in the enforcement console for cross-turn lookup.
- **Events block** in the trace shows everything that fired:
  inbound events sent to EnfGuard, the verdict events the proxy emitted
  back, and the outbound events from the response.
- **Editable judge fail modes** in the Policies tab (per-predicate
  dropdown plus a global default).
- **Per-tid trace index** + judge-cache snapshot id for safe rotation.
- **Hot reload** via `POST /admin/reload` — re-parses YAML, regenerates
  composite `.sig`/`.mfotl`, restarts EnfGuard, swaps under
  `state.enforcement_lock`.
- **Cache-clear utility** at `scripts/clear_runtime_cache.py` so the
  user can demo from a clean slate.
- **Temporal policy** demo (`rate_limit_3_per_5_turns` in the example
  YAML) using the nested `ONCE` pattern from
  `examples/inspiration_policies.mfotl`.
- **Tool / agent event family**: the signature carries `ToolCall`,
  `ToolPlanned`, `ToolResult`, and `Classify`. `mappings.py` parses
  Anthropic `tool_use` blocks and OpenAI `tool_calls` arrays through
  `instrlib.tool_mapper.map_tool_call`, plus the matching inbound
  `tool_result` / `role: "tool"` shapes. The `/v1/tool_execute`
  action hook emits `ToolPlanned` before the runtime side effect.
- **Agent-action enforcement gate** at `POST /v1/tool_execute`. Agents
  call this oracle before running a tool; the proxy emits the matching
  `ToolPlanned` / `ToolCall` / `Classify` facts, runs enforcement, and
  returns `{decision: "allow"|"block", reason?, warning?, tid,
  trace_url}`. MFOTL policies express the decision through
  `Block(t, "tool", ...)`, `Warn(t, "tool", ...)`, or
  `Approve(t, "tool", ...)`. NanoClaw integrates via the Claude Agent
  SDK's `canUseTool`; OpenClaw via PRISM `tool:before_call`.
- **Boot-time binary check** with a clear search-trail diagnostic when
  the EnfGuard binary is missing. `config.detect_enfguard_binary()`
  resolves it from `$ENFGUARD_BIN`, then `which enfguard`, then
  `which enfguard.exe`, then a fallback path. Boot banner prints the
  resolved binary, yaml, composite sig/mfotl, and CORS origins.
- **CORS hardening**: `allow_origins` defaults to loopback only
  (proxy port + Vite 5173) instead of `*`. Override via
  `$ENFGUARD_CORS_ALLOW_ORIGINS`.

Test count: **164 passing** (1 deselected, pre-existing prompt-count
mismatch unrelated to this work); no flakes.

## 7. What's parked: the static-analysis pre-evaluator

We currently have:

- `static_analysis.py` — regex-based parser of the composite formula
  that extracts predicate calls per event source.
- `batch_judge.py` — uses that index to pre-evaluate judges before
  EnfGuard runs and warm the shared judge cache.

This works for simple formula shapes (`Event(t, c, n) AND pred(c) > T`)
but has known limitations that produce real artifacts: e.g. `hard_rules`
showing up *twice* in a single phase trace because the analyzer caught
one binding site (UserMessage.content) but the EnfGuard subprocess
later evaluated `hard_rules` on a second site (SystemPrompt.content)
that the analyzer didn't recognise. End-to-end this means our "pre-
batched" judge calls miss the second site, that call falls through to
the slow per-call path, and a phase that should have been ~one round
trip becomes two.

**Decision: park the current static-analysis approach.** Don't delete
the code (the proxy still uses it for the cases it handles), but
don't extend it either — the next batching design will replace it. The
strategy memo at `JUDGE_BATCHING_STRATEGIES.md` lays out six candidate
strategies (current V2, guard-aware skipping, V1-style multi-label
packs, aggressive active-policy bundle, speculative phase-2 templates,
parallel single-judge calls, hybrid router) and a recommended
benchmark order.

## 8. Operational notes for the next session

**Boot sequence:**
1. `export ENFGUARD_ADMIN_TOKEN=…` (proxy refuses to start without it).
2. `cd frontend && npm install && npm run build` (otherwise `/enforcement` 503s).
3. `python -m uvicorn proxy:app --host 127.0.0.1 --port 9000`.
4. Open `http://127.0.0.1:9000/chat?admin_token=…`.

**Clean-slate testing:** stop the proxy, then
`python scripts/clear_runtime_cache.py`, then restart. Wipes
`state/judge_cache.jsonl`, `logs/traces/`, `logs/trace_store.jsonl`,
and per-session records.

**Per-predicate backend example** (already in `enfguard.yaml`):
```yaml
predicates:
  - name: confidential_information_inbound
    kind: llm_judge
    backend: openai          # openai | ollama | anthropic
    model: gpt-4o-mini       # provider-specific id
    timeout_ms: 5000         # this judge can take longer
    on_fail: closed
    system_prompt: |
      Score 1.0 only when ...
```

**Live demos:**
- *safety_level* switch → flip the dropdown, send the same message,
  and repeat a hard-safety prompt to show the temporal escalation policy:
  safe blocks immediately, cautious warns then blocks, dangerous waits
  until the third recent match.
- *allow_emojis* switch + `no_emoji_in_output_policy` → run with output
  emoji on, then off.
- *rate_limit_3_per_5_turns* policy → enable, send four messages, watch
  the fourth block.
- *Approve* + `approve_secrets` policy → send a message
  mentioning family, watch the approval card pop up; click Approve and
  the assistant proceeds.

## 9. Next up: smart judge batching

This is the next chunk of work. Read
`JUDGE_BATCHING_STRATEGIES.md` first — it has the full menu of
strategies and the trade-offs. Recommended path:

1. **Add the metrics infrastructure** (`judge_strategy`,
   `judge_http_call_id`, `task_count`, `backend`, `model` on every
   trace row) so we can compare strategies apples-to-apples.
2. **Strategy A: guard-aware skipping** — extend the
   predicate-policy index so a judge call is only planned when:
   (a) at least one owning policy is active, (b) all simple switch
   guards are satisfiable, (c) the matching event exists in this
   phase. Lowest-risk, removes the obvious wasted calls (e.g.
   `no_emoji_in_output` when `allow_emojis=true`).
3. **Strategy E: parallel single-judge calls** — when there are two or
   more cache misses with compatible config, run them with
   `asyncio.gather` instead of stuffing them all into one batch
   prompt. Compare against the current batch-prompt approach for
   end-to-end latency and parse-failure rate.
4. **Strategy C: aggressive active-policy bundle** — once the metrics
   exist, gather every judge predicate that *might* matter for this
   phase (active policy + satisfiable switches + event present) and
   send them as one well-structured batch task. Keep per-task cache
   keys identical to today.

The fallback pattern for unsupported MFOTL shapes stays correct (the
EnfGuard subprocess will run the predicate at runtime). The goal is to
make the *fast path* cover more cases, not to have a one-size answer.

## 10. Things deferred to LATER.md

- Two-variable predicate batching (e.g. system-prompt × completion
  pairs) — V1 had it, V2 doesn't.
- Full MFOTL parser instead of regex — only worth it if we commit to
  Strategy A or Strategy C and start running into shapes the regex
  can't handle. Brainstorm at `notes/BRAINSTORM_OPEN_ITEMS.md` Item 1.
- Per-tid context files instead of the single `current_context.json`
  + `enforcement_lock`. Single-user demo doesn't need it.
- Streaming responses — the proxy returns 501 today. Now blocking the
  NanoClaw point-A path (the SDK requests `stream: true`); workaround
  is to disable streaming in the agent for now.
- Replay-from-log mode + the "Test this prompt" button.
- Wall-clock MFOTL intervals (`tid` is the timestamp, intervals count
  turns, not milliseconds).

Resolved (2026-05-08):

- ~~Tool / agent event family~~ — landed. `ToolCall`, `ToolPlanned`,
  `ToolResult`, and `Classify` are in the signature, `event_schema.py`,
  and parsed or emitted by `mappings.py` / `proxy.py` for both Anthropic
  `tool_use` and OpenAI `tool_calls` shapes, inbound `tool_result` /
  `role: "tool"` shapes, and the `POST /v1/tool_execute`
  agent-action gate.

These are not on fire. Don't pull any of them in unless explicitly
requested — the surface area is already what a thesis demo can defend.
