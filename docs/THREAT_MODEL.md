# THREAT_MODEL

**Status:** Thesis-defence companion note stating the trust boundaries
under which EnfGuardV2 claims to enforce safety policies.
**Audience:** Thesis reviewers; benchmark and policy-pack authors who
need to know which attacker capabilities the system is designed to
contend with.
**Scope:** Trust boundaries, attacker capabilities and goals, security
guarantees that hold, and the threats explicitly out of scope. This note
is referenced from the evaluation chapter wherever a benchmark case
makes an assumption about what the attacker controls.

## 1. Trust boundaries

The system is partitioned into trusted and untrusted components. The
boundary between them is enforced by the proxy and the OCaml MFOTL
monitor; the boundary's correctness is what the thesis claims.

**Trusted components.** The proxy host (operating system, network
stack, storage); the `enfguard.exe` OCaml monitor binary and its
process boundary; the policy YAML and signature files as authored;
the proxy spine in `code/EnfGuardV2/proxy.py` and its supporting
modules; the configured response and tool handlers; the React
enforcement console as operated by the deployment owner; the LLM
provider's TLS endpoint *as a delivery channel only* — its content is
treated as untrusted, see below. The Python derivation predicates that
the policy author writes are trusted to the extent that the author is.

**Untrusted components.** Every byte that crosses into the system from
outside. This includes: model completions (the assistant text the
provider returns); user messages (input from the chat client or the
agent's user); tool results (any output of a tool execution, whether
from a local syscall or a remote API); retrieved content (RAG
documents, MCP server responses, web-fetched pages); skill files and
tool definitions loaded at startup if the deployment supports dynamic
loading. Untrusted content is allowed to influence the policy evaluation
only through events the proxy emits, and only through clauses the YAML
author has explicitly authored to reason about it.

**Boundary mechanism.** The boundary is enforced by the proxy's event
emission contract. Untrusted content reaches the MFOTL engine only as
arguments of events the proxy emits. The engine cannot read the
network, the filesystem, or the model output directly; it can only see
what the proxy chose to put into an event. This means the boundary's
soundness depends on the proxy's event extraction being faithful — see
§5 for what that means and where it can fail.

## 2. Attacker capabilities

The thesis considers attackers with the following capabilities. The
benchmark cases are sampled across these capabilities.

The attacker controls user inputs to the chat surface or the agent's
prompt. The attacker controls the contents of any external resource the
agent or chatbot reads — emails, calendar events, cloud-drive documents,
Slack messages, retrieved web pages, MCP server responses, RAG-indexed
documents. The attacker controls the contents of any tool result if the
tool reads from an attacker-influenceable source (`backend.trusted_tool_names`
specifies which tools are *not* attacker-influenceable; everything else
is). The attacker may chain multiple requests within a session and may
attempt to compose innocent-looking steps into a harmful aggregate.
The attacker may use any natural-language technique against the model
— jailbreaks, roleplay, encoded payloads, multilingual prompts,
delimiter confusion, payload splitting, indirect prompt injection via
tool results.

The attacker does *not* control the policy YAML, the event signature,
the proxy host, the OCaml monitor binary, the model provider's
infrastructure, or the operating system. The attacker does not have a
side channel through which to influence the proxy's internal state
without going through one of the documented input channels.

## 3. Attacker goals

The benchmark organises attacker goals along the eight policy families
P1–P8 of the evaluation design. Each goal is paired with the policy
family that addresses it, the v4 signature events the policy quantifies
over, and the dominant benchmark part that exercises it.

| Attacker goal | Policy family | v4 events | Benchmark coverage |
|---|---|---|---|
| Induce harmful textual content directly | P1, P2 | `Message`, `Completion-`, `CompletionRedacted+` | Custom chat (response-side); HarmBench |
| Extract system prompt or configured secret | P3 | `Message`, `Completion-`, secret-marker predicate | Custom chat (C-LEX); TensorTrust |
| Read sensitive files / write outside workspace | P4 | `ToolCall-` + `Classify(_, _, "path_sensitivity", _)` | Custom agent |
| Perform destructive action without approval | P5 | `ToolCall` or `ToolPlanned` + `Approve(...,"tool",...)` | Custom agent; AgentDojo Banking |
| Sensitive read → external sink | P6 | Temporal `ONCE` over `ToolCall` and `Classify` | Custom agent; AgentDojo Workspace |
| Untrusted observation → privileged action | P7 | `ToolResult` + `Untrusted` + later `ToolCall-` | Custom agent (canonical IPI); AgentDojo Workspace |
| Use tools outside task scope | P8 (partial) | `ToolCall` + per-task policy | Custom agent; AgentDojo Banking |

Some severe attacker goals are explicitly **out of v4's defended
surface** and are catalogued as signature-gap rows in the benchmark
rather than claimed defences: supply-chain injection in tool
definitions (`ToolDefined`, `SkillLoaded`), memory and retrieval-
context poisoning (`MemoryRead`, `MemoryWrite`, `RetrievedDocument`),
non-owner authority spoofing (`Actor`), unauthorised sub-agent
spawning (`SubAgentSpawned`), background-task escape (`ScheduledTask`),
and downstream injection via structured output (`StructuredOutput`).
These are documented as future-work targets and the evaluation chapter
acknowledges them rather than papering over them.

## 4. Security guarantees claimed and how they will be validated

Under the trust boundaries of §1 and the attacker model of §2–3, the
thesis claims the following guarantees. Each is tied to the benchmark
strategy that will validate it; the benchmark has not yet been run on
v4, so these are claims-to-validate rather than measured facts.

*Verdict-event correctness.* If the policy's MFOTL clause is satisfied
by the events the engine has seen, the corresponding `Block`, `Warn`,
or `Approve` verdict event is caused at the correct `tid` and `phase`.
To be validated by the verdict-event half of the two-part oracle in
proxy-isolation mode for every benchmark case.

*Suppression integrity.* The strength of this guarantee differs by surface,
because the proxy controls different things on each.

On the *response* surface the proxy owns the bytes. When a `Block` verdict at
`phase = response` fires under `enforcement_mode = enforce`, the original
`Completion` text is not forwarded to the downstream client; the released content
is either redacted or absent depending on the handler. Streaming buffers the full
upstream response before release, so there is no token-level leak. This is a hard
guarantee, validated by the released-completion check.

On the *agent* surface the proxy is a cooperative gate, not an interposition.
`POST /v1/tool_execute` returns `{decision}` and the instrumented runtime is
responsible for not executing a blocked tool. The guarantee is therefore
conditional: given a faithful adapter that routes every side-effecting tool
through the hook before the effect and honors a `block`, a blocked `ToolPlanned`
does not execute. If the adapter omits the hook, mislabels a tool, or ignores the
verdict, the effect can still happen. This is the same dependency named under
"adapter under-labelling" in section 5, stated here so the claim is not read as a
byte-level guarantee. Validated by the fake-tool-runtime state oracle, which
checks the gate decision rather than asserting the proxy itself blocked the
syscall.

*Provenance handling.* Tool results from tools not in
`backend.trusted_tool_names` are accompanied by an `Untrusted(tid,
source)` event, and policies can quantify over `Untrusted` to express
P7-class rules. To be validated by the custom agent suite's P7 cases and
by the AgentDojo Workspace and Banking subsets, where attacker payloads
are embedded in tool-readable content (email bodies, statement memos)
and the policy should block any subsequent privileged action.

*Temporal reasoning.* MFOTL clauses with `ONCE`, `EVENTUALLY`, and
windowed quantifiers fire correctly across multiple `tid`s within a
session, with `rid` available for per-user-request grouping. Validated
by the seven temporal patterns in the custom suite (§8 of the
evaluation design), reported separately so the temporal claim is
visible to a reviewer.

*Audit completeness.* Every verdict that fires during a run is emitted
as a `Block+`, `Warn+`, or `Approve+` event and is available to the
React enforcement console and the run's event log. To be validated by the
verdict-event emission rate metric in the metrics table.

## 5. Boundary failures: where the trust assumption can break

A faithful threat model identifies where the trust boundary can fail.
Three failure modes are documented here so the thesis can acknowledge
them rather than have them surprise a reviewer.

The first is *unfaithful event extraction*. The proxy reads provider
chat-API responses and extracts events. If the provider changes its
API (a new field, a renamed event, a reshaped streaming chunk format),
the proxy's extraction may omit content that should have produced a
`Completion` or `ToolCall` event. The mitigation is the provider-API
observability table in the evaluation design (§5) and the
`streaming_buffered` flag per case; the residual risk is that a new
provider behavior between thesis submission and viva could invalidate a
benchmark result. The thesis treats observed event coverage as a
design assumption to validate, not a fact.

The second is *adapter under-labelling of `Untrusted` sources*. The
agent-framework adapter (NanoClaw, OpenClaw, the AgentDojo adapter) is
responsible for emitting `Untrusted` alongside `ToolResult` events
whose source is attacker-influenceable. If the adapter omits an
`Untrusted` event where one is warranted, the MFOTL engine cannot
recover the provenance and a P7 policy will not fire. The mitigation
is the explicit list of untrusted-sourcing tools in each adapter,
reviewed alongside the policy pack. The residual risk is that a tool
the adapter author marked trusted may carry attacker-influenceable
content (a "trusted" CRM tool that returns notes the attacker can
write); the benchmark records the labelling assumption per case so
this risk is visible.

The third is *policy author error*. The YAML author is trusted, but
trusted authors make mistakes. A clause that quantifies over the wrong
`tid` or that misuses `ONCE` will not enforce the intended property.
The mitigation is the two-part oracle: if the clause is wrong, the
verdict event may still fire correctly while the state oracle catches
the missing real-world effect, or vice versa. The benchmark's
expressiveness suite is explicitly designed to exercise common policy-
authoring patterns so this class of error is surfaced during
development rather than deployment.

## 6. Out of scope

The thesis explicitly does not claim to defend against the following.
Reviewers asking "what about X?" for any of these can be answered with
"this is out of scope and is documented as such in the threat model".

Model-provider compromise: if the upstream LLM provider is compromised
and returns adversarial completions tailored to bypass EnfGuard's
policies, the proxy cannot detect this beyond what its content-based
predicates can catch. Operating-system escape: an attacker who has
already gained code execution on the proxy host can disable EnfGuard;
the trust boundary in §1 assumes the host is uncompromised. Side-channel
attacks on the host (timing, cache, power). Denial-of-service against
the proxy itself, beyond what the unbounded-consumption policies catch
at the application layer. Insider threat where the YAML author is the
attacker. Supply-chain compromise of the OCaml monitor binary or the
Python dependencies, beyond standard build-reproducibility hygiene.

## 7. Summary

EnfGuardV2 is a runtime enforcement proxy. Its security claim is that,
given a well-formed YAML policy and a correctly-emitting adapter, the
events the MFOTL engine sees are a faithful representation of the
attacker-untrusted inputs that have crossed the boundary, and that the
verdicts the engine causes are applied as suppression and audit at the
proxy. The boundary is enforced by the proxy's event-extraction
discipline, the adapter's untrusted-source labelling, and the MFOTL
engine's deterministic clause evaluation. Threats outside this
boundary — provider compromise, OS escape, side channels, insider — are
not claimed as defended, and the benchmark does not test them.

## Cross-references

- Signature rationale: `code/EnfGuardV2/notes/SIGNATURE_V4_RATIONALE.md`.
- Suppression / causation semantics: `code/EnfGuardV2/notes/PROACTIVE_SEMANTICS.md`.
- Evaluation design: `writing/planning/security-benchmark/security_benchmark_evaluation_design.md`.
- Policy families P1–P8 mapping to v4 events: §5 of the evaluation design.
- `backend.trusted_tool_names`: `code/EnfGuardV2/yaml_loader.py::_parse_trusted_tool_names`.
- `Untrusted` emission: `code/EnfGuardV2/mappings.py::collect_proposing_tools`.
