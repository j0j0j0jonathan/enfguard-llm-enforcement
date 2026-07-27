# Classify vocabulary

What the proxy emits for each tool call. Policies match these constants, so this
is the contract a policy author writes against. The full reference lives in the
internal `CLASSIFY_VOCABULARY.md`. This is the short version.

Source of truth: `instrlib/tool_mapper.py`, `instrlib/path_confinement.py`,
`instrlib/tool_judge.py`, `enfguard.sig`.

## Structural events

Every tool call emits a `ToolCall` (model proposed it) and, at the pre execution
gate, a `ToolPlanned` (runtime is about to run it). A `ToolResult` follows once
the tool ran. Each semantic fact is a separate `Classify(call_id, dim, level)`.

| Event | Meaning |
|---|---|
| `ToolPlanned(t, call_id, tool, input)` | Pre execution hook reached. The authoritative point to block. |
| `ToolCall(t, call_id, tool, input)` | Model proposed the call at the response phase. |
| `ToolResult(t, call_id, content, exit_code)` | Tool ran. `exit_code` 0 ok, non zero error. |
| `Classify(t, call_id, dim, level)` | One semantic fact about the call (tables below). |

`tool` is the canonical kind, never the raw name. Kinds: `bash`, `file_read`,
`file_write`, `file_delete`, `file_editor`, `search`, `network`, `code`,
`computer`, or the raw lowercased name when unrecognised.

## Canonicalization before classification

Every bash or code command is normalized before any classifier runs. The pass is
matching only and never executes anything. It strips empty quotes (`c''url`),
joins line continuations, collapses backslash splitting (`\c\a\t`), decodes hex
and octal escape clusters, substitutes `${IFS}`, and expands `$(printf ...)`,
`$(echo ...)`, and `VAR=value` assembly. Encoded execution decodes base64,
base32, and hex (including line wrapped base64) to depth 3.

## Classify dimensions

Emitted for every call:

| dim | levels |
|---|---|
| `tool_family` | shell, file, search, network, code, computer, unknown |
| `tool_name` | raw tool name, lowercased |
| `extension_tool` | skill |
| `extension_action` | create, update, delete, use, unknown |
| `extension_mechanism` | shell, code, file, network, unknown |
| `tool_status` | classified, unclassified, uncertain (deterministic coverage, no verdict) |

Emitted per call type:

| dim | levels | emitted for |
|---|---|---|
| `command_risk` | critical, elevated, safe | `bash` |
| `code_risk` | critical, elevated, safe | `code` |
| `computer_risk` | critical, elevated, safe | `computer` |
| `network_risk` | suspicious, external, trusted | `network`, and `bash` with a remote payload or upload URL |
| `path_sensitivity` | credentials, startup, system, user, public | file tools, plus credential search or sweep |
| `path_confinement` | escape, inside | any call carrying a path, resolved by realpath |
| `action_class` | the 13 categories below | bash, code, file, search, network |
| `content_risk` | instruction_like, persistence_instruction, secret_material | a `ToolResult`, not a call |

Each `action_class` also carries a sub kind dimension. The sub kinds and verdicts
per category are in the table below.

## The 13 categories

| Category | action_class | sub kind dim | default verdict |
|---|---|---|---|
| Reconnaissance | `reconnaissance` | `recon_kind` | accumulate, then Warn, then Block |
| Resource Development | `resource_development` | `resdev_kind`, optional `dependency_status` | untrusted install Block, key generation Warn |
| Initial Access | `initial_access` | `ia_kind` | brute force and webshell Block, connect after a download or credential read Block |
| Execution | `execution` | `execution_kind` | encoded and reverse shell Block, remote payload Approve |
| Persistence | `persistence` | `persistence_kind` | dangerous/system scheduler targets Block; routine schedules, shell init, and autostart Approve |
| Privilege Escalation | `privilege_escalation` | `priv_kind`, `priv_action` | change Approve, enumerate Warn, change after injection Block |
| Defense Evasion | `defense_evasion` | `evasion_kind` | disable security Block, anti audit Warn, obfuscation Warn |
| Credential Access | `credential_access` | `credential_kind` | single read Approve, sweep Block, echoed secret Block |
| Discovery | `discovery` | `discovery_kind` | accumulate, individually benign |
| Lateral Movement | `lateral_movement` | `lm_kind`, optional `credential_kind=ssh_key` | tunnel Block, pivot after a credential read Block, same-turn pivot with credential key Block |
| Collection | `collection` | `collection_kind` | sensitive copy Block, archive and dump Approve, bulk read Warn |
| Exfiltration | `exfiltration` | `exfil_kind` | covert channel and suspicious sink Block, external sink Approve |
| Impact | `impact` | `impact_kind`, `file_action` | catastrophic and protected target Block, every file delete Approve, sixth deletion after five completed deletes in one minute Block |

Clean attribution. A credential action is not also recon. An execution shape is
not also discovery. A dual use probe such as `whoami` carries both `discovery`
and `reconnaissance`. The higher severity classes suppress the generic recon and
discovery labels. Verdicts are owned by the policy YAML, not by the classifier.
The classifier only emits facts.

## Judges

The deterministic packs need no judge. Seven gated, fail open judges run only at
ingest and only when a deterministic gate opens. They cover unknown tools,
ambiguous remote payload URLs, weak persistence wording, free form secret
material, an uncertain known command, a likely typo squat package, and an
obfuscated webshell. Each emits at most one allow listed `Classify` fact or
nothing. No judge ever runs inside the formula. A judge outage degrades to
deterministic coverage with `judge_status=failed_open` telemetry.

## Coverage fallback

`tool_status` and `judge_status` make silent classifier gaps visible and policy
addressable. Neither produces a verdict on its own. A policy author can opt in to
gate anything that is `uncertain` or `unclassified` for human approval.
