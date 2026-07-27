# EnfGuard base signature, events only:
# All predicate `fun` declarations come from correspidning yaml and are appended to a generated composite signature (`state/enfguard_composite.sig`) at runtime. 
# If a user wants to use a built-in helper such as hard_rules, contains_secrets, or model_blocklist, he declars it in YAML with `kind: builtin`.
# see writing/appendices/policy-and-signature/signature_design.pdf for design doc

# Lifecycle (3)
Session(sid:string)
Turn(tid:int, rid:string, sid:string)
Clock(tid:int, phase:string, ms:int)

# Conversation content (4)
# role in {"user", "assistant", "system", "developer"}
Message(tid:int, role:string, content:string, n:int)
Completion(tid:int, content:string, n:int)-
CompletionRedacted(tid:int, content:string, n:int)+
CompletionReleased(tid:int, content:string, n:int)

# Tool / agent (4)
# tool carries canonical tool name ("bash", "read_file",
# "web_fetch", ...). Loader-validated against a registered set.
ToolCall(tid:int, call_id:string, tool:string, input:string)-
ToolPlanned(tid:int, call_id:string, tool:string, input:string)-
ToolResult(tid:int, call_id:string, content:string, exit_code:int)
# One Classify per risk dimension. dim in {"command_risk",
# "path_sensitivity", "network_risk"}.
Classify(tid:int, call_id:string, dim:string, level:string)

# Configuration and policy state (6, emitted once per turn at Phase 1)
ModelSelection(tid:int, provider:string, model:string)
StreamConfig(tid:int, enabled:int)
PolicyActive(tid:int, policy_id:string)
SettingInt(tid:int, name:string, value:int)
SettingBool(tid:int, name:string, value:int)
SettingString(tid:int, name:string, value:string)

# Provenance (1)
# Emitted alongside every ToolResult whose proposing tool is not in
# backend.trusted_tool_names. Also emitted for other untrusted-origin
# content (paste, web fetch) when the proxy can detect it.
Untrusted(tid:int, source:string)

# Side channel (1)
UserFeedback(tid:int, kind:string, payload:string)

# Verdicts (3 causable, phase identifies which of the three enforcement
# layers the verdict applies to: "request", "response", or "tool")
Block(tid:int, phase:string, category:string, reason:string)+
Warn(tid:int, phase:string, category:string, reason:string)+
Approve(tid:int, phase:string, label:string)+

# Reserved for the RBAC / least-privilege extension. Not active yet
# Identity(tid:int, user:string, org:string)
# Capability(tid:int, name:string)
