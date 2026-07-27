"""Runtime schema for the event signature.

Invariant: must mirror active events in ``enfguard.sig``
This file is the formal EnfGuard contract and this module is the Python-side validator used before
events are serialized to the EnfGuard subprocess.

Enumerable string arguments have documented value sets:

* ``Message.role``       in ``{"user", "assistant", "system", "developer"}``
* ``Clock.phase``        in ``{"request", "response", "tool"}``
* ``Classify.dim``       in ``{"command_risk", "path_sensitivity", "network_risk",
                               "code_risk", "computer_risk", "unknown"}``
* ``Classify.level``     depends on ``dim`` — see CLASSIFY_LEVELS_BY_DIM below.
* ``Block.phase``        in ``{"request", "response", "tool"}``
* ``Warn.phase``         in ``{"request", "response", "tool"}``
* ``Approve.phase``      in ``{"request", "response", "tool"}``
* ``Untrusted.source``   in ``{"tool_result", "web_fetch", "retrieved_doc", "paste", ...}``

Future dims to add (see tool_mapper.py):
  - "database_risk"  for SQL/query tools  (safe | elevated | critical)
  - "memory_risk"    for vector-store / retrieval writes
  - "process_risk"   for process-management tools (list | kill | spawn)
  - "content_risk"   LLM-judge-based dim for unstructured tool inputs
  - "file_editor_op" subcommand-level risk for str_replace_based_editor
"""

from __future__ import annotations
from instrlib import Schema

# Enumerable argument value sets, so 
# Loader-validation: yaml_loader checks policy-author string literals against these sets at load time 
# and proxy emission: proxy.py and tool_mapper.py import the named constants

ROLE_USER = "user"
ROLE_ASSISTANT = "assistant"
ROLE_SYSTEM = "system"
ROLE_DEVELOPER = "developer"
VALID_ROLES = frozenset({ROLE_USER, ROLE_ASSISTANT, ROLE_SYSTEM, ROLE_DEVELOPER})

PHASE_REQUEST = "request"
PHASE_RESPONSE = "response"
PHASE_TOOL = "tool"
VALID_CLOCK_PHASES = frozenset({PHASE_REQUEST, PHASE_RESPONSE, PHASE_TOOL})
VALID_VERDICT_PHASES = frozenset({PHASE_REQUEST, PHASE_RESPONSE, PHASE_TOOL})


# Classify dimensions.
# Each dim has a fixed level vocabulary defined in CLASSIFY_LEVELS_BY_DIM.
# tool_mapper.py is the emiiter, first add there and then here 


CLASSIFY_DIM_COMMAND  = "command_risk"    # bash/shell commands
CLASSIFY_DIM_PATH     = "path_sensitivity"  # file read/write/delete/editor
CLASSIFY_DIM_NETWORK  = "network_risk"    # network/fetch calls
CLASSIFY_DIM_CODE     = "code_risk"       # python/code-exec tools
CLASSIFY_DIM_COMPUTER = "computer_risk"   # GUI / computer-use tools
CLASSIFY_DIM_UNKNOWN  = "unknown"         # sentinel for unrecognized tool categories

VALID_CLASSIFY_DIMS = frozenset({
    CLASSIFY_DIM_COMMAND,
    CLASSIFY_DIM_PATH,
    CLASSIFY_DIM_NETWORK,
    CLASSIFY_DIM_CODE,
    CLASSIFY_DIM_COMPUTER,
    CLASSIFY_DIM_UNKNOWN,
})

CLASSIFY_LEVELS_BY_DIM: dict[str, frozenset[str]] = {
    # command_risk: shell/bash commands
    CLASSIFY_DIM_COMMAND: frozenset({"safe", "elevated", "critical"}),
    # path_sensitivity: file system paths
    CLASSIFY_DIM_PATH: frozenset(
        {"credentials", "startup", "system", "user", "public"}
    ),
    # network_risk: outbound URLs
    CLASSIFY_DIM_NETWORK: frozenset({"trusted", "external", "suspicious"}),
    # code_risk: code passed to an execution tool (eval/exec/subprocess = critical)
    CLASSIFY_DIM_CODE: frozenset({"safe", "elevated", "critical"}),
    # computer_risk: GUI action type (drag/type = elevated, screenshot = safe)
    CLASSIFY_DIM_COMPUTER: frozenset({"safe", "elevated", "critical"}),
    # unknown: catch-all for tool categories not yet mapped in tool_mapper.py
    CLASSIFY_DIM_UNKNOWN: frozenset({"unclassified"}),
}



# Active event declarations. Needs to mirror ``enfguard.sig``.

EVENT_TYPES: tuple[tuple[str, tuple[type, ...]], ...] = (
    # Lifecycle (3)
    ("Session", (str,)),
    ("Turn", (int, str, str)),
    ("Clock", (int, str, int)),
    # Conversation content (4)
    ("Message", (int, str, str, int)),
    ("Completion", (int, str, int)),
    ("CompletionRedacted", (int, str, int)),
    ("CompletionReleased", (int, str, int)),
    # Tool / agent (4)
    ("ToolCall", (int, str, str, str)),
    ("ToolPlanned", (int, str, str, str)),
    ("ToolResult", (int, str, str, int)),
    ("Classify", (int, str, str, str)),
    # Configuration and policy state (6)
    ("ModelSelection", (int, str, str)),
    ("StreamConfig", (int, int)),
    ("PolicyActive", (int, str)),
    ("SettingInt", (int, str, int)),
    ("SettingBool", (int, str, int)),
    ("SettingString", (int, str, str)),
    # Provenance (1)
    ("Untrusted", (int, str)),
    # Side channel (1)
    ("UserFeedback", (int, str, str)),
    # Verdicts (3 causable)
    ("Block", (int, str, str, str)),
    ("Warn", (int, str, str, str)),
    ("Approve", (int, str, str)),
)


def build_event_schema() -> Schema:
    """Build the runtime event schema matching ``enfguard_user.sig``."""

    schema = Schema()
    for name, types in EVENT_TYPES:
        schema.add(name, list(types))
    return schema
