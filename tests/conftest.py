"""Shared isolation for mutable classifier hooks used by mapper tests."""

import pytest

from instrlib import tool_mapper


_JUDGE_REGISTRARS = (
    tool_mapper.register_url_risk_classifier,
    tool_mapper.register_package_name_classifier,
    tool_mapper.register_webshell_classifier,
    tool_mapper.register_persistence_instruction_classifier,
    tool_mapper.register_secret_material_classifier,
    tool_mapper.register_content_disclosure_classifier,
    tool_mapper.register_broad_content_classifier,
    tool_mapper.register_memory_poison_classifier,
    tool_mapper.register_authored_capability_classifier,
    tool_mapper.register_unknown_tool_review_gate,
    tool_mapper.register_unknown_tool_classifier,
    tool_mapper.register_uncertain_action_classifier,
    tool_mapper.register_semantic_command_classifier,
)


@pytest.fixture(autouse=True)
def _isolate_mapper_judge_hooks():
    """Prevent one test's registered judge from changing later mapper tests."""
    for register in _JUDGE_REGISTRARS:
        register(None)
    yield
    for register in _JUDGE_REGISTRARS:
        register(None)
