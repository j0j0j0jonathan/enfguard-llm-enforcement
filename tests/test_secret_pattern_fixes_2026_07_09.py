"""Secret-detection precision/recall fixes (2026-07-09).

Driven by an external review of `contains_secret_material`:

Recall (were missed before):
  * modern OpenAI project keys (`sk-proj-...`) and Anthropic keys (`sk-ant-api03-...`)
    whose body contains hyphens, which the legacy `sk-[A-Za-z0-9]{20,}` missed.
  * Stripe live keys (`sk_live_...`, `rk_live_...`) and HuggingFace tokens (`hf_...`).

Precision (were over-blocked before):
  * AWS documents dummy access keys with an EXAMPLE marker
    (`AKIAIOSFODNN7EXAMPLE`) and pastes of that tutorial value must not hard-block.

    python -m pytest tests/test_secret_pattern_fixes_2026_07_09.py -q
"""

from instrlib.tool_mapper import contains_secret_material


# --- recall: modern key shapes must now match ---------------------------------

def test_openai_project_key_caught():
    assert contains_secret_material("OPENAI_API_KEY=sk-proj-abcDEF123456_gh-ijkl7890MNOP")


def test_anthropic_key_caught():
    assert contains_secret_material("key: sk-ant-api03-AbCdEf012345-6789_ghIJKLmnop")


def test_stripe_live_key_caught():
    assert contains_secret_material("STRIPE=sk_live_51HabcdEFghiJKLmno0123")


def test_stripe_restricted_live_key_caught():
    assert contains_secret_material("rk_live_51HabcdEFghiJKLmno0123")


def test_huggingface_token_caught():
    assert contains_secret_material("hf_abcDEFghijKLMNopqrstUVWX1234")


def test_legacy_openai_key_still_caught():
    assert contains_secret_material("sk-abcDEF0123456789ghijKLMN")


# --- precision: documented dummy keys must NOT hard-block ----------------------

def test_aws_example_dummy_not_flagged():
    assert not contains_secret_material(
        "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    )


def test_aws_example_secret_value_not_flagged():
    assert not contains_secret_material(
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    )


def test_aws_temp_example_dummy_not_flagged():
    assert not contains_secret_material("ASIAIOSFODNN7EXAMPLE")


# --- guard: a real AWS key (no EXAMPLE marker) still fires ---------------------

def test_real_aws_key_still_caught():
    # 20-char AWS key (AKIA + 16) with no EXAMPLE marker.
    assert contains_secret_material("AKIABCDEFGHIJKLMNOP0")


# --- guard: placeholder path unchanged ----------------------------------------

def test_source_placeholder_still_ignored():
    assert not contains_secret_material("self.secret_key = secret_key")
    assert not contains_secret_material('API_KEY = os.environ["API_KEY"]')
