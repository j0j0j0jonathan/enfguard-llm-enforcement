import logging
from pathlib import Path

from static_analysis import PredicateCall, extract_predicate_calls

_BASE_DIR = Path(__file__).resolve().parents[1]
_RUNTIME_DIR = _BASE_DIR if (_BASE_DIR / "enfguard_user.mfotl").is_file() else _BASE_DIR / "code/proxy"


def test_default_formula_with_no_predicates_is_empty():
    """The shipped fallback `enfguard_user.mfotl` is `ALWAYS TRUE` so it
    extracts no predicate calls; the events-only base sig declares no funs.

    Real policy authors paste clauses from `examples/inspiration_policies.mfotl`
    (or write their own) into `enfguard.yaml`; the loader composes those into
    `state/enfguard_composite.mfotl`, which is what static analysis sees at
    runtime."""

    calls = extract_predicate_calls(_RUNTIME_DIR / "enfguard_user.mfotl")

    assert calls == {}


def test_extracts_event_t_s_predicate_shape(tmp_path):
    sig = tmp_path / "policy.sig"
    sig.write_text(
        "fun session_risk(sid:string) : float\n"
        "Turn(tid:int, sid:string)\n"
        "Warn(tid:int, phase:string, category:string, reason:string)+\n",
        encoding="utf-8",
    )
    mfotl = tmp_path / "policy.mfotl"
    mfotl.write_text(
        """
ALWAYS (FORALL t, s.
  (Turn(t, s)
   AND session_risk(s) > 0.5)
  IMPLIES Warn(t, \"request\", "session", "risky session"))
""",
        encoding="utf-8",
    )

    calls = extract_predicate_calls(mfotl, sig)

    assert calls == {
        "Turn": [
            PredicateCall(
                predicate="session_risk",
                arg_sources=("Turn.sid",),
                event_name="Turn",
                event_arg_indices=(1,),
                variables=("s",),
            )
        ]
    }


def test_unsupported_multi_arg_predicate_logs_warning_and_skips(tmp_path, caplog):
    sig = tmp_path / "policy.sig"
    sig.write_text(
        "fun pair_check(left:string, right:string) : float\n"
        "Message(tid:int, \"system\", content:string, token_count:int)\n"
        "Completion(tid:int, content:string, token_count:int)\n"
        "Block(tid:int, phase:string, category:string, reason:string)+\n",
        encoding="utf-8",
    )
    mfotl = tmp_path / "policy.mfotl"
    mfotl.write_text(
        """
ALWAYS (FORALL t, sc, sn, rc, rn.
  (Message(t, \"system\", sc, sn)
   AND Completion(t, rc, rn)
   AND pair_check(sc, rc) > 0.5)
  IMPLIES Block(t, \"response\", "custom", "pair matched"))
""",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        calls = extract_predicate_calls(mfotl, sig)

    assert calls == {}
    assert "only single-argument predicate calls are batched" in caplog.text
    assert "falling back" in caplog.text


def test_generated_yaml_predicate_is_discovered(tmp_path):
    sig = tmp_path / "enfguard_composite.sig"
    sig.write_text(
        "fun has_magic_word(content:string) : float\n"
        "Message(tid:int, role:string, content:string, token_count:int)\n"
        "Block(tid:int, phase:string, category:string, reason:string)+\n",
        encoding="utf-8",
    )
    mfotl = tmp_path / "enfguard_composite.mfotl"
    mfotl.write_text(
        """
ALWAYS (FORALL t, c, n.
  (Message(t, \"user\", c, n)
   AND has_magic_word(c) > 0.5)
  IMPLIES Block(t, \"request\", "custom", "matched"))
""",
        encoding="utf-8",
    )

    calls = extract_predicate_calls(mfotl, sig)

    assert calls["Message"][0].predicate == "has_magic_word"
    assert calls["Message"][0].arg_sources == ("Message.content",)
