"""Tiny deterministic predicates for the starter YAML.

These are intentionally boring: no LLM judge, no network call, just ordinary
Python returning a float in [0.0, 1.0].
"""


def mentions_invoice(content):
    text = str(content or "").lower()
    return 1.0 if "invoice" in text or "iban" in text else 0.0
