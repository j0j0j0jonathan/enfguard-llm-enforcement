"""Regression tests for R2 (download-vocabulary expansion) and R3
(obfuscated-IP / userinfo URL risk).

Separate from the generic shell-hardening (`_deobfuscate`) so the two concerns
stay distinguishable: R2/R3 widen the URL / download vocabulary only.

    python -m pytest tests/test_tool_mapper_url_download_vocab.py -q
"""

from __future__ import annotations

from instrlib.tool_mapper import classify_resdev_kind, classify_url


# --- R2: download vocabulary --------------------------------------------------

def test_extra_url_fetchers_are_downloads():
    for cmd in (
        "aria2c https://h/payload.bin",
        "axel https://h/tool.tgz",
        "lftp -e 'get pkg.tgz' https://h/",
        "tftp -g -r boot.img https://h/",
    ):
        assert classify_resdev_kind(cmd) == "download", cmd


def test_general_http_client_get_is_not_a_download():
    # httpie / `http GET` is a request, not a save — excluded on purpose.
    assert classify_resdev_kind("http GET https://api/x") != "download"
    assert classify_resdev_kind("httpie https://api/x") != "download"


def test_download_vocab_does_not_overfire_on_benign():
    # plain API GET / status checks (no save) must not become a download
    for cmd in ("curl https://api.example.com/v1/status", "http GET https://api/x",
                "echo aria2c is a downloader"):
        assert classify_resdev_kind(cmd) != "download", cmd


def test_scp_rsync_remain_outside_download_vocab():
    # direction-ambiguous transfer tools are intentionally not download (upload
    # stays owned by Exfiltration); they must not be mislabeled download here.
    for cmd in ("scp user@h:/p .", "rsync -av remote:/d ./d"):
        assert classify_resdev_kind(cmd) != "download", cmd


# --- R3: obfuscated-IP / userinfo URL risk ------------------------------------

def test_obfuscated_ip_urls_are_suspicious():
    for url in (
        "http://0x7f000001/x",                 # hex IP
        "http://2130706433/x",                 # decimal IP
        "http://0x7f.0x0.0x0.0x1/x",           # dotted hex
        "http://0177.0000.0000.0001/x",        # dotted octal
        "http://github.com@evil.tld/x",        # userinfo '@' host-spoof
    ):
        assert classify_url(url) == "suspicious", url


def test_normal_urls_keep_their_class():
    assert classify_url("https://github.com/o/r") == "trusted"
    assert classify_url("https://pypi.org/simple") == "trusted"
    assert classify_url("https://webhook.site/abc/x") == "suspicious"
    assert classify_url("https://example.com/data.json") == "external"
    # a plain dotted-decimal IP is ordinary external, not auto-suspicious
    assert classify_url("http://93.184.216.34/x") == "external"
