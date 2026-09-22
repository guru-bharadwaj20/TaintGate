import base64
from urllib.parse import quote
from taintgate.dlp.canary import make_canary, canary_found
from taintgate.dlp.markdown import render_safe
from taintgate.dlp.outbound import check_outbound
from taintgate.dlp.urls import normalize_url, destination_allowed
from taintgate.labels import Labeled, Label


def test_encoded_canaries():
    canary = make_canary()
    for encoded in (quote(quote(canary)), canary.encode().hex(), base64.b64encode(canary.encode()).decode()):
        assert canary_found({"payload": [encoded]}, [canary])
        assert not check_outbound(encoded, "user", [canary])


def test_confidential_url_is_stripped():
    value = Labeled('![secret](https://allowed.example/?secret=hello)', Label(readers=frozenset({"user"})))
    safe = render_safe(value, {"allowed.example"})
    assert 'src=""' in safe.value and "secret=hello" not in safe.value
    assert safe.label == value.label
    assert not check_outbound(safe, "outsider")


def test_destination_normalization_and_shadowing():
    assert normalize_url("HTTPS://ExAmPle.COM:443/a") == "https://example.com/a"
    assert destination_allowed("https://example.com/x", {"example.com"})
    assert not destination_allowed("https://example.com.evil.test", {"example.com"})
    assert not destination_allowed("https://example.com@evil.test", {"example.com"})
