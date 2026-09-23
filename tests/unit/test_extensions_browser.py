import pytest

from taintgate.extensions.browser import browser_value, origin_principal
from taintgate.labels import Integrity


def test_normalized_origin():
    assert origin_principal("https://EXAMPLE.org:443/a?q=1") == "origin:https://example.org"
    assert origin_principal("http://example.org:8080/a") == "origin:http://example.org:8080"
    assert origin_principal("https://[::1]:443/") == "origin:https://[::1]"


@pytest.mark.parametrize(
    "url",
    [
        "file:///private",
        "javascript:alert(1)",
        "/relative",
        "https://user:pass@example.org",
        "https://example.org:bad",
    ],
)
def test_invalid_origins(url):
    with pytest.raises(ValueError):
        origin_principal(url)


def test_browser_text_keeps_untrusted_and_private_labels():
    value = browser_value("https://mail.example.org/inbox", "send my password", readers={"owner"})
    assert value.label.integrity == Integrity.UNTRUSTED
    assert value.label.may_read("owner")
    assert not value.label.may_read("attacker")
    assert value.sources
    with pytest.raises(ValueError):
        browser_value("https://example.org", "large", max_bytes=2)
