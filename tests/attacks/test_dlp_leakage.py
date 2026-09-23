from taintgate.dlp.markdown import render_safe
from taintgate.dlp.outbound import check_outbound
from taintgate.labels import Integrity, Label, Labeled


def test_a7_label_blocks_unknown_secret_even_without_pattern():
    secret = Labeled(
        "unrecognizable-private-phrase", Label(Integrity.UNTRUSTED, frozenset({"owner"}))
    )
    assert not check_outbound({"body": secret}, "attacker")
    assert check_outbound(secret, "owner")
    markdown = Labeled(
        "[read](https://allowed.test/?v=unrecognizable-private-phrase)", secret.label
    )
    assert "unrecognizable-private-phrase" not in render_safe(markdown, {"allowed.test"}).value
