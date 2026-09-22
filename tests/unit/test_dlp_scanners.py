from taintgate.dlp.secrets import scan_secrets, card_findings, indian_identifier_findings, entropy, entropy_findings


BENIGN = ("Read the latest status", "Version 2026.10.2", "The card display is empty", "https://example.com/docs", "a" * 50, "Total cost is 1250", "Please summarize this email", "Build succeeded", "Meeting at noon", "See issue #1234")


def test_small_benign_corpus_false_positives():
    assert sum(bool(scan_secrets(text) or card_findings(text) or indian_identifier_findings(text)) for text in BENIGN) == 0


def test_synthetic_pattern_checks():
    assert scan_secrets("AKIA" + "A" * 16)
    assert card_findings("test credit card: 4111 1111 1111 1111")
    assert not card_findings("4111 1111 1111 1111")
    assert indian_identifier_findings("PAN ABCDE1234F")
    assert indian_identifier_findings("Aadhaar 2345 6789 0123")
    assert entropy("aaaa") == 0
    assert not entropy_findings("a" * 30)
