from taintgate.extensions.suggestions import suggest_from_approved_traces


def test_only_explicitly_approved_known_traces_create_hints():
    events = [
        {"action": "allow", "user_approved": True, "tool": "send", "recipient": "owner"},
        {"action": "allow", "tool": "send", "recipient": "attacker"},
        {"action": "deny", "user_approved": True, "tool": "send", "recipient": "attacker"},
        {"action": "allow", "user_approved": True, "tool": "unknown", "recipient": "owner"},
    ]
    result = suggest_from_approved_traces(events, {"send"})
    assert len(result) == 1
    assert result[0].recipients == ("owner",)
    assert result[0].review_required is True
