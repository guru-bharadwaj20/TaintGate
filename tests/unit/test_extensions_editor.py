from taintgate.extensions.editor import diagnostics, policy_diagnostics, policy_highlights


def test_valid_editor_plan():
    assert diagnostics('send("hello")', {"send"}) == ()


def test_editor_diagnostics_do_not_execute():
    assert diagnostics("import os")[0].severity == "error"
    assert diagnostics("x = (")[0].line == 1
    assert diagnostics("unknown()")[0].message == "Unregistered call"


def test_policy_editor_lexical_spans_and_parser_diagnostics():
    source = 'allow(C) :- call(C, "send").'
    assert policy_diagnostics(source) == ()
    tokens = policy_highlights(source)
    assert any(t.kind == "variable" and source[t.start : t.end] == "C" for t in tokens)
    assert any(t.kind == "string" for t in tokens)
    assert policy_diagnostics("allow(")[0].severity == "error"
