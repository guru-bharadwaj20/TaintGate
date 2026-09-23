from taintgate.extensions.editor import diagnostics


def test_valid_editor_plan():
    assert diagnostics('send("hello")', {"send"}) == ()


def test_editor_diagnostics_do_not_execute():
    assert diagnostics("import os")[0].severity == "error"
    assert diagnostics("x = (")[0].line == 1
    assert diagnostics("unknown()")[0].message == "Unregistered call"
