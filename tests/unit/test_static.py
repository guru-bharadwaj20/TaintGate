from taintgate.labels import Label, Integrity, Labeled
from taintgate.static import Analyzer, AbstractValue


def test_extract_conservative():
    source = AbstractValue(Label(Integrity.UNTRUSTED, {'owner'}))
    result = Analyzer(principals={'owner'}).analyze('x = extract(text, {})', {'text': source})
    assert result.environment['x'].label == source.label


def test_abstract_branch_pc():
    flag = AbstractValue(Label(Integrity.UNTRUSTED))
    result = Analyzer({'send': Label()}, principals={'owner'}).analyze('if flag:\n send("constant")', {'flag': flag})
    assert result.calls[0].label.integrity == Integrity.UNTRUSTED


def test_scope_changes():
    from taintgate.static import ApprovalScope
    base = ApprovalScope.create('x = 1', {'tool': 'v1'}, {'deny': True}, {'owner'})
    assert base != ApprovalScope.create('x = 2', {'tool': 'v1'}, {'deny': True}, {'owner'})
    assert base != ApprovalScope.create('x = 1', {'tool': 'v2'}, {'deny': True}, {'owner'})
    assert base != ApprovalScope.create('x = 1', {'tool': 'v1'}, {'deny': False}, {'owner'})
    assert base != ApprovalScope.create('x = 1', {'tool': 'v1'}, {'deny': True}, {'attacker'})


def test_runtime_checks_remain():
    import pytest
    from taintgate.interp import Interpreter, Tool, RuntimeFault
    source = 'send("hello")'
    Analyzer({'send': Label()}).analyze(source)
    with pytest.raises(RuntimeFault, match='tool_denied'):
        Interpreter({'send': Tool(lambda x: None)}).run(source)
