from taintgate.labels import Integrity, Label, Labeled
from taintgate.static import AbstractValue, Analyzer


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

    from taintgate.interp import Interpreter, RuntimeFault, Tool
    source = 'send("hello")'
    Analyzer({'send': Label()}).analyze(source)
    with pytest.raises(RuntimeFault, match='tool_denied'):
        Interpreter({'send': Tool(lambda x: None)}).run(source)


def test_static_predicts_runtime_taint():
    from taintgate.interp import Interpreter, Tool
    for source in ['if flag:\n send("a")', 'if flag:\n x = 1\nsend("a")', 'for x in items:\n send(x)', 'send(flag)']:
        inputs = {'flag': AbstractValue(Label(Integrity.UNTRUSTED)), 'items': AbstractValue(Label(Integrity.UNTRUSTED))}
        result = Analyzer({'send': Label()}).analyze(source, inputs)
        seen = []
        vm = Interpreter({'send': Tool(lambda x: None)}, lambda name,args,pc: seen.append(pc) or True)
        vm.run(source, {'flag': Labeled(True, Label(Integrity.UNTRUSTED)), 'items': Labeled([1], Label(Integrity.UNTRUSTED))})
        assert seen and result.calls
        assert all(call.potentially_unsafe for call in result.calls)
