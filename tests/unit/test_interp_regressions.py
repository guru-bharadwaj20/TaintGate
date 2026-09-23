"""Small retained regressions, including a nested-container sink bypass."""
import pytest

from taintgate.interp import Interpreter, RuntimeFault, Tool
from taintgate.labels import Integrity, Label, Labeled


@pytest.mark.parametrize('expression', ['[secret]', '{"data": secret}', '[[secret]]'])
def test_nested_secret_sink(expression):
    sent = []
    vm = Interpreter({'send': Tool(lambda x: sent.append(x))},
                     lambda name, args, pc: args['0'].label.may_read('outside'), strict=False)
    with pytest.raises(RuntimeFault, match='tool_denied'):
        vm.run('send(' + expression + ')', {'secret': Labeled('PRIVATE', Label(readers={'owner'}))})
    assert not sent


def test_a1_poisoned_condition_cannot_authorize_action():
    calls = []
    vm = Interpreter({'delete': Tool(lambda: calls.append('deleted'))},
                     lambda name, args, pc: pc.integrity == Integrity.TRUSTED)
    with pytest.raises(RuntimeFault, match='tool_denied'):
        vm.run('if poisoned:\n delete()', {'poisoned': Labeled(True, Label(Integrity.UNTRUSTED))})
    assert calls == []
