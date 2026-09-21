import pytest
from taintgate.labels import Label, Labeled, Integrity
from taintgate.interp import Interpreter, RuntimeFault


def test_immutable_alias():
    host = {'a': [1]}
    value = Labeled(host)
    host['a'].append(2)
    assert value.value['a'] == (1,)
    with pytest.raises(TypeError):
        value.value['a'] = 2


def test_assignment():
    secret = Labeled(3, Label(Integrity.UNTRUSTED, {'owner'}))
    env = Interpreter().run('y = x + 2', {'x': secret})
    assert env['y'].value == 5
    assert env['y'].label == secret.label
