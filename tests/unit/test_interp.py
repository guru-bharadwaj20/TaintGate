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


@pytest.mark.parametrize('expression', ['1+2*3', '8//3', 'not False', '3 < 4 < 5', 'False or 4', '"A".lower()', 'f"x{3}"', '[1,2][0]', 'len([1,2])'])
def test_python_oracle(expression):
    import subprocess, sys, json
    result = subprocess.run([sys.executable, '-I', '-c', 'import json; print(json.dumps(' + expression + '))'], capture_output=True, text=True, check=True, timeout=5)
    actual = Interpreter().run('x = ' + expression)['x'].value
    assert actual == json.loads(result.stdout)
