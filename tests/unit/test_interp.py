import pytest

from taintgate.interp import Interpreter, RuntimeFault
from taintgate.labels import Integrity, Label, Labeled


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
    import json
    import subprocess
    import sys
    result = subprocess.run([sys.executable, '-I', '-c', 'import json; print(json.dumps(' + expression + '))'], capture_output=True, text=True, check=True, timeout=5)
    actual = Interpreter().run('x = ' + expression)['x'].value
    assert actual == json.loads(result.stdout)


def test_untaken_branch_assignment():
    flag = Labeled(False, Label(Integrity.UNTRUSTED))
    env = Interpreter().run('x = 0\nif flag:\n x = 1\ny = x', {'flag': flag})
    assert env['y'].label.integrity == Integrity.UNTRUSTED


def test_tool_pc():
    from taintgate.interp import Tool
    seen = []
    vm = Interpreter({'send': Tool(lambda x: None)}, lambda name, args, pc: seen.append(pc) or True)
    vm.run('if flag:\n send("constant")', {'flag': Labeled(True, Label(Integrity.UNTRUSTED))})
    assert seen[0].integrity == Integrity.UNTRUSTED


def test_error_redaction():
    from taintgate.interp import Tool
    def fail():
        raise ValueError('SECRET-CREDENTIAL')
    vm = Interpreter({'read': Tool(fail)}, lambda *args: True)
    with pytest.raises(RuntimeFault) as exc:
        vm.run('read()')
    assert 'SECRET' not in str(exc.value)
    assert exc.value.__cause__ is None


@pytest.mark.parametrize('flag', [True, False])
def test_tainted_guard_blocks_later_constant(flag):
    from taintgate.interp import Tool
    sent = []
    vm = Interpreter({'send': Tool(lambda x: sent.append(x))}, lambda name, args, pc: pc.integrity == Integrity.TRUSTED)
    with pytest.raises(RuntimeFault):
        vm.run('if flag:\n x = 1\nsend("constant")', {'flag': Labeled(flag, Label(Integrity.UNTRUSTED))})
    assert not sent


def test_nested_loop_control():
    from taintgate.interp import Tool
    seen = []
    vm = Interpreter({'send': Tool(lambda x: None)}, lambda name, args, pc: seen.append(pc) or True)
    vm.run('for x in items:\n if x:\n  send("x")', {'items': Labeled([True], Label(Integrity.UNTRUSTED))})
    assert all(p.integrity == Integrity.UNTRUSTED for p in seen)


def test_early_failure_and_fuel():
    from taintgate.interp import Tool
    sent = []
    vm = Interpreter({'send': Tool(lambda x: sent.append(x))}, lambda *args: True)
    with pytest.raises(RuntimeFault):
        vm.run('x = 1 / secret\nsend("x")', {'secret': Labeled(0, Label(Integrity.UNTRUSTED, {'owner'}))})
    assert not sent
    with pytest.raises(RuntimeFault, match='fuel_exhausted'):
        Interpreter(fuel=1).run('x = 1 + 2')
    with pytest.raises(RuntimeFault, match='result_size_limit'):
        Interpreter(max_result=10).run('x = "a" * 100')
