"""Amplification and deep aliases cannot escape deterministic runtime limits."""

import pytest

from taintgate.interp import Interpreter, RuntimeFault, Tool


def test_aliased_nested_containers_consume_fuel_before_a_sink():
    calls = []
    vm = Interpreter({"send": Tool(lambda x: calls.append(x))}, lambda *args: True, fuel=100)
    with pytest.raises(RuntimeFault, match="fuel_exhausted"):
        vm.run("items = [1] * 50\nouter = [items] * 50\nsend(outer)")
    assert calls == []


@pytest.mark.parametrize(
    "source", ['x = "aaaa".replace("a", "abcdefgh")', 'x = "aaaa".replace("", "abcdefgh")']
)
def test_replace_amplification_is_rejected_before_allocation(source):
    with pytest.raises(RuntimeFault, match="result_size_limit"):
        Interpreter(max_result=10).run(source)


def test_replace_count_can_bound_the_output():
    result = Interpreter(max_result=10).run('x = "aaaa".replace("a", "ab", 1)')
    assert result["x"].value == "abaaa"


def test_huge_percent_width_is_forbidden():
    with pytest.raises(RuntimeFault, match="string_percent_format_forbidden"):
        Interpreter().run('x = "%1000000000s" % "a"')


def test_numeric_modulo_remains_supported():
    assert Interpreter().run("x = 7 % 3")["x"].value == 1
