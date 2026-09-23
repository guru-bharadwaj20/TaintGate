import pytest

from taintgate.interp import Interpreter, RuntimeFault


@pytest.mark.parametrize("reference", ["$ref", "$dynamicRef", "$recursiveRef"])
def test_schema_references_cannot_trigger_unmediated_network_fetch(reference):
    seen = []
    vm = Interpreter(extractor=lambda text, schema: seen.append(schema) or "typed")
    source = 'x = extract("input", {"' + reference + '": "https://attacker.example/schema"})'
    with pytest.raises(RuntimeFault, match="schema_.*reference_forbidden"):
        vm.run(source)
    assert seen == []


def test_local_nonrecursive_schema_reference_still_validates():
    vm = Interpreter(extractor=lambda text, schema: "typed")
    result = vm.run(
        'x = extract("input", {"$defs": {"text": {"type": "string"}}, "$ref": "#/$defs/text"})'
    )
    assert result["x"].value == "typed"


def test_remote_reference_hidden_in_local_target_is_rejected():
    seen = []
    vm = Interpreter(extractor=lambda text, schema: seen.append(True) or "typed")
    source = 'x = extract("input", {"$ref": "#/target", "target": {"$ref": "https://attacker.example/schema"}})'
    with pytest.raises(RuntimeFault, match="schema_remote_reference_forbidden"):
        vm.run(source)
    assert not seen
