"""Content-dependent scalars must include confidential element labels."""

import pytest

from taintgate.interp import Interpreter, RuntimeFault, Tool
from taintgate.labels import Label, Labeled


@pytest.mark.parametrize(
    "expression",
    ['f"{container}"', 'container == ["PRIVATE"]', '"PRIVATE" in container'],
)
def test_content_observations_retain_private_element_label(expression):
    value = Labeled([Labeled("PRIVATE", Label(readers={"owner"}))])
    sent = []
    vm = Interpreter(
        {"send": Tool(lambda body: sent.append(body))},
        lambda name, args, pc: args["0"].label.may_read("outside"),
    )
    with pytest.raises(RuntimeFault, match="tool_denied"):
        vm.run("send(" + expression + ")", {"container": value})
    assert not sent


def test_length_preserves_public_shape_for_private_elements():
    value = Labeled([Labeled("PRIVATE", Label(readers={"owner"}))])
    output = Interpreter().run("size = len(container)", {"container": value})
    assert output["size"].value == 1
    assert output["size"].label.readers is None


def test_content_failure_retains_private_error_label():
    value = Labeled([Labeled("PRIVATE", Label(readers={"owner"}))])
    with pytest.raises(RuntimeFault) as error:
        Interpreter().run('x = "%d" % container', {"container": value})
    assert error.value.label.readers == frozenset({"owner"})
    assert "PRIVATE" not in str(error.value)


def test_quarantine_consumption_joins_nested_privacy_labels():
    value = Labeled([Labeled("PRIVATE", Label(readers={"owner"}))])
    vm = Interpreter(extractor=lambda text, schema: text[0])
    result = vm.run('x = extract(container, {"type": "string"})', {"container": value})["x"]
    assert result.label.readers == frozenset({"owner"})
