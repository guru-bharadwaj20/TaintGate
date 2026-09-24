"""Trust-boundary and resource-failure scenarios beyond happy-path expressions."""

import pytest

from taintgate.interp import Interpreter, RuntimeFault, Tool
from taintgate.labels import Integrity, Label, Labeled


def test_quarantine_schema_rejects_tool_shaped_output():
    calls = []
    vm = Interpreter(
        {"send": Tool(lambda x: calls.append(x))},
        lambda *args: True,
        extractor=lambda text, schema: {"tool": "send", "arguments": "secret"},
    )
    with pytest.raises(RuntimeFault):
        vm.run(
            'x = extract(text, {"type": "integer"})\nsend(x)',
            {"text": Labeled("attacker", Label(Integrity.UNTRUSTED))},
        )
    assert calls == []


def test_quarantine_labelled_output_retains_readers_and_provenance():
    vm = Interpreter(
        extractor=lambda text, schema: Labeled("typed", Label(readers={"owner"}), {"quarantine"})
    )
    result = vm.run('x = extract("input", {"type": "string"})')["x"]
    assert result.label.integrity == Integrity.UNTRUSTED
    assert result.label.readers == frozenset({"owner"})
    assert "quarantine" in result.sources


def test_truthy_policy_reply_does_not_allow_tool():
    calls = []
    vm = Interpreter({"send": Tool(lambda: calls.append(True))}, lambda *args: "allow")
    with pytest.raises(RuntimeFault, match="tool_denied"):
        vm.run("send()")
    assert calls == []


@pytest.mark.parametrize(
    "source,kwargs,code",
    [
        ("for x in [1,2]:\n y = x", {"max_iterations": 1}, "iteration_limit"),
        ("for x in 1:\n y = x", {}, "loop_container"),
        ("x = 100000", {"max_result": 8}, "integer_size_limit"),
        ('x = "abc" + "def"', {"max_result": 4}, "result_size_limit"),
        ("x = len(2)", {}, "len_type"),
        ("x = len()", {}, "len_arity"),
        ("x = 1.field", {}, "runtime_failure"),
        ("x = (1).field", {}, "field_requires_mapping"),
        ("x = 1.lower()", {}, "runtime_failure"),
        ("x = (1).lower()", {}, "string_method_receiver"),
        ('x = "abc".strip(chars="a")', {}, "string_method_receiver"),
        ('x = extract("a", {})', {}, "extraction_unavailable"),
    ],
)
def test_resource_and_type_failures_are_safe(source, kwargs, code):
    with pytest.raises(RuntimeFault, match=code):
        Interpreter(**kwargs).run(source)


def test_empty_private_loop_taints_later_action_counter():
    seen = []
    vm = Interpreter({"send": Tool(lambda: None)}, lambda name, args, pc: seen.append(pc) or False)
    with pytest.raises(RuntimeFault, match="tool_denied"):
        vm.run("for x in items:\n y = x\nsend()", {"items": Labeled([], Label(readers={"owner"}))})
    assert seen[0].readers == frozenset({"owner"})


def test_secret_lookup_failure_has_label_without_secret_text():
    vm = Interpreter()
    with pytest.raises(RuntimeFault) as error:
        vm.run('x = record["ACCOUNT-SECRET"]', {"record": Labeled({}, Label(readers={"owner"}))})
    assert error.value.label.readers == frozenset({"owner"})
    assert "ACCOUNT-SECRET" not in str(error.value)


def test_trace_edges_and_labels_contain_no_payload():
    vm = Interpreter()
    vm.run(
        'x = secret + "suffix"',
        {"secret": Labeled("PRIVATE-CANARY", Label(readers={"owner"}), {"source"})},
    )
    assert vm.trace[0]["parents"] == ["source"]
    assert any(event["parents"] for event in vm.trace)
    assert "PRIVATE-CANARY" not in repr(vm.trace)


def test_repeated_operations_have_distinct_stable_execution_nodes():
    vm = Interpreter()
    source = "x = 1 + 2\ny = 1 + 2\nz = x + y"
    vm.run(source)
    first = list(vm.trace)
    assert len({event["operation"] for event in first}) == len(first)
    assert first[-1]["parents"] == sorted([first[0]["operation"], first[1]["operation"]])
    vm.run(source)
    assert vm.trace == first


def test_control_sources_reach_constant_call_arguments():
    seen = []
    vm = Interpreter(
        {"send": Tool(lambda x: None)},
        lambda name, args, pc: seen.append(args["0"].sources) or False,
    )
    with pytest.raises(RuntimeFault):
        vm.run(
            'if condition:\n send("constant")',
            {"condition": Labeled(True, Label(Integrity.UNTRUSTED), {"mail-source"})},
        )
    assert "mail-source" in seen[0]
