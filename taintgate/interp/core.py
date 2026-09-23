"""Deterministic labelled AST execution."""

from __future__ import annotations

import ast
import operator
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol, cast

from referencing import Registry, Resource

from taintgate.labels import Integrity, Label, Labeled, provenance_id
from taintgate.lang import parse_plan


class RuntimeFault(Exception):
    def __init__(self, label: Label = Label(), code: str = "runtime_failure") -> None:
        self.label, self.code = label, code
        super().__init__(code)


class _RegistryFactory(Protocol):
    """Public attrs constructor alias is not inferred by some type checkers."""

    def __call__(self, *, retrieve: Callable[[str], Resource[Any]]) -> Registry[Any]: ...


@dataclass(frozen=True)
class Tool:
    function: Callable[..., Any]
    result_label: Label = Label(Integrity.UNTRUSTED)
    identity: str = "registered"


class Interpreter:
    arithmetic: dict[type[ast.operator], Callable[[Any, Any], Any]] = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
        ast.FloorDiv: operator.floordiv,
        ast.Mod: operator.mod,
    }
    comparisons: dict[type[ast.cmpop], Callable[[Any, Any], Any]] = {
        ast.Eq: operator.eq,
        ast.NotEq: operator.ne,
        ast.Lt: operator.lt,
        ast.LtE: operator.le,
        ast.Gt: operator.gt,
        ast.GtE: operator.ge,
        ast.In: lambda a, b: a in b,
        ast.NotIn: lambda a, b: a not in b,
        ast.Is: operator.is_,
        ast.IsNot: operator.is_not,
    }
    unary: dict[type[ast.unaryop], Callable[[Any], Any]] = {
        ast.Not: operator.not_,
        ast.USub: operator.neg,
        ast.UAdd: operator.pos,
    }

    def __init__(
        self,
        tools: dict[str, Tool] | None = None,
        authorize: Callable[[str, dict[str, Labeled], Label], bool] | None = None,
        extractor: Callable[[Any, Any], Any] | None = None,
        *,
        strict: bool = True,
        fuel: int = 10000,
        max_iterations: int = 1000,
        max_result: int = 65536,
    ) -> None:
        self.tools = tools or {}
        self.authorize = authorize or (lambda name, args, pc: False)
        self.extractor = extractor
        self.strict, self.fuel = strict, fuel
        self.fuel_limit = fuel
        self.max_iterations, self.max_result = max_iterations, max_result
        self.env: dict[str, Labeled] = {}
        self.pc, self.control = Label(), Label()
        self.pc_sources, self.control_sources = frozenset[str](), frozenset[str]()
        self.trace: list[dict[str, Any]] = []

    def effective_pc(self) -> Label:
        return self.pc.join(self.control) if self.strict else self.pc

    def effective_sources(self) -> frozenset[str]:
        return self.pc_sources | self.control_sources if self.strict else self.pc_sources

    def consume(self) -> None:
        self.fuel -= 1
        if self.fuel < 0:
            raise RuntimeFault(self.effective_pc(), "fuel_exhausted")

    def run(self, source: str, inputs: Mapping[str, Any] | None = None) -> dict[str, Labeled]:
        try:
            self.trace = []
            self.pc, self.control = Label(), Label()
            self.pc_sources, self.control_sources = frozenset(), frozenset()
            self.fuel = self.fuel_limit
            self.env = {
                k: v if isinstance(v, Labeled) else Labeled(v) for k, v in (inputs or {}).items()
            }
            for name, value in self.env.items():
                identity = provenance_id("input:" + name, value.sources)
                self.trace.append(
                    {
                        "operation": identity,
                        "parents": sorted(value.sources),
                        "label": value.label,
                        "integrity": value.label.integrity.name,
                        "readers": None
                        if value.label.readers is None
                        else sorted(value.label.readers),
                    }
                )
                self.env[name] = Labeled(value.value, value.label, value.sources | {identity})
            self.block(parse_plan(source, self.tools).body)
            return dict(self.env)
        except RuntimeFault:
            raise
        except Exception:
            raise RuntimeFault(self.effective_pc()) from None

    def block(self, statements: list[ast.stmt]) -> None:
        for node in statements:
            self.statement(node)

    def statement(self, node: ast.stmt) -> None:
        self.consume()
        if isinstance(node, ast.Expr):
            self.expression(node.value)
        elif isinstance(node, ast.Assign):
            target = node.targets[0]
            assert isinstance(target, ast.Name)
            value = self.expression(node.value)
            self.env[target.id] = Labeled(
                value.value,
                value.label.join(self.effective_pc()),
                value.sources | self.effective_sources(),
            )
        elif isinstance(node, ast.If):
            condition = self.expression(node.test)
            old_pc = self.pc
            old_sources = self.pc_sources
            self.pc = self.pc.join(condition.label)
            self.pc_sources |= condition.sources
            self.control = self.control.join(self.pc)
            try:
                self.block(node.body if condition.value else node.orelse)
            finally:
                self.pc = old_pc
                self.pc_sources = old_sources
        elif isinstance(node, ast.For):
            self.loop(node)
        else:
            raise RuntimeFault(self.effective_pc(), "unsupported_statement")

    def loop(self, node: ast.For) -> None:
        collection = self.expression(node.iter)
        if not isinstance(collection.value, (tuple, Mapping, str)):
            raise RuntimeFault(collection.label, "loop_container")
        old_pc = self.pc
        old_sources = self.pc_sources
        self.pc = self.pc.join(collection.label)
        self.pc_sources |= collection.sources
        self.control = self.control.join(self.pc)
        assert isinstance(node.target, ast.Name)
        try:
            for i, item in enumerate(collection.value):
                if i >= self.max_iterations:
                    raise RuntimeFault(self.effective_pc(), "iteration_limit")
                value = (
                    item
                    if isinstance(item, Labeled)
                    else Labeled(item, collection.label, collection.sources)
                )
                self.env[node.target.id] = Labeled(
                    value.value,
                    value.label.join(self.effective_pc()),
                    value.sources | self.effective_sources(),
                )
                self.block(node.body)
        finally:
            self.pc = old_pc
            self.pc_sources = old_sources

    def combine(self, value: Any, *operands: Labeled) -> Labeled:
        label, sources = Label(), frozenset[str]()
        for operand in operands:
            label, sources = label.join(operand.label), sources | operand.sources
        identity = provenance_id("operation:" + str(len(self.trace)), sources)
        self.trace.append(
            {
                "operation": identity,
                "parents": sorted(sources),
                "label": label,
                "integrity": label.integrity.name,
                "readers": None if label.readers is None else sorted(label.readers),
            }
        )
        return Labeled(value, label, sources | {identity})

    def raw(self, value: Any) -> Any:
        self.consume()
        if isinstance(value, Labeled):
            return self.raw(value.value)
        if isinstance(value, tuple):
            return [self.raw(v) for v in value]
        if isinstance(value, Mapping):
            return {k: self.raw(v) for k, v in value.items()}
        return value

    def flatten_label(self, value: Labeled) -> Labeled:
        self.consume()
        label, sources = value.label, value.sources
        children = (
            value.value.values()
            if isinstance(value.value, Mapping)
            else value.value
            if isinstance(value.value, tuple)
            else ()
        )
        for child in children:
            if isinstance(child, Labeled):
                item = self.flatten_label(child)
                label, sources = label.join(item.label), sources | item.sources
        if self.strict:
            self.control = self.control.join(label)
            self.control_sources |= sources
        return Labeled(value.value, label, sources)

    def check_schema_references(self, schema: Any) -> None:
        """Conservative scan before extraction; no remote schema resolution."""
        self.consume()
        if isinstance(schema, dict):
            for key, value in schema.items():
                if key in {"$recursiveRef", "$dynamicRef"}:
                    raise RuntimeFault(self.effective_pc(), "schema_recursive_reference_forbidden")
                if key == "$ref" and (not isinstance(value, str) or not value.startswith("#")):
                    raise RuntimeFault(self.effective_pc(), "schema_remote_reference_forbidden")
                self.check_schema_references(value)
        elif isinstance(schema, list):
            for value in schema:
                self.check_schema_references(value)

    def expression(self, node: ast.expr) -> Labeled:
        self.consume()
        result = self.evaluate(node)
        if isinstance(result.value, (str, tuple, Mapping)) and len(result.value) > self.max_result:
            raise RuntimeFault(result.label.join(self.effective_pc()), "result_size_limit")
        if isinstance(result.value, int) and result.value.bit_length() > self.max_result:
            raise RuntimeFault(result.label.join(self.effective_pc()), "integer_size_limit")
        if self.strict:
            self.control = self.control.join(result.label)
            self.control_sources |= result.sources
        return result

    def evaluate(self, node: ast.expr) -> Labeled:
        if isinstance(node, ast.Constant):
            return Labeled(node.value)
        if isinstance(node, ast.Name):
            return self.env[node.id]
        if isinstance(node, ast.List):
            return Labeled(tuple(self.expression(n) for n in node.elts), self.pc)
        if isinstance(node, ast.Dict):
            keys = [self.expression(n) for n in node.keys if n is not None]
            values = [self.expression(n) for n in node.values]
            return self.combine({k.value: v for k, v in zip(keys, values, strict=True)}, *keys)
        if isinstance(node, ast.BinOp):
            left, right = self.expression(node.left), self.expression(node.right)
            if isinstance(node.op, ast.Mod) and isinstance(left.value, str):
                left, right = self.flatten_label(left), self.flatten_label(right)
                raise RuntimeFault(self.effective_pc(), "string_percent_format_forbidden")
            if isinstance(node.op, ast.Mult):
                for container, count in ((left.value, right.value), (right.value, left.value)):
                    if (
                        isinstance(container, (str, tuple))
                        and isinstance(count, int)
                        and len(container) * max(count, 0) > self.max_result
                    ):
                        raise RuntimeFault(self.effective_pc(), "result_size_limit")
            return self.combine(
                self.arithmetic[type(node.op)](left.value, right.value), left, right
            )
        if isinstance(node, ast.UnaryOp):
            operand = self.expression(node.operand)
            return self.combine(self.unary[type(node.op)](operand.value), operand)
        if isinstance(node, ast.BoolOp):
            operands = []
            for item in node.values:
                result = self.expression(item)
                operands.append(result)
                if (isinstance(node.op, ast.And) and not result.value) or (
                    isinstance(node.op, ast.Or) and result.value
                ):
                    break
            return self.combine(operands[-1].value, *operands)
        if isinstance(node, ast.Compare):
            left = self.flatten_label(self.expression(node.left))
            operands = [left]
            compared = True
            for op, right_node in zip(node.ops, node.comparators, strict=True):
                right = self.flatten_label(self.expression(right_node))
                operands.append(right)
                compared = self.comparisons[type(op)](self.raw(left), self.raw(right))
                if not compared:
                    break
                left = right
            return self.combine(compared, *operands)
        if isinstance(node, ast.JoinedStr):
            parts = [
                self.flatten_label(
                    self.expression(n.value if isinstance(n, ast.FormattedValue) else n)
                )
                for n in node.values
            ]
            return self.combine("".join(str(self.raw(p)) for p in parts), *parts)
        if isinstance(node, (ast.Subscript, ast.Attribute)):
            container = self.expression(node.value)
            index = (
                self.expression(node.slice)
                if isinstance(node, ast.Subscript)
                else Labeled(node.attr)
            )
            if isinstance(node, ast.Attribute) and not isinstance(container.value, Mapping):
                raise RuntimeFault(container.label, "field_requires_mapping")
            value = container.value[index.value]
            value = (
                value
                if isinstance(value, Labeled)
                else Labeled(value, container.label, container.sources)
            )
            return self.combine(value.value, container, index, value)
        if isinstance(node, ast.Call):
            return self.call(node)
        raise RuntimeFault(self.effective_pc(), "unsupported_expression")

    def call(self, node: ast.Call) -> Labeled:
        if isinstance(node.func, ast.Attribute):
            receiver = self.expression(node.func.value)
            if not isinstance(receiver.value, str) or node.keywords:
                raise RuntimeFault(receiver.label, "string_method_receiver")
            arguments = [self.expression(n) for n in node.args]
            if node.func.attr == "replace" and len(arguments) in {2, 3}:
                old, new = arguments[0].value, arguments[1].value
                count = arguments[2].value if len(arguments) == 3 else -1
                if isinstance(old, str) and isinstance(new, str) and isinstance(count, int):
                    occurrences = receiver.value.count(old)
                    if count >= 0:
                        occurrences = min(occurrences, count)
                    if len(receiver.value) + occurrences * (len(new) - len(old)) > self.max_result:
                        raise RuntimeFault(self.effective_pc(), "result_size_limit")
            result = getattr(str, node.func.attr)(receiver.value, *(a.value for a in arguments))
            return self.combine(result, receiver, *arguments)
        assert isinstance(node.func, ast.Name)
        name = node.func.id
        args = {str(i): self.expression(n) for i, n in enumerate(node.args)}
        args.update({str(k.arg): self.expression(k.value) for k in node.keywords})
        if name == "len":
            if len(node.args) != 1 or node.keywords:
                raise RuntimeFault(code="len_arity")
            value = args["0"]
            if not isinstance(value.value, (str, tuple, Mapping)):
                raise RuntimeFault(value.label, "len_type")
            return self.combine(len(value.value), value)
        if name == "extract":
            if self.extractor is None or len(node.args) != 2 or node.keywords:
                raise RuntimeFault(code="extraction_unavailable")
            from jsonschema import Draft202012Validator

            text, schema = self.flatten_label(args["0"]), self.flatten_label(args["1"])
            raw_schema = self.raw(schema)
            self.check_schema_references(raw_schema)
            result = self.extractor(self.raw(text), raw_schema)
            extra = self.flatten_label(result if isinstance(result, Labeled) else Labeled(result))
            result = self.raw(extra)

            def deny_retrieval(uri: str) -> Resource[Any]:
                raise RuntimeFault(self.effective_pc(), "schema_remote_reference_forbidden")

            registry_factory = cast(_RegistryFactory, Registry)
            validator = Draft202012Validator(
                raw_schema, registry=registry_factory(retrieve=deny_retrieval)
            )
            validator.validate(result)
            value = self.combine(result, text, schema, extra)
            return Labeled(value.value, value.label.join(Label(Integrity.UNTRUSTED)), value.sources)
        args = {k: self.flatten_label(v) for k, v in args.items()}
        args = {
            k: Labeled(v.value, v.label, v.sources | self.effective_sources())
            for k, v in args.items()
        }
        call_sources = self.effective_sources().union(*(arg.sources for arg in args.values()))
        call_label = self.effective_pc()
        for arg in args.values():
            call_label = call_label.join(arg.label)
        call_id = provenance_id("call:" + name + ":" + str(len(self.trace)), call_sources)
        self.trace.append(
            {
                "operation": call_id,
                "parents": sorted(call_sources),
                "label": call_label,
                "integrity": call_label.integrity.name,
                "readers": None if call_label.readers is None else sorted(call_label.readers),
                "kind": "tool_call",
                "tool": name,
            }
        )
        if self.authorize(name, args, self.effective_pc()) is not True:
            raise RuntimeFault(self.effective_pc(), "tool_denied")
        tool = self.tools[name]
        if self.strict:
            self.control = self.control.join(tool.result_label)
        result = tool.function(
            *(self.raw(args[str(i)]) for i in range(len(node.args))),
            **{str(k.arg): self.raw(args[str(k.arg)]) for k in node.keywords},
        )
        label = tool.result_label.join(self.effective_pc())
        sources = call_sources | {call_id, provenance_id("tool", [tool.identity])}
        for arg in args.values():
            label, sources = label.join(arg.label), sources | arg.sources
        if isinstance(result, Labeled):
            label, sources = label.join(result.label), sources | result.sources
            result = result.value
        return Labeled(result, label, sources)
