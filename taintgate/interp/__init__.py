"""Small AST interpreter. No host execution of plan text."""
import ast
import operator
from collections.abc import Mapping
from dataclasses import dataclass
from taintgate.labels import Label, Labeled, Integrity, provenance_id
from taintgate.lang import parse_plan


class RuntimeFault(Exception):
    def __init__(self, label=Label(), code='runtime_failure'):
        self.label, self.code = label, code
        super().__init__(code)


class Interpreter:
    def __init__(self, tools=None, authorize=None, extractor=None, *, strict=True,
                 fuel=10000, max_iterations=1000, max_result=65536):
        self.tools = tools or {}
        self.authorize = authorize or (lambda name, args, pc: False)
        self.extractor = extractor
        self.env = {}
        self.pc = Label()
        self.control = Label()
        self.strict = strict
        self.fuel = fuel
        self.max_iterations, self.max_result = max_iterations, max_result
        self.trace = []

    def run(self, source, inputs=None):
        self.env = {k: v if isinstance(v, Labeled) else Labeled(v) for k, v in (inputs or {}).items()}
        tree = parse_plan(source, self.tools)
        self.block(tree.body)
        return dict(self.env)

    def block(self, statements):
        for node in statements:
            self.statement(node)

    def expression(self, node):
        if isinstance(node, ast.Constant):
            return Labeled(node.value)
        if isinstance(node, ast.Name):
            return self.env[node.id]
        return self.complex_expression(node)

    def statement(self, node):
        if isinstance(node, ast.Expr):
            self.expression(node.value)
            return
        raise RuntimeFault(code='unsupported_statement')

    def complex_expression(self, node):
        raise RuntimeFault(code='unsupported_expression')

    _statement_base = statement

    def statement(self, node):
        if isinstance(node, ast.Assign):
            self.env[node.targets[0].id] = self.expression(node.value)
            return
        return self._statement_base(node)

    def combine(self, value, *operands):
        label = Label()
        sources = frozenset()
        for operand in operands:
            label = label.join(operand.label)
            sources |= operand.sources
        return Labeled(value, label, sources)

    arithmetic = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
                  ast.Div: operator.truediv, ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod}
    unary = {ast.Not: operator.not_, ast.USub: operator.neg, ast.UAdd: operator.pos}
    _complex_base = complex_expression

    def complex_expression(self, node):
        if isinstance(node, ast.BinOp):
            a, b = self.expression(node.left), self.expression(node.right)
            return self.combine(self.arithmetic[type(node.op)](a.value, b.value), a, b)
        if isinstance(node, ast.UnaryOp):
            a = self.expression(node.operand)
            return self.combine(self.unary[type(node.op)](a.value), a)
        return self._complex_base(node)

    comparisons = {ast.Eq: operator.eq, ast.NotEq: operator.ne, ast.Lt: operator.lt,
                   ast.LtE: operator.le, ast.Gt: operator.gt, ast.GtE: operator.ge,
                   ast.In: lambda a,b: a in b, ast.NotIn: lambda a,b: a not in b,
                   ast.Is: operator.is_, ast.IsNot: operator.is_not}
    _complex_arithmetic = complex_expression

    def complex_expression(self, node):
        if isinstance(node, ast.Compare):
            a = self.expression(node.left)
            operands = [a]
            result = True
            for op, right in zip(node.ops, node.comparators):
                b = self.expression(right)
                operands.append(b)
                result = self.comparisons[type(op)](self.raw(a), self.raw(b))
                if not result:
                    break
                a = b
            return self.combine(result, *operands)
        return self._complex_arithmetic(node)

    def raw(self, value):
        if isinstance(value, Labeled):
            return self.raw(value.value)
        if isinstance(value, tuple):
            return [self.raw(v) for v in value]
        if isinstance(value, Mapping):
            return {k: self.raw(v) for k, v in value.items()}
        return value

    _complex_compare = complex_expression

    def complex_expression(self, node):
        if isinstance(node, ast.BoolOp):
            operands = []
            for item in node.values:
                result = self.expression(item)
                operands.append(result)
                if (isinstance(node.op, ast.And) and not result.value) or (isinstance(node.op, ast.Or) and result.value):
                    break
            return self.combine(result.value, *operands)
        return self._complex_compare(node)

    _complex_boolean = complex_expression

    def complex_expression(self, node):
        if isinstance(node, ast.JoinedStr):
            parts = [self.expression(n.value if isinstance(n, ast.FormattedValue) else n) for n in node.values]
            return self.combine(''.join(str(p.value) for p in parts), *parts)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            receiver = self.expression(node.func.value)
            if not isinstance(receiver.value, str):
                raise RuntimeFault(receiver.label, 'string_method_receiver')
            args = [self.expression(n) for n in node.args]
            if node.keywords:
                raise RuntimeFault(code='string_method_keywords')
            result = getattr(str, node.func.attr)(receiver.value, *(a.value for a in args))
            return self.combine(result, receiver, *args)
        return self._complex_boolean(node)

    _complex_string = complex_expression

    def complex_expression(self, node):
        if isinstance(node, ast.List):
            return Labeled(tuple(self.expression(n) for n in node.elts), self.pc)
        return self._complex_string(node)

    _complex_list = complex_expression

    def complex_expression(self, node):
        if isinstance(node, ast.Dict):
            keys = [self.expression(n) for n in node.keys]
            values = [self.expression(n) for n in node.values]
            return self.combine({k.value: v for k, v in zip(keys, values)}, *keys)
        return self._complex_list(node)

    _complex_dict = complex_expression

    def complex_expression(self, node):
        if isinstance(node, ast.Subscript):
            container, index = self.expression(node.value), self.expression(node.slice)
            result = container.value[index.value]
            result = result if isinstance(result, Labeled) else Labeled(result, container.label, container.sources)
            return self.combine(result.value, container, index, result)
        return self._complex_dict(node)

    _complex_index = complex_expression

    def complex_expression(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'len':
            if len(node.args) != 1 or node.keywords:
                raise RuntimeFault(code='len_arity')
            value = self.expression(node.args[0])
            if not isinstance(value.value, (str, tuple, Mapping)):
                raise RuntimeFault(value.label, 'len_type')
            return self.combine(len(value.value), value)
        return self._complex_index(node)

    _complex_len = complex_expression

    def complex_expression(self, node):
        if isinstance(node, ast.Attribute):
            container = self.expression(node.value)
            if not isinstance(container.value, Mapping):
                raise RuntimeFault(container.label, 'field_requires_mapping')
            value = container.value[node.attr]
            value = value if isinstance(value, Labeled) else Labeled(value, container.label)
            return self.combine(value.value, container, value)
        return self._complex_len(node)

    _complex_field = complex_expression

    def complex_expression(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in self.tools:
            name = node.func.id
            args = {str(i): self.expression(n) for i, n in enumerate(node.args)}
            args.update({k.arg: self.expression(k.value) for k in node.keywords})
            if self.authorize(name, args, self.effective_pc()) is not True:
                raise RuntimeFault(self.effective_pc(), 'tool_denied')
            positional = [self.raw(args[str(i)]) for i in range(len(node.args))]
            keyword = {k.arg: self.raw(args[k.arg]) for k in node.keywords}
            return self.tool_result(self.tools[name], positional, keyword, args)
        return self._complex_field(node)

    def effective_pc(self):
        return self.pc.join(self.control) if self.strict else self.pc

    def tool_result(self, tool, positional, keyword, args):
        result = tool.function(*positional, **keyword)
        label = tool.result_label.join(self.effective_pc())
        for arg in args.values():
            label = label.join(arg.label)
        if isinstance(result, Labeled):
            label = label.join(result.label)
            sources, result = result.sources, result.value
        else:
            sources = frozenset()
        return Labeled(result, label, sources | {provenance_id('tool', [str(tool.identity)])})


@dataclass(frozen=True)
class Tool:
    function: object
    result_label: Label = Label(Integrity.UNTRUSTED)
    identity: str = 'registered'

_before_extract = Interpreter.complex_expression


def _extract_expression(self, node):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'extract':
        if self.extractor is None or len(node.args) != 2 or node.keywords:
            raise RuntimeFault(code='extraction_unavailable')
        text, schema = [self.expression(n) for n in node.args]
        from jsonschema import validate
        result = self.extractor(self.raw(text), self.raw(schema))
        validate(result, self.raw(schema))
        value = self.combine(result, text, schema)
        return Labeled(value.value, value.label.join(Label(Integrity.UNTRUSTED)), value.sources)
    return _before_extract(self, node)


Interpreter.complex_expression = _extract_expression

_before_provenance = Interpreter.combine


def _combine_provenance(self, value, *operands):
    result = _before_provenance(self, value, *operands)
    identity = provenance_id('operation', result.sources)
    self.trace.append({'operation': identity, 'label': result.label})
    return Labeled(result.value, result.label, result.sources | {identity})


Interpreter.combine = _combine_provenance
