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
