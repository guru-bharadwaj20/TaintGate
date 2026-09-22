"""Conservative preflight analysis; never replaces runtime mediation."""
import ast
import hashlib
import json
from dataclasses import dataclass, field
from taintgate.labels import Label, Integrity
from taintgate.lang import parse_plan


@dataclass(frozen=True)
class AbstractValue:
    label: Label = Label()
    shape: Label = Label()
    sources: frozenset[str] = frozenset()
    known: object = None
    resolved: bool = False

    def join(self, other):
        same = self.resolved and other.resolved and self.known == other.known
        return AbstractValue(self.label.join(other.label), self.shape.join(other.shape),
                             self.sources | other.sources, self.known if same else None, same)

class Analyzer:
    def __init__(self, tools=None, principals=(), *, strict=True):
        self.tools = tools or {}
        self.principals = frozenset(principals)
        if any(not isinstance(p, str) or not p for p in self.principals):
            raise ValueError('Invalid principal universe')
        self.strict = strict
        self.pc = Label()
        self.env = {}
        self.calls = []

    def check_label(self, label):
        if label.readers is not None and not label.readers <= self.principals:
            raise ValueError('Label readers outside configured principal universe')

    def analyze(self, source, inputs=None):
        self.env = dict(inputs or {})
        self.calls, self.pc = [], Label()
        for value in self.env.values():
            self.check_label(value.label)
        self.block(parse_plan(source, self.tools).body)
        return Analysis(dict(self.env), tuple(self.calls))

    def block(self, nodes):
        for node in nodes:
            if isinstance(node, ast.Assign):
                value = self.expression(node.value)
                self.env[node.targets[0].id] = AbstractValue(value.label.join(self.pc), value.shape.join(self.pc), value.sources, value.known, value.resolved)
            elif isinstance(node, ast.Expr):
                self.expression(node.value)
            else:
                self.control_statement(node)

    def expression(self, node):
        if isinstance(node, ast.Constant):
            return AbstractValue(known=node.value, resolved=True)
        if isinstance(node, ast.Name):
            value = self.env.get(node.id, AbstractValue(Label(Integrity.UNTRUSTED, frozenset())))
            if self.strict:
                self.pc = self.pc.join(value.label)
            return value
        if isinstance(node, ast.Call):
            return self.call(node)
        values = [self.expression(child) for child in ast.iter_child_nodes(node)
                  if isinstance(child, ast.expr)]
        label, sources = Label(), frozenset()
        for value in values:
            label, sources = label.join(value.label), sources | value.sources
        if self.strict:
            self.pc = self.pc.join(label)
        return AbstractValue(label, label, sources)

    def call(self, node):
        args = [self.expression(a) for a in node.args]
        args.extend(self.expression(k.value) for k in node.keywords)
        label = self.pc
        for arg in args:
            label = label.join(arg.label)
        if isinstance(node.func, ast.Name) and node.func.id in self.tools:
            output = self.tools[node.func.id]
            output = output.result_label if hasattr(output, 'result_label') else output
            self.check_label(output)
            self.collect_call(node, args, label)
            return AbstractValue(label.join(output), label.join(output), frozenset({node.func.id}))
        if isinstance(node.func, ast.Attribute):
            receiver = self.expression(node.func.value)
            label = label.join(receiver.label)
        if isinstance(node.func, ast.Name) and node.func.id == 'extract':
            label = label.join(Label(Integrity.UNTRUSTED))
        return AbstractValue(label, label)

    def merge_env(self, left, right):
        top = AbstractValue(Label(Integrity.UNTRUSTED, frozenset()))
        return {name: left.get(name, top).join(right.get(name, top)) for name in left.keys() | right.keys()}

    def control_statement(self, node):
        if isinstance(node, ast.If):
            condition = self.expression(node.test)
            initial = dict(self.env)
            self.pc = self.pc.join(condition.label)
            self.block(node.body)
            left = dict(self.env)
            self.env = initial
            self.block(node.orelse)
            self.env = self.merge_env(left, self.env)
        elif isinstance(node, ast.For):
            self.loop(node)

    def loop(self, node):
        collection = self.expression(node.iter)
        self.pc = self.pc.join(collection.label).join(collection.shape)
        initial = dict(self.env)
        # Labels have finite height; known values are discarded by joins.
        limit = (len(self.principals) + 3) * (len(self.env) + len(list(ast.walk(node))) + 1)
        for _ in range(limit):
            before = dict(self.env)
            self.env[node.target.id] = AbstractValue(collection.label.join(self.pc), collection.shape, collection.sources)
            self.block(node.body)
            self.env = self.merge_env(initial, self.env)
            if self.env == before:
                return
        raise ValueError('Abstract loop did not converge')

    def collect_call(self, node, args, label):
        site = CallSite(node.lineno, node.func.id, label, tuple(args))
        if site not in self.calls:
            self.calls.append(site)


@dataclass(frozen=True)
class CallSite:
    line: int
    tool: str
    label: Label
    arguments: tuple[AbstractValue, ...]

    @property
    def potentially_unsafe(self):
        return self.label.integrity == Integrity.UNTRUSTED or self.label.readers is not None or any(not a.resolved for a in self.arguments)


@dataclass(frozen=True)
class Analysis:
    environment: dict[str, AbstractValue]
    calls: tuple[CallSite, ...]

def describe_argument(value):
    if value.resolved:
        return {'resolved': True, 'value': value.known}
    return {'resolved': False, 'description': 'Runtime value unknown',
            'integrity': value.label.integrity.name,
            'readers': None if value.label.readers is None else sorted(value.label.readers)}
