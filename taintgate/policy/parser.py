"""Policy parser; accepts no Python expressions or executable functions."""
import re
import json
from . import Atom, Program, Rule, Var, PolicyError

_TOKEN = re.compile(r'\s*(?:(?P<ident>[A-Za-z_][A-Za-z_0-9]*)|(?P<int>-?\d+)|(?P<string>"(?:[^"\\]|\\.)*")|(?P<symbol>:-|[(),.]))')

def _tokens(text):
    pos = 0
    result = []
    while pos < len(text):
        if not text[pos:].strip():
            break
        match = _TOKEN.match(text, pos)
        if not match:
            raise PolicyError(f'Invalid policy token at offset {pos}')
        result.append((match.lastgroup, match.group(match.lastgroup)))
        pos = match.end()
    return result

class Parser:
    def __init__(self, text):
        self.tokens = _tokens(text)
        self.pos = 0

    def take(self, expected=None):
        if self.pos >= len(self.tokens):
            raise PolicyError('Unexpected end of policy')
        kind, value = self.tokens[self.pos]
        if expected is not None and value != expected:
            raise PolicyError(f'Expected {expected!r}, got {value!r}')
        self.pos += 1
        return kind, value

    def peek(self):
        return self.tokens[self.pos][1] if self.pos < len(self.tokens) else None

    def term(self):
        kind, value = self.take()
        if kind == 'ident' and value[0].isupper():
            return Var(value)
        if kind == 'int':
            return int(value)
        if kind == 'string':
            try:
                return json.loads(value)
            except ValueError as exc:
                raise PolicyError('Invalid string escape') from exc
        raise PolicyError('Expected variable, integer, or quoted string')

    def atom(self):
        negated = self.peek() == 'not'
        if negated:
            self.take('not')
        kind, name = self.take()
        if kind != 'ident' or not name[0].islower():
            raise PolicyError('Predicate must begin lowercase')
        self.take('(')
        args = []
        if self.peek() != ')':
            args.append(self.term())
            while self.peek() == ',':
                self.take(',')
                args.append(self.term())
        self.take(')')
        return Atom(name, tuple(args), negated)

    def parse(self):
        facts, rules = [], []
        while self.peek() is not None:
            head = self.atom()
            if head.negated:
                raise PolicyError('Negated heads are forbidden')
            if self.peek() == ':-':
                self.take(':-')
                body = [self.atom()]
                while self.peek() == ',':
                    self.take(',')
                    body.append(self.atom())
                rules.append(Rule(head, tuple(body)))
            else:
                facts.append(head)
            self.take('.')
        return Program(tuple(facts), tuple(rules))

def parse(text):
    from .validation import validate
    return validate(Parser(text).parse())
