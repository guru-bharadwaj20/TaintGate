from dataclasses import dataclass, field
from . import Program, PolicyError
from .validation import validate
from .relations import Relations
from .joins import join, instantiate

@dataclass
class Evaluation:
    facts: frozenset
    derivations: dict = field(default_factory=dict)

class NaiveEngine:
    def __init__(self, program):
        from .parser import parse
        self.program = validate(parse(program) if isinstance(program, str) else program)

    def evaluate(self, facts=()):
        relations = Relations((*self.program.facts, *facts))
        if any(a.negated for r in self.program.rules for a in r.body):
            raise PolicyError('Negation requires stratified evaluation')
        changed = True
        while changed:
            changed = False
            for rule in self.program.rules:
                for binding, support in list(join(rule.body, relations)):
                    changed |= relations.add(instantiate(rule.head, binding))
        return Evaluation(relations.facts())
