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
    def __init__(self, program, max_facts=10000, max_rounds=1000, max_work=1000000):
        self.max_facts = max_facts
        self.max_rounds = max_rounds
        self.max_work = max_work
        from .parser import parse
        self.program = validate(parse(program) if isinstance(program, str) else program)

    def evaluate(self, facts=()):
        relations = Relations((*self.program.facts, *facts))
        if any(a.negated for r in self.program.rules for a in r.body):
            raise PolicyError('Negation requires stratified evaluation')
        rounds = work = 0
        changed = True
        while changed:
            rounds += 1
            if rounds > self.max_rounds or sum(map(len, relations.data.values())) > self.max_facts:
                raise PolicyError("Evaluation budget exceeded")
            changed = False
            for rule in self.program.rules:
                for binding, support in list(join(rule.body, relations)):
                    work += 1
                    if work > self.max_work:
                        raise PolicyError("Evaluation work budget exceeded")
                    changed |= relations.add(instantiate(rule.head, binding))
        return Evaluation(relations.facts())
