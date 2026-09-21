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
        from .strata import stratify
        rounds = work = 0
        for rules in stratify(self.program):
            changed = True
            while changed:
                rounds += 1
                if rounds > self.max_rounds or sum(map(len, relations.data.values())) > self.max_facts:
                    raise PolicyError("Evaluation budget exceeded")
                changed = False
                for rule in rules:
                    for binding, support in list(join(rule.body, relations)):
                        work += 1
                        if work > self.max_work:
                            raise PolicyError("Evaluation work budget exceeded")
                        changed |= relations.add(instantiate(rule.head, binding))
        return Evaluation(relations.facts())

class Delta:
    """A round's newly inserted facts, partitioned by predicate."""
    def __init__(self, facts=()):
        from collections import defaultdict
        self.data = defaultdict(set)
        for fact in facts:
            self.data[fact.predicate].add(fact.args)

    def add(self, fact):
        self.data[fact.predicate].add(fact.args)

    def __bool__(self):
        return any(self.data.values())
