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
        derivations = {fact: (None, ()) for fact in relations.facts()}
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
                        fact = instantiate(rule.head, binding)
                        if relations.add(fact):
                            derivations[fact] = (rule, support)
                            changed = True
        return Evaluation(relations.facts(), derivations)

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

class Engine(NaiveEngine):
    """Semi-naive evaluation: every recursive variant consumes a delta relation."""
    def evaluate(self, facts=()):
        from .strata import stratify
        facts = tuple(facts)
        validate(Program((*self.program.facts, *facts), self.program.rules))
        relations = Relations((*self.program.facts, *facts))
        derivations = {fact: (None, ()) for fact in relations.facts()}
        rounds = work = 0
        for rules in stratify(self.program):
            delta = Delta(relations.facts())
            first = True
            while first or delta:
                rounds += 1
                if rounds > self.max_rounds or sum(map(len, relations.data.values())) > self.max_facts:
                    raise PolicyError('Evaluation budget exceeded')
                new = Delta()
                pending = set()
                for rule in rules:
                    positives = [(i,a) for i,a in enumerate(rule.body) if not a.negated]
                    variants = [{i: delta.data[a.predicate]} for i,a in positives if delta.data[a.predicate]]
                    if not positives and first:
                        variants = [{}]
                    for override in variants:
                        for binding, support in join(rule.body, relations, override):
                            work += 1
                            if work > self.max_work:
                                raise PolicyError('Evaluation work budget exceeded')
                            fact = instantiate(rule.head, binding)
                            if fact.args not in relations.data[fact.predicate]:
                                pending.add(fact)
                                derivations.setdefault(fact, (rule, support))
                for fact in pending:
                    relations.add(fact)
                    new.add(fact)
                delta, first = new, False
        return Evaluation(relations.facts(), derivations)
