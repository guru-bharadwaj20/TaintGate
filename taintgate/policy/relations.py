from collections import defaultdict
from . import Atom, Var

class Relations:
    def __init__(self, facts=()):
        self.data = defaultdict(set)
        for fact in facts:
            self.add(fact)

    def add(self, fact):
        before = len(self.data[fact.predicate])
        self.data[fact.predicate].add(fact.args)
        return len(self.data[fact.predicate]) != before

    def rows(self, predicate, pattern=None):
        return self.data[predicate]

    def facts(self):
        return frozenset(Atom(p, row) for p, rows in self.data.items() for row in rows)
