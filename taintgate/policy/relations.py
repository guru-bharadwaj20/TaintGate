from collections import defaultdict
from collections.abc import Iterable

from . import Atom, Term


class Relations:
    def __init__(self, facts: Iterable[Atom] = ()) -> None:
        self.data: dict[str, set[tuple[Term, ...]]] = defaultdict(set)
        self.indexes: dict[tuple[str, int], dict[Term, set[tuple[Term, ...]]]] = defaultdict(lambda: defaultdict(set))
        for fact in facts:
            self.add(fact)

    def add(self, fact: Atom) -> bool:
        before = len(self.data[fact.predicate])
        self.data[fact.predicate].add(fact.args)
        added = len(self.data[fact.predicate]) != before
        if added:
            for position, value in enumerate(fact.args):
                self.indexes[(fact.predicate, position)][value].add(fact.args)
        return added

    def rows(self, predicate: str, pattern: tuple[Term | None, ...] | None = None) -> set[tuple[Term, ...]]:
        if pattern is None:
            return self.data[predicate]
        candidates = [self.indexes[(predicate, i)].get(v, set())
                      for i, v in enumerate(pattern) if v is not None]
        return min(candidates, key=len) if candidates else self.data[predicate]

    def facts(self) -> frozenset[Atom]:
        return frozenset(Atom(p, row) for p, rows in self.data.items() for row in rows)
