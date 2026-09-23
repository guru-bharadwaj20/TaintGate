from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from . import Atom, PolicyError, Program, Rule, Term
from .joins import instantiate, join
from .relations import Relations
from .validation import validate


@dataclass
class Evaluation:
    facts: frozenset[Atom]
    derivations: dict[Atom, tuple[Rule | None, tuple[Atom, ...]]] = field(default_factory=dict)

    def explain(self, fact: Atom, max_depth: int = 12, max_nodes: int = 100) -> dict[str, Any]:
        budget = [max_nodes]

        def visit(current: Atom, path: set[Atom], depth: int) -> dict[str, Any]:
            if budget[0] <= 0:
                return {"fact": repr(current), "truncated": True}
            budget[0] -= 1
            node: dict[str, Any] = {"fact": repr(current)}
            if current in path:
                return {**node, "cycle": True}
            if depth >= max_depth:
                return {**node, "truncated": True}
            entry = self.derivations.get(current)
            if entry is None:
                return {**node, "missing": True}
            rule, support = entry
            node["rule"] = repr(rule) if rule else "input fact"
            node["supports"] = []
            for item in support:
                if budget[0] <= 0:
                    node["truncated"] = True
                    break
                node["supports"].append(visit(item, path | {current}, depth + 1))
            return node

        return visit(fact, set(), 0)


class NaiveEngine:
    def __init__(
        self,
        program: Program | str,
        max_facts: int = 10000,
        max_rounds: int = 1000,
        max_work: int = 1000000,
    ) -> None:
        self.max_facts = max_facts
        self.max_rounds = max_rounds
        self.max_work = max_work
        from .parser import parse

        self.program = validate(parse(program) if isinstance(program, str) else program)

    def evaluate(self, facts: Iterable[Atom] = ()) -> Evaluation:
        facts = tuple(facts)
        validate(Program(tuple(facts)))
        combined = (*self.program.facts, *facts)
        if len(set(combined)) > self.max_facts:
            raise PolicyError("Input fact budget exceeded")
        relations = Relations(combined)
        budget = [self.max_work]
        derivations: dict[Atom, tuple[Rule | None, tuple[Atom, ...]]] = {
            fact: (None, ()) for fact in relations.facts()
        }
        from .strata import stratify

        rounds = work = 0
        for rules in stratify(self.program):
            changed = True
            while changed:
                rounds += 1
                if (
                    rounds > self.max_rounds
                    or sum(map(len, relations.data.values())) > self.max_facts
                ):
                    raise PolicyError("Evaluation budget exceeded")
                changed = False
                for rule in rules:
                    for binding, support in list(join(rule.body, relations, budget=budget)):
                        work += 1
                        if work > self.max_work:
                            raise PolicyError("Evaluation work budget exceeded")
                        fact = instantiate(rule.head, binding)
                        if relations.add(fact):
                            if sum(map(len, relations.data.values())) > self.max_facts:
                                raise PolicyError("Derived fact budget exceeded")
                            derivations[fact] = (rule, support)
                            changed = True
        return Evaluation(relations.facts(), derivations)


class Delta:
    """A round's newly inserted facts, partitioned by predicate."""

    def __init__(self, facts: Iterable[Atom] = ()) -> None:
        from collections import defaultdict

        self.data: dict[str, set[tuple[Term, ...]]] = defaultdict(set)
        for fact in facts:
            self.data[fact.predicate].add(fact.args)

    def add(self, fact: Atom) -> None:
        self.data[fact.predicate].add(fact.args)

    def __bool__(self) -> bool:
        return any(self.data.values())


class Engine(NaiveEngine):
    """Semi-naive evaluation: every recursive variant consumes a delta relation."""

    def evaluate(self, facts: Iterable[Atom] = ()) -> Evaluation:
        from .strata import stratify

        facts = tuple(facts)
        validate(Program((*self.program.facts, *facts), self.program.rules))
        facts = tuple(facts)
        validate(Program(tuple(facts)))
        combined = (*self.program.facts, *facts)
        if len(set(combined)) > self.max_facts:
            raise PolicyError("Input fact budget exceeded")
        relations = Relations(combined)
        budget = [self.max_work]
        derivations: dict[Atom, tuple[Rule | None, tuple[Atom, ...]]] = {
            fact: (None, ()) for fact in relations.facts()
        }
        rounds = work = 0
        for rules in stratify(self.program):
            delta = Delta(relations.facts())
            first = True
            while first or delta:
                rounds += 1
                if (
                    rounds > self.max_rounds
                    or sum(map(len, relations.data.values())) > self.max_facts
                ):
                    raise PolicyError("Evaluation budget exceeded")
                new = Delta()
                pending = set()
                for rule in rules:
                    positives = [(i, a) for i, a in enumerate(rule.body) if not a.negated]
                    variants = [
                        {i: delta.data[a.predicate]}
                        for i, a in positives
                        if delta.data[a.predicate]
                    ]
                    if not positives and first:
                        variants = [{}]
                    for override in variants:
                        for binding, support in join(rule.body, relations, override, budget):
                            work += 1
                            if work > self.max_work:
                                raise PolicyError("Evaluation work budget exceeded")
                            fact = instantiate(rule.head, binding)
                            if fact.args not in relations.data[fact.predicate]:
                                pending.add(fact)
                                if (
                                    sum(map(len, relations.data.values())) + len(pending)
                                    > self.max_facts
                                ):
                                    raise PolicyError("Derived fact budget exceeded")
                                derivations.setdefault(fact, (rule, support))
                for fact in pending:
                    relations.add(fact)
                    new.add(fact)
                delta, first = new, False
        return Evaluation(relations.facts(), derivations)
