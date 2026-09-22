from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from taintgate.labels import Label

from . import Atom
from .engine import Evaluation


def call_facts(call_id: str, tool: str, args: Mapping[str, Any], destination: str | None = None, pc: Label | None = None) -> tuple[Atom, ...]:
    """Lower real labels recursively; invalid metadata fails closed."""
    from collections.abc import Mapping

    from taintgate.labels import Integrity, Label, Labeled

    from . import PolicyError
    facts = [Atom('call', (call_id, tool))]
    def nested(value: Any, depth: int = 0) -> Iterator[Any]:
        if depth > 32:
            raise PolicyError('Nested label budget exceeded')
        if isinstance(value, Labeled):
            if not isinstance(value.label, Label):
                raise PolicyError('Invalid runtime label')
            yield value
            yield from nested(value.value, depth + 1)
        elif isinstance(value, Mapping):
            for child in value.values():
                yield from nested(child, depth + 1)
        elif isinstance(value, (tuple, list)):
            for child in value:
                yield from nested(child, depth + 1)
    for name, value in args.items():
        if not isinstance(value, Labeled):
            raise PolicyError('Unlabelled policy argument')
        for item in nested(value):
            for source in item.sources:
                facts.append(Atom('source', (call_id, str(source))))
            if name in ('to', 'recipient', 'destination', 'url') and item.label.integrity == Integrity.UNTRUSTED:
                facts.append(Atom('untrusted_recipient', (call_id,)))
            if destination is not None and not item.label.may_read(destination):
                facts.append(Atom('reader_denied', (call_id,)))
    if pc is not None:
        if not isinstance(pc, Label):
            raise PolicyError('Invalid control-flow label')
        if pc.integrity == Integrity.UNTRUSTED:
            facts.append(Atom('untrusted_control', (call_id,)))
    return tuple(facts)

@dataclass(frozen=True)
class Decision:
    action: str
    reasons: tuple[Any, ...]

def decide(evaluation: Evaluation, call_id: str) -> Decision:
    for action in ('deny', 'ask'):
        if Atom(action, (call_id,)) in evaluation.facts:
            return Decision(action, (evaluation.explain(Atom(action, (call_id,))),))
    if Atom('allow', (call_id,)) in evaluation.facts:
        return Decision('allow', (evaluation.explain(Atom('allow', (call_id,))),))
    return Decision('deny', ('no explicit allow rule',))

def approval_facts(call_id: str, tool: str, args: Mapping[str, Any], amount_limit: float = 1000, destructive_tools: tuple[str, ...] = ()) -> tuple[Atom, ...]:
    """Numeric/destructive thresholds are deterministic facts, never model judgments."""
    facts = []
    if tool in destructive_tools:
        facts.append(Atom('approval_required', (call_id,)))
    amount = args.get('amount')
    if amount is not None:
        amount = getattr(amount, 'value', amount)
        if type(amount) not in (int, float) or not __import__('math').isfinite(amount) or amount > amount_limit:
            facts.append(Atom('approval_required', (call_id,)))
    return tuple(facts)
