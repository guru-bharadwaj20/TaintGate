from . import Atom

def call_facts(call_id, tool, args, destination=None, pc=None):
    """Lower labelled arguments without granting any authority implicitly."""
    facts = [Atom('call', (call_id, tool))]
    for name, value in args.items():
        label = getattr(value, 'label', None)
        for source in getattr(value, 'sources', ()):
            facts.append(Atom('source', (call_id, str(source))))
        integrity = str(getattr(label, 'integrity', 'UNTRUSTED')).upper()
        if name in ('to', 'recipient', 'destination', 'url') and 'UNTRUSTED' in integrity:
            facts.append(Atom('untrusted_recipient', (call_id,)))
        readers = getattr(label, 'readers', frozenset())
        if destination is not None and readers is not None and destination not in readers:
            facts.append(Atom('reader_denied', (call_id,)))
    if pc is not None and 'UNTRUSTED' in str(getattr(pc, 'integrity', 'UNTRUSTED')).upper():
        facts.append(Atom('untrusted_control', (call_id,)))
    return tuple(facts)
from dataclasses import dataclass

@dataclass(frozen=True)
class Decision:
    action: str
    reasons: tuple

def decide(evaluation, call_id):
    for action in ('deny', 'ask'):
        if Atom(action, (call_id,)) in evaluation.facts:
            return Decision(action, (evaluation.explain(Atom(action, (call_id,))),))
    if Atom('allow', (call_id,)) in evaluation.facts:
        return Decision('allow', (evaluation.explain(Atom('allow', (call_id,))),))
    return Decision('deny', ('no explicit allow rule',))

def approval_facts(call_id, tool, args, amount_limit=1000, destructive_tools=()):
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
