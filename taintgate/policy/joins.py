from . import Atom, PolicyError, Var


def match(args, row, binding):
    result = dict(binding)
    for term, value in zip(args, row):
        if isinstance(term, Var):
            if term in result and result[term] != value:
                return None
            result[term] = value
        elif term != value:
            return None
    return result

def instantiate(atom, binding):
    return Atom(atom.predicate, tuple(binding[t] if isinstance(t, Var) else t for t in atom.args))

def join(body, relations, overrides=None, budget=None):
    states = [({}, ())]
    positives = [(i, a) for i, a in enumerate(body) if not a.negated]
    negatives = [a for a in body if a.negated]
    for index, atom in positives:
        next_states = []
        for binding, support in states:
            pattern = tuple(binding.get(t) if isinstance(t, Var) else t for t in atom.args)
            rows = overrides[index] if overrides and index in overrides else relations.rows(atom.predicate, pattern)
            for row in rows:
                if budget is not None:
                    budget[0] -= 1
                    if budget[0] < 0:
                        raise PolicyError('Intermediate join work budget exceeded')
                merged = match(atom.args, row, binding)
                if merged is not None:
                    next_states.append((merged, support + (Atom(atom.predicate, row),)))
        states = next_states
    for binding, support in states:
        if all(instantiate(atom, binding).args not in relations.data[atom.predicate] for atom in negatives):
            yield binding, support
