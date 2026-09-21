from . import BUILTIN_ARITIES, PolicyError, Var

def validate(program):
    if len(program.facts) + len(program.rules) > 2000:
        raise PolicyError('Policy statement budget exceeded')
    arities = dict(BUILTIN_ARITIES)
    atoms = list(program.facts)
    for rule in program.rules:
        atoms.extend((rule.head, *rule.body))
    for atom in atoms:
        if len(atom.args) > 16:
            raise PolicyError('Predicate arity budget exceeded')
        if any(type(t) not in (str, int, Var) for t in atom.args):
            raise PolicyError('Function symbols and structured terms are forbidden')
        arity = arities.setdefault(atom.predicate, len(atom.args))
        if arity != len(atom.args):
            raise PolicyError(f'Inconsistent arity for {atom.predicate}')
    for fact in program.facts:
        if fact.negated or any(isinstance(t, Var) for t in fact.args):
            raise PolicyError('Facts must be positive and ground')
    for rule in program.rules:
        bound = {t for atom in rule.body if not atom.negated
                 for t in atom.args if isinstance(t, Var)}
        needed = {t for atom in (rule.head, *[a for a in rule.body if a.negated])
                  for t in atom.args if isinstance(t, Var)}
        if rule.head.negated or not needed <= bound:
            raise PolicyError('Unsafe head or negation variable')
    return program
