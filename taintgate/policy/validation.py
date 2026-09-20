from . import BUILTIN_ARITIES, PolicyError, Var

def validate(program):
    arities = dict(BUILTIN_ARITIES)
    atoms = list(program.facts)
    for rule in program.rules:
        atoms.extend((rule.head, *rule.body))
    for atom in atoms:
        arity = arities.setdefault(atom.predicate, len(atom.args))
        if arity != len(atom.args):
            raise PolicyError(f'Inconsistent arity for {atom.predicate}')
    return program
