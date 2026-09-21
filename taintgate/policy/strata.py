from . import PolicyError

def dependency_graph(program):
    graph = {}
    for fact in program.facts:
        graph.setdefault(fact.predicate, [])
    for rule in program.rules:
        edges = graph.setdefault(rule.head.predicate, [])
        for atom in rule.body:
            graph.setdefault(atom.predicate, [])
            edges.append((atom.predicate, atom.negated))
    return graph
