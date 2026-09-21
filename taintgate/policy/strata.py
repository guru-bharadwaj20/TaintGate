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

def components(graph):
    """Iterative Kosaraju avoids Python stack limits on adversarial chains."""
    visited, order = set(), []
    for start in graph:
        stack = [(start, False)]
        while stack:
            node, done = stack.pop()
            if done:
                order.append(node)
                continue
            if node in visited:
                continue
            visited.add(node)
            stack.append((node, True))
            stack.extend((dep, False) for dep, _ in graph[node] if dep not in visited)
    reverse = {node: [] for node in graph}
    for node, edges in graph.items():
        for dep, _ in edges:
            reverse[dep].append(node)
    assigned, result = set(), []
    for start in reversed(order):
        if start in assigned:
            continue
        group, stack = set(), [start]
        while stack:
            node = stack.pop()
            if node in assigned:
                continue
            assigned.add(node)
            group.add(node)
            stack.extend(reverse[node])
        result.append(frozenset(group))
    return result

def reject_negative_cycles(graph):
    membership = {node: i for i, group in enumerate(components(graph)) for node in group}
    for node, edges in graph.items():
        for dep, negative in edges:
            if negative and membership[node] == membership[dep]:
                raise PolicyError(f'Negative dependency cycle: {node} -> {dep}')
