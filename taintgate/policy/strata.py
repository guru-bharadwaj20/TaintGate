from . import PolicyError, Program, Rule

Graph = dict[str, list[tuple[str, bool]]]


def dependency_graph(program: Program) -> Graph:
    graph: Graph = {}
    for fact in program.facts:
        graph.setdefault(fact.predicate, [])
    for rule in program.rules:
        edges = graph.setdefault(rule.head.predicate, [])
        for atom in rule.body:
            graph.setdefault(atom.predicate, [])
            edges.append((atom.predicate, atom.negated))
    return graph


def components(graph: Graph) -> list[frozenset[str]]:
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
    reverse: dict[str, list[str]] = {node: [] for node in graph}
    for node, edges in graph.items():
        for dep, _ in edges:
            reverse[dep].append(node)
    assigned, result = set(), []
    for start in reversed(order):
        if start in assigned:
            continue
        group, pending = set(), [start]
        while pending:
            node = pending.pop()
            if node in assigned:
                continue
            assigned.add(node)
            group.add(node)
            pending.extend(reverse[node])
        result.append(frozenset(group))
    return result


def reject_negative_cycles(graph: Graph) -> None:
    membership = {node: i for i, group in enumerate(components(graph)) for node in group}
    for node, edges in graph.items():
        for dep, negative in edges:
            if negative and membership[node] == membership[dep]:
                raise PolicyError(f"Negative dependency cycle: {node} -> {dep}")


def stratify(program: Program) -> list[tuple[Rule, ...]]:
    graph = dependency_graph(program)
    reject_negative_cycles(graph)
    levels = {node: 0 for node in graph}
    changed = True
    while changed:
        changed = False
        for node, edges in graph.items():
            required = max((levels[dep] + int(negative) for dep, negative in edges), default=0)
            if required > levels[node]:
                levels[node] = required
                changed = True
    return [
        tuple(r for r in program.rules if levels[r.head.predicate] == i)
        for i in range(max(levels.values(), default=0) + 1)
    ]
