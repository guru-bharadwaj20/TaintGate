"""Validated restricted syntax; parsing never executes the plan."""
import ast


class PlanError(ValueError):
    pass


def parse_plan(source: str, registered_calls=(), *, max_bytes=65536, max_depth=40, max_literal=8192):
    try:
        tree = ast.parse(source, mode='exec')
    except (SyntaxError, RecursionError) as exc:
        raise PlanError('Invalid plan syntax') from exc
    Validator(set(registered_calls), max_depth, max_literal).visit(tree)
    return tree
