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


class Validator(ast.NodeVisitor):
    allowed = {ast.Module, ast.Expr, ast.Assign, ast.Name, ast.Load, ast.Store,
               ast.Constant, ast.List, ast.Dict, ast.If, ast.For, ast.Call,
               ast.keyword, ast.Compare, ast.BoolOp, ast.BinOp, ast.UnaryOp,
               ast.Subscript, ast.Attribute, ast.JoinedStr, ast.FormattedValue,
               ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod,
               ast.USub, ast.UAdd, ast.Not, ast.And, ast.Or, ast.Eq, ast.NotEq,
               ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn, ast.Is, ast.IsNot}

    def __init__(self, calls, max_depth, max_literal):
        self.calls = calls | {'len', 'extract'}
        self.max_depth, self.max_literal = max_depth, max_literal
        self.depth = 0

    def generic_visit(self, node):
        if type(node) not in self.allowed:
            raise PlanError('Unsupported syntax: ' + type(node).__name__)
        super().generic_visit(node)

    def visit_Assign(self, node):
        if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            raise PlanError('Assignment requires one name')
        self.generic_visit(node)

    def visit_Constant(self, node):
        if type(node.value) not in (str, bool, int, float, type(None)):
            raise PlanError('Unsupported literal')

    def visit_Dict(self, node):
        if any(key is None for key in node.keys):
            raise PlanError('Dictionary unpacking is forbidden')
        self.generic_visit(node)

    def visit_List(self, node):
        self.generic_visit(node)

    def visit_If(self, node):
        self.generic_visit(node)

    def visit_For(self, node):
        if not isinstance(node.target, ast.Name) or node.orelse:
            raise PlanError('For requires one target and no else')
        self.generic_visit(node)
