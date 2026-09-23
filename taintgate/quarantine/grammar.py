"""Bounded JSON Schema normalization and deterministic GBNF generation."""

from __future__ import annotations

import itertools
import json
from collections.abc import Callable
from typing import Any


class SchemaError(ValueError):
    pass


def normalize(
    schema: dict[str, Any], root: dict[str, Any] | None = None, seen: frozenset[str] = frozenset(),
    *, _budget: list[int] | None = None, _depth: int = 0
) -> dict[str, Any]:
    if not isinstance(schema, dict) or _depth > 24:
        raise SchemaError('Invalid or excessively expanded schema')
    budget = [5000, 250000] if _budget is None else _budget
    budget[0] -= 1
    budget[1] -= sum(len(k) + len(str(v)) for k, v in schema.items() if not isinstance(v, (dict, list)))
    if min(budget) < 0:
        raise SchemaError('Schema expansion budget exceeded')
    root = schema if root is None else root
    if "$ref" in schema:
        ref = schema["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/$defs/") or ref in seen:
            raise SchemaError("Unsupported or recursive reference")
        if set(schema) - {"$ref", "title", "description"}:
            raise SchemaError("Reference siblings unsupported")
        try:
            target = root["$defs"][ref[8:]]
        except (KeyError, TypeError) as exc:
            raise SchemaError("Missing schema definition") from exc
        return normalize(target, root, seen | {ref}, _budget=budget, _depth=_depth + 1)
    result = dict(schema)
    if "properties" in result:
        result["properties"] = {
            k: normalize(v, root, seen, _budget=budget, _depth=_depth + 1) for k, v in result["properties"].items()
        }
    if "items" in result:
        result["items"] = normalize(result["items"], root, seen, _budget=budget, _depth=_depth + 1)
    if "anyOf" in result:
        result["anyOf"] = [normalize(v, root, seen, _budget=budget, _depth=_depth + 1) for v in result["anyOf"]]
    return result


def terminal(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


class Compiler:
    def __init__(self) -> None:
        self.rules: dict[str, str] = {"ws": r"[ \t\n\r]*"}
        self.handlers: dict[str, Callable[[dict[str, Any]], str]] = {}

    def compile(self, schema: dict[str, Any]) -> str:
        self.rules = {"ws": r"[ \t\n\r]*"}
        if len(json.dumps(schema)) > 100_000:
            raise SchemaError("Schema too large")
        check_depth(schema)
        expression = self.node(normalize(schema))
        if sum(len(v) for v in self.rules.values()) > 250_000:
            raise SchemaError("Grammar too large")
        return (
            "root ::= ws "
            + expression
            + " ws\n"
            + "\n".join(k + " ::= " + v for k, v in self.rules.items())
            + "\n"
        )

    def node(self, schema: dict[str, Any]) -> str:
        allowed = {
            "type",
            "properties",
            "required",
            "additionalProperties",
            "items",
            "minItems",
            "maxItems",
            "enum",
            "const",
            "anyOf",
            "minLength",
            "maxLength",
            "format",
            "$defs",
            "title",
            "description",
            "default",
            "$schema",
        }
        if set(schema) - allowed:
            raise SchemaError("Unsupported schema keyword")
        if "format" in schema and schema["format"] not in {"email", "date", "date-time"}:
            raise SchemaError("Unsupported string format")
        if "anyOf" in schema:
            choices = schema["anyOf"]
            if not choices or len(choices) > 16:
                raise SchemaError("Invalid union")
            return "(" + " | ".join(self.node(v) for v in choices) + ")"
        if isinstance(schema.get("type"), list):
            return (
                "("
                + " | ".join(self.node({**schema, "type": kind}) for kind in schema["type"])
                + ")"
            )
        if schema.get("type") == "null":
            return terminal("null")
        if "const" in schema or "enum" in schema:
            values = [schema["const"]] if "const" in schema else schema["enum"]
            if not values or len(values) > 128:
                raise SchemaError("Invalid enum bounds")
            return (
                "("
                + " | ".join(
                    terminal(
                        json.dumps(v, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
                    )
                    for v in values
                )
                + ")"
            )
        kind = schema.get("type")
        handler = self.handlers.get(kind) if isinstance(kind, str) else None
        if handler is None:
            raise SchemaError("Unsupported schema type")
        body = handler(schema)
        name = "r" + str(len(self.rules))
        self.rules[name] = body
        return name


def object_rule(compiler: Compiler, schema: dict[str, Any]) -> str:
    properties = schema.get("properties", {})
    required = set(schema.get("required", []))
    if schema.get("additionalProperties", False) is not False:
        raise SchemaError("Open objects unsupported")
    if not required <= set(properties):
        raise SchemaError("Unknown required field")
    optional = [k for k in properties if k not in required]
    if len(optional) > 8 or len(properties) > 64:
        raise SchemaError("Object exceeds bounds")
    expressions = {
        k: terminal(json.dumps(k)) + " ws " + terminal(":") + " ws " + compiler.node(v)
        for k, v in properties.items()
    }
    variants = []
    for bits in itertools.product((False, True), repeat=len(optional)):
        included = required | {k for k, b in zip(optional, bits) if b}
        body = (" ws " + terminal(",") + " ws ").join(
            expressions[k] for k in properties if k in included
        )
        variants.append(terminal("{") + " ws " + body + " ws " + terminal("}"))
    return "(" + " | ".join(variants) + ")"


def compile_schema(schema: dict[str, Any]) -> str:
    compiler = Compiler()
    compiler.handlers["object"] = lambda s: object_rule(compiler, s)
    compiler.handlers["array"] = lambda s: array_rule(compiler, s)
    compiler.handlers["string"] = lambda s: string_rule(compiler, s)
    compiler.handlers["integer"] = lambda s: r'"-"? ("0" | [1-9] [0-9]{0,18})'
    compiler.handlers["number"] = lambda s: (
        r'"-"? ("0" | [1-9] [0-9]{0,18}) ("." [0-9]{1,18})? ([eE] [+-]? [0-9]{1,3})?'
    )
    compiler.handlers["boolean"] = lambda s: '"true" | "false"'
    return compiler.compile(schema)


def array_rule(compiler: Compiler, schema: dict[str, Any]) -> str:
    minimum, maximum = schema.get("minItems", 0), schema.get("maxItems", 32)
    if type(minimum) is not int or type(maximum) is not int or not 0 <= minimum <= maximum <= 128:
        raise SchemaError("Invalid array bounds")
    item = compiler.node(schema.get("items", {}))
    variants = [
        (" ws " + terminal(",") + " ws ").join([item] * n) for n in range(minimum, maximum + 1)
    ]
    return terminal("[") + " ws (" + " | ".join(variants) + ") ws " + terminal("]")


def string_rule(compiler: Compiler, schema: dict[str, Any]) -> str:
    compiler.rules["char"] = r'[^"\\\x00-\x1f] | "\\" (["\\/bfnrt] | "u" [0-9a-fA-F]{4})'
    minimum, maximum = schema.get("minLength", 0), schema.get("maxLength", 4096)
    if type(minimum) is not int or type(maximum) is not int or not 0 <= minimum <= maximum <= 4096:
        raise SchemaError("Invalid string bounds")
    return terminal('"') + " char{" + str(minimum) + "," + str(maximum) + "} " + terminal('"')


def check_depth(value: Any, depth: int = 0) -> None:
    if depth > 24:
        raise SchemaError("Schema too deep")
    if isinstance(value, dict):
        for child in value.values():
            check_depth(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            check_depth(child, depth + 1)
