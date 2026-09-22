"""Bounded JSON Schema normalization and deterministic GBNF generation."""
from __future__ import annotations
import itertools
import json
from typing import Any, Callable

class SchemaError(ValueError):
    pass

def normalize(schema: dict[str, Any], root: dict[str, Any] | None = None, seen: frozenset[str] = frozenset()) -> dict[str, Any]:
    root = schema if root is None else root
    if "$ref" in schema:
        ref = schema["$ref"]
        if not isinstance(ref,str) or not ref.startswith("#/$defs/") or ref in seen:
            raise SchemaError("Unsupported or recursive reference")
        if set(schema)-{"$ref","title","description"}:
            raise SchemaError("Reference siblings unsupported")
        try:
            target = root["$defs"][ref[8:]]
        except (KeyError,TypeError) as exc:
            raise SchemaError("Missing schema definition") from exc
        return normalize(target,root,seen|{ref})
    result = dict(schema)
    if "properties" in result:
        result["properties"] = {k:normalize(v,root,seen) for k,v in result["properties"].items()}
    if "items" in result:
        result["items"] = normalize(result["items"],root,seen)
    if "anyOf" in result:
        result["anyOf"] = [normalize(v,root,seen) for v in result["anyOf"]]
    return result

def terminal(value: str) -> str:
    return json.dumps(value,ensure_ascii=True)

class Compiler:
    def __init__(self) -> None:
        self.rules: dict[str,str] = {"ws": '[ \t\n\r]*'}
        self.handlers: dict[str,Callable[[dict[str,Any]],str]] = {}

    def compile(self, schema: dict[str,Any]) -> str:
        self.rules = {"ws": '[ \t\n\r]*'}
        expression = self.node(normalize(schema))
        return "root ::= ws " + expression + " ws\n" + "\n".join(k+" ::= "+v for k,v in self.rules.items()) + "\n"

    def node(self, schema: dict[str,Any]) -> str:
        kind = schema.get("type")
        handler = self.handlers.get(kind)
        if handler is None:
            raise SchemaError("Unsupported schema type")
        body = handler(schema)
        name = "r"+str(len(self.rules))
        self.rules[name] = body
        return name


def object_rule(compiler: Compiler, schema: dict[str,Any]) -> str:
    properties = schema.get("properties",{})
    required = set(schema.get("required",properties))
    if required != set(properties):
        raise SchemaError("Optional fields not yet supported")
    fields = [terminal(json.dumps(k))+" ws "+terminal(":")+" ws "+compiler.node(v) for k,v in properties.items()]
    body = (" ws "+terminal(",")+" ws ").join(fields)
    return terminal("{")+" ws "+body+" ws "+terminal("}")

def compile_schema(schema: dict[str,Any]) -> str:
    compiler = Compiler()
    compiler.handlers["object"] = lambda s:object_rule(compiler,s)
    return compiler.compile(schema)
