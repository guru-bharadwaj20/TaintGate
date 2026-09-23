"""Semantic validation after grammar-constrained decoding."""

from __future__ import annotations

import json
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from taintgate.quarantine.grammar import SchemaError

FORMATS = frozenset({"email", "date", "date-time"})


def validate_data(value: Any, schema: dict[str, Any]) -> Any:
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)
    return value


def parse_validated(raw: str, schema: dict[str, Any]) -> Any:
    if len(raw.encode()) > 100_000:
        raise SchemaError("Extraction response too large")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise SchemaError("Duplicate extraction field")
            result[key] = value
        return result

    def bad_constant(value: str) -> Any:
        raise SchemaError("Nonfinite extraction value")

    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=bad_constant)
    return validate_data(value, schema)
