"""Semantic validation after grammar-constrained decoding."""

from __future__ import annotations

import json
import math
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from taintgate.quarantine.grammar import SchemaError

FORMATS = frozenset({"email", "date", "date-time"})


def validate_data(value: Any, schema: dict[str, Any]) -> Any:
    validate_finite(value)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)
    return value


def validate_finite(value: Any, depth: int = 0) -> None:
    if depth > 32:
        raise SchemaError("Extraction nesting exceeds bounds")
    if isinstance(value, float) and not math.isfinite(value):
        raise SchemaError("Nonfinite extraction value")
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise SchemaError("Invalid Unicode scalar") from None
    elif isinstance(value, dict):
        for key, item in value.items():
            validate_finite(key, depth + 1)
            validate_finite(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            validate_finite(item, depth + 1)


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
