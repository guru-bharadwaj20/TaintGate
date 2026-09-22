"""Semantic validation after grammar-constrained decoding."""
from __future__ import annotations
import json
from typing import Any
from jsonschema import Draft202012Validator, FormatChecker
from taintgate.quarantine.grammar import SchemaError

FORMATS = frozenset({"email","date","date-time"})

def validate_data(value: Any, schema: dict[str,Any]) -> Any:
    Draft202012Validator(schema,format_checker=FormatChecker()).validate(value)
    return value
