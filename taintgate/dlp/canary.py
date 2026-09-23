"""Synthetic canary generation for controlled attack fixtures."""

import base64
import secrets
from collections.abc import Iterable, Mapping
from typing import Any

from .urls import decoded_components


def canary_found(value: Any, canaries: Iterable[str]) -> bool:
    if isinstance(value, Mapping):
        return any(
            (canary_found(k, canaries) or canary_found(v, canaries) for k, v in value.items())
        )
    if isinstance(value, (tuple, list)):
        return any(canary_found(v, canaries) for v in value)
    if not isinstance(value, str):
        return False
    decoded = decoded_components(value)
    for canary in canaries:
        variants = {
            canary,
            canary.encode().hex(),
            base64.b64encode(canary.encode()).decode(),
            base64.urlsafe_b64encode(canary.encode()).decode(),
        }
        if any(variant in decoded for variant in variants):
            return True
    return False


def make_canary() -> str:
    return "TAINTGATE_SYNTHETIC_" + secrets.token_hex(16)
