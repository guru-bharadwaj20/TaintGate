"""Consolidated recipient and supplementary secret sink checks."""

from collections.abc import Iterable, Mapping
from typing import Any

from taintgate.labels import Labeled

from .canary import canary_found
from .secrets import card_findings, indian_identifier_findings, scan_secrets
from .urls import decoded_components


def check_outbound(value: Any, principal: str, canaries: Iterable[str] = ()) -> bool:
    if isinstance(value, Labeled):
        if not value.label.may_read(principal):
            return False
        return check_outbound(value.value, principal, canaries)
    if isinstance(value, Mapping):
        return all(
            (
                check_outbound(k, principal, canaries) and check_outbound(v, principal, canaries)
                for k, v in value.items()
            )
        )
    if isinstance(value, (tuple, list)):
        return all(check_outbound(v, principal, canaries) for v in value)
    if isinstance(value, str):
        text = decoded_components(value)
        return not (
            canary_found(text, canaries)
            or scan_secrets(text)
            or card_findings(text)
            or indian_identifier_findings(text)
        )
    return type(value) in (bool, int, float, type(None))
