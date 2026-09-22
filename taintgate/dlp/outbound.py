"""Consolidated recipient and supplementary secret sink checks."""
from collections.abc import Mapping
from taintgate.labels import Labeled
from .canary import canary_found
from .secrets import scan_secrets, card_findings, indian_identifier_findings
from .urls import decoded_components


def check_outbound(value, principal, canaries=()):
    if isinstance(value, Labeled):
        if not value.label.may_read(principal):
            return False
        return check_outbound(value.value, principal, canaries)
    if isinstance(value, Mapping):
        return all(check_outbound(k, principal, canaries) and check_outbound(v, principal, canaries) for k, v in value.items())
    if isinstance(value, (tuple, list)):
        return all(check_outbound(v, principal, canaries) for v in value)
    if isinstance(value, str):
        text = decoded_components(value)
        return not (canary_found(text, canaries) or scan_secrets(text) or card_findings(text) or indian_identifier_findings(text))
    return type(value) in (bool, int, float, type(None))
