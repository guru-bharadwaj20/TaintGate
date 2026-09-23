"""Deterministic outbound filtering; pattern detection is supplementary."""

from enum import StrEnum


class Sink(StrEnum):
    TOOL_ARGUMENT = "tool_argument"
    FINAL_RESPONSE = "final_response"
    RENDERED_DESTINATION = "rendered_destination"
