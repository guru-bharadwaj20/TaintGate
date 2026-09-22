"""Deterministic outbound filtering; pattern detection is supplementary."""
from enum import Enum


class Sink(str, Enum):
    TOOL_ARGUMENT = "tool_argument"
    FINAL_RESPONSE = "final_response"
    RENDERED_DESTINATION = "rendered_destination"
