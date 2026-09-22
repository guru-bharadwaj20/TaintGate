"""Supplementary secret alerts; never declassifies labelled values."""
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    kind: str
    start: int
    end: int


PATTERNS = {
    "aws_access_key": r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    "github_token": r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b",
    "openai_key": r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b",
    "private_key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
}


def scan_secrets(text):
    findings = []
    for kind, pattern in PATTERNS.items():
        findings.extend(Finding(kind, match.start(), match.end()) for match in re.finditer(pattern, text))
    return findings
