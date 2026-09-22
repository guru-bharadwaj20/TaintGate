"""Supplementary secret alerts; never declassifies labelled values."""
import re
import math
from collections import Counter
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


def entropy(text):
    if not text:
        return 0.0
    return -sum((n / len(text)) * math.log2(n / len(text)) for n in Counter(text).values())


def entropy_findings(text, threshold=4.5, minimum=24):
    if not 0 <= threshold <= 8 or minimum < 8:
        raise ValueError("Invalid entropy configuration")
    return [Finding("high_entropy", m.start(), m.end()) for m in re.finditer(r"[A-Za-z0-9_+/=-]+", text)
            if len(m.group()) >= minimum and entropy(m.group()) >= threshold]


def luhn(digits):
    if not digits.isascii() or not digits.isdigit():
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        number = int(char)
        if index % 2:
            number *= 2
            number -= 9 if number > 9 else 0
        total += number
    return total % 10 == 0


def card_findings(text):
    results = []
    for match in re.finditer(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)", text):
        number = re.sub(r"[ -]", "", match.group())
        context = text[max(0, match.start() - 40):match.start()].lower()
        if 13 <= len(number) <= 19 and luhn(number) and re.search(r"card|visa|mastercard|payment|credit", context):
            results.append(Finding("payment_card", match.start(), match.end()))
    return results
