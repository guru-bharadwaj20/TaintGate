"""Supplementary secret alerts; never declassifies labelled values."""

import math
import re
from collections import Counter
from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    kind: str
    start: int
    end: int


PATTERNS = {
    "aws_access_key": "\\b(?:AKIA|ASIA)[A-Z0-9]{16}\\b",
    "github_token": "\\bgh[pousr]_[A-Za-z0-9]{36,255}\\b",
    "openai_key": "\\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\\b",
    "private_key": "-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
}


def scan_secrets(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for kind, pattern in PATTERNS.items():
        findings.extend(
            Finding(kind, match.start(), match.end()) for match in re.finditer(pattern, text)
        )
    return findings


def entropy(text: str) -> float:
    if not text:
        return 0.0
    return -sum(n / len(text) * math.log2(n / len(text)) for n in Counter(text).values())


def entropy_findings(text: str, threshold: float = 4.5, minimum: int = 24) -> list[Finding]:
    if not 0 <= threshold <= 8 or minimum < 8:
        raise ValueError("Invalid entropy configuration")
    return [
        Finding("high_entropy", m.start(), m.end())
        for m in re.finditer("[A-Za-z0-9_+/=-]+", text)
        if len(m.group()) >= minimum and entropy(m.group()) >= threshold
    ]


def luhn(digits: str) -> bool:
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


def card_findings(text: str) -> list[Finding]:
    results = []
    for match in re.finditer("(?<!\\d)(?:\\d[ -]?){12,18}\\d(?!\\d)", text):
        number = re.sub("[ -]", "", match.group())
        context = text[max(0, match.start() - 40) : match.start()].lower()
        if (
            13 <= len(number) <= 19
            and luhn(number)
            and re.search("card|visa|mastercard|payment|credit", context)
        ):
            results.append(Finding("payment_card", match.start(), match.end()))
    return results


def indian_identifier_findings(text: str) -> list[Finding]:
    results = [
        Finding("pan_format", m.start(), m.end())
        for m in re.finditer("\\b[A-Z]{5}[0-9]{4}[A-Z]\\b", text)
    ]
    for match in re.finditer("(?<!\\d)[2-9]\\d{3}[ -]?\\d{4}[ -]?\\d{4}(?!\\d)", text):
        if re.search("aadhaar|aadhar|uid", text[max(0, match.start() - 40) : match.start()], re.I):
            results.append(Finding("aadhaar_format", match.start(), match.end()))
    return results
