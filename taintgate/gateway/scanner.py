"""Heuristic metadata alerts; pins and policy enforce security."""
import re
import unicodedata


def scan_description(description: str, known_tools=()):
    findings = []
    if len(description) > 4096:
        findings.append("description exceeds 4096 characters")
    if any(unicodedata.category(c) in {"Cf", "Cc"} and c not in "\n\r\t" for c in description):
        findings.append("invisible Unicode or control character")
    if re.search(r"ignore\s+(previous|prior|all)|system\s+prompt|do\s+not\s+(tell|reveal)|secretly|hide\s+this", description, re.I):
        findings.append("model-directed imperative or concealment")
    for name in known_tools:
        if re.search(r"(?<![\w-])" + re.escape(name) + r"(?![\w-])", description):
            findings.append("reference to another tool: " + name)
    return findings
