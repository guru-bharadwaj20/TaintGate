"""Heuristic metadata alerts; pins and policy enforce security."""
import re


def scan_description(description: str, known_tools=()):
    findings = []
    if re.search(r"ignore\s+(previous|prior|all)|system\s+prompt|do\s+not\s+(tell|reveal)|secretly|hide\s+this", description, re.I):
        findings.append("model-directed imperative or concealment")
    for name in known_tools:
        if re.search(r"(?<![\w-])" + re.escape(name) + r"(?![\w-])", description):
            findings.append("reference to another tool: " + name)
    return findings
