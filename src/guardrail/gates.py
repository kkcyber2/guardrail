"""The four validation gates."""
from __future__ import annotations

import json
import re
from typing import Any

from .verdict import Action, Reason

# --------------------------------------------------------------------------- #
# Schema
# --------------------------------------------------------------------------- #
TYPE_MAP = {
    "str": str,
    "int": int,
    "float": (int, float),
    "bool": bool,
    "list": list,
    "dict": dict,
}


def gate_schema(text: str, schema: dict[str, str] | None) -> Reason | None:
    """Check that `text` is JSON matching a {field: type} schema."""
    if schema is None:
        return None
    try:
        payload = json.loads(text)
    except (ValueError, TypeError):
        return Reason("schema", Action.BLOCK, "Output is not valid JSON.")
    if not isinstance(payload, dict):
        return Reason("schema", Action.BLOCK, "Output is not a JSON object.")
    problems: list[str] = []
    for field_name, expected in schema.items():
        if field_name not in payload:
            problems.append(f"missing field {field_name!r}")
            continue
        python_type = TYPE_MAP.get(expected)
        if python_type is None:
            problems.append(f"unknown expected type {expected!r} for {field_name!r}")
            continue
        value = payload[field_name]
        # bool is a subclass of int; do not let True satisfy an int field.
        if expected == "int" and isinstance(value, bool):
            problems.append(f"field {field_name!r} should be int, got bool")
        elif not isinstance(value, python_type):
            problems.append(
                f"field {field_name!r} should be {expected}, got {type(value).__name__}"
            )
    if problems:
        return Reason("schema", Action.BLOCK, "; ".join(problems), problems)
    return None


# --------------------------------------------------------------------------- #
# PII
# --------------------------------------------------------------------------- #
PII_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("email", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("phone", re.compile(r"(?<!\d)(?:\+?\d{1,3}[\s.\-]?)?(?:\(\d{3}\)|\d{3})[\s.\-]?\d{3}[\s.\-]?\d{4}(?!\d)")),
    ("card", re.compile(r"(?<!\d)(?:\d[ \-]?){13,19}(?!\d)")),
    ("ssn", re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")),
    ("ipv4", re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")),
)

REDACTION = {
    "email": "[email redacted]",
    "phone": "[phone redacted]",
    "card": "[card redacted]",
    "ssn": "[id redacted]",
    "ipv4": "[ip redacted]",
}


def _luhn(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def find_pii(text: str) -> dict[str, list[str]]:
    """Return {kind: [matches]}. Card numbers must pass the Luhn check."""
    found: dict[str, list[str]] = {}
    for kind, pattern in PII_PATTERNS:
        matches = []
        for match in pattern.finditer(text):
            value = match.group(0)
            if kind == "card" and not _luhn(value):
                continue
            if kind == "ipv4":
                octets = value.split(".")
                if any(int(o) > 255 for o in octets):
                    continue
            matches.append(value)
        if matches:
            found[kind] = matches
    return found


def redact_pii(text: str) -> tuple[str, dict[str, list[str]]]:
    """Mask every PII match and return the masked text plus what was found."""
    found = find_pii(text)
    masked = text
    for kind, matches in found.items():
        for value in matches:
            masked = masked.replace(value, REDACTION[kind])
    return masked, found


def gate_pii(text: str, *, redact: bool) -> tuple[Reason | None, str]:
    found = find_pii(text)
    if not found:
        return None, text
    summary = ", ".join(f"{len(v)} {k}" for k, v in sorted(found.items()))
    if redact:
        masked, _ = redact_pii(text)
        return (
            Reason("pii", Action.REDACT, f"Redacted {summary}.", [v for m in found.values() for v in m]),
            masked,
        )
    return (
        Reason("pii", Action.BLOCK, f"Output contains {summary}.", [v for m in found.values() for v in m]),
        text,
    )


# --------------------------------------------------------------------------- #
# Prompt injection
# --------------------------------------------------------------------------- #
INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("instruction_override", re.compile(r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|rules?)")),
    ("role_hijack", re.compile(r"(?i)\byou\s+are\s+now\s+(?:a|an|the)\b")),
    ("system_prompt_probe", re.compile(r"(?i)\b(?:reveal|show|print|repeat|output)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|rules?)")),
    ("developer_mode", re.compile(r"(?i)\b(?:developer|debug|god|dan|jailbreak)\s*mode\b")),
    ("policy_bypass", re.compile(r"(?i)\b(?:bypass|disable|turn\s+off|ignore)\s+(?:your\s+)?(?:safety|guardrails?|filters?|restrictions?|policy)")),
    ("exfiltration", re.compile(r"(?i)\b(?:send|post|exfiltrate|upload)\b.{0,40}\b(?:api[\s_-]?key|token|password|credential|secret)s?\b")),
    ("delimiter_spoof", re.compile(r"(?i)(?:<\|(?:im_start|im_end|system|endoftext)\|>|\[/?INST\]|###\s*(?:system|instruction))")),
)


def gate_injection(text: str) -> Reason | None:
    hits: list[str] = []
    for name, pattern in INJECTION_PATTERNS:
        if pattern.search(text):
            hits.append(name)
    if hits:
        return Reason(
            "injection",
            Action.BLOCK,
            f"Output contains prompt-injection patterns: {', '.join(hits)}.",
            hits,
        )
    return None


# --------------------------------------------------------------------------- #
# Toxicity
# --------------------------------------------------------------------------- #
TOXIC_TERMS: tuple[str, ...] = (
    "idiot", "moron", "imbecile", "worthless", "subhuman", "vermin",
    "kill yourself", "kys", "go die", "should be dead",
    "i will kill you", "i will hurt you", "you deserve to die",
)

HARASSMENT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\byou(?:'re| are)\s+(?:so\s+)?(?:stupid|useless|pathetic|worthless)\b"),
    re.compile(r"(?i)\bnobody\s+(?:likes|cares about|wants)\s+you\b"),
)


def gate_toxicity(text: str) -> Reason | None:
    lowered = text.lower()
    hits = [term for term in TOXIC_TERMS if term in lowered]
    hits += [p.pattern for p in HARASSMENT_PATTERNS if p.search(text)]
    if hits:
        return Reason(
            "toxicity",
            Action.BLOCK,
            f"Output contains abusive language ({len(hits)} match(es)).",
            hits,
        )
    return None
