"""The result of running the gates."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Action(str, Enum):
    ALLOW = "allow"
    REDACT = "redact"
    BLOCK = "block"


@dataclass
class Reason:
    gate: str
    action: Action
    detail: str
    evidence: list[str] = field(default_factory=list)

    def public(self) -> dict[str, Any]:
        return {
            "gate": self.gate,
            "action": self.action.value,
            "detail": self.detail,
            "evidence": self.evidence,
        }


@dataclass
class Verdict:
    allowed: bool
    action: Action
    text: str
    reasons: list[Reason] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.action is Action.BLOCK

    def public(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "action": self.action.value,
            "text": self.text,
            "reasons": [r.public() for r in self.reasons],
        }
