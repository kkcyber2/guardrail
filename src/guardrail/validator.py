"""Run the gates in order and combine their verdicts."""
from __future__ import annotations

from .gates import gate_injection, gate_pii, gate_schema, gate_toxicity
from .verdict import Action, Reason, Verdict


def validate(
    text: str,
    *,
    schema: dict[str, str] | None = None,
    redact_pii: bool = False,
    check_injection: bool = True,
    check_toxicity: bool = True,
) -> Verdict:
    """Validate `text` through every enabled gate.

    Gates run cheapest-first. A BLOCK from any gate stops the chain, because there
    is no point scanning output that is already rejected.
    """
    reasons: list[Reason] = []
    current = text

    schema_reason = gate_schema(current, schema)
    if schema_reason is not None:
        reasons.append(schema_reason)
        return Verdict(allowed=False, action=Action.BLOCK, text=text, reasons=reasons)

    pii_reason, current = gate_pii(current, redact=redact_pii)
    if pii_reason is not None:
        reasons.append(pii_reason)
        if pii_reason.action is Action.BLOCK:
            return Verdict(allowed=False, action=Action.BLOCK, text=text, reasons=reasons)

    if check_injection:
        injection_reason = gate_injection(current)
        if injection_reason is not None:
            reasons.append(injection_reason)
            return Verdict(allowed=False, action=Action.BLOCK, text=text, reasons=reasons)

    if check_toxicity:
        toxicity_reason = gate_toxicity(current)
        if toxicity_reason is not None:
            reasons.append(toxicity_reason)
            return Verdict(allowed=False, action=Action.BLOCK, text=text, reasons=reasons)

    action = Action.REDACT if any(r.action is Action.REDACT for r in reasons) else Action.ALLOW
    return Verdict(allowed=True, action=action, text=current, reasons=reasons)
