"""Command line entry point."""
from __future__ import annotations

import argparse
import json
import sys

from .validator import validate


def render(verdict) -> str:
    lines = [
        f"Action : {verdict.action.value.upper()}",
        f"Allowed: {verdict.allowed}",
        "",
    ]
    if verdict.reasons:
        lines.append("Gates:")
        for reason in verdict.reasons:
            lines.append(f"  [{reason.action.value}] {reason.gate}: {reason.detail}")
    else:
        lines.append("All gates passed.")
    if verdict.text != "" and verdict.action.value == "redact":
        lines.append("")
        lines.append("Output:")
        lines.append(verdict.text)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="guardrail", description="Validate LLM output before it ships")
    parser.add_argument("text", help="the model output to validate")
    parser.add_argument("--schema", help='JSON object mapping field -> type, e.g. \'{"name":"str"}\'')
    parser.add_argument("--redact", action="store_true", help="mask PII instead of blocking")
    parser.add_argument("--no-injection", action="store_true")
    parser.add_argument("--no-toxicity", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    schema = None
    if args.schema:
        try:
            schema = json.loads(args.schema)
        except ValueError as exc:
            print(f"--schema is not valid JSON: {exc}", file=sys.stderr)
            return 2

    verdict = validate(
        args.text,
        schema=schema,
        redact_pii=args.redact,
        check_injection=not args.no_injection,
        check_toxicity=not args.no_toxicity,
    )
    print(json.dumps(verdict.public(), indent=2) if args.json else render(verdict))
    return 0 if verdict.allowed else 1


if __name__ == "__main__":
    sys.exit(main())
