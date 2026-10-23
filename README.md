# Guardrail

Validates what an LLM is about to send back, before it reaches a user or a downstream
system. Four gates run in order and every rejection says exactly which gate fired and
why.

| Gate | Catches |
|---|---|
| `schema` | Output that does not match the expected JSON shape |
| `pii` | Emails, phone numbers, card numbers, national IDs, IP addresses |
| `injection` | Prompt-injection and jailbreak patterns in the *output* |
| `toxicity` | Slurs, threats, self-harm and harassment language |

## Why validate the output, not just the input

Input filtering is necessary and insufficient. A model can be steered by content it
retrieved, by a tool result, or by a previous turn — none of which passed through the
input filter. Checking the output is the last place you still control.

## Design

* **Gates are independent and ordered.** Cheap structural checks run first so an
  expensive scan never runs on output that was already going to be rejected.
* **Redaction is separate from rejection.** PII can be masked and passed through;
  injection cannot.
* **Every decision is explainable.** `Verdict.reasons` lists each gate's outcome.

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
guardrail '{"name":"Ada","email":"ada@example.com"}'
guardrail --schema '{"name":"str","age":"int"}' '{"name":"Ada","age":36}'
guardrail --redact 'Contact me at ada@example.com or 555-0100'
```

## As a library

```python
from guardrail.validator import validate

verdict = validate('{"name":"Ada"}', schema={"name": "str"})
if not verdict.allowed:
    print(verdict.reasons)
```

## Tests

```bash
pytest -q
```

## License

MIT — see `LICENSE`.
