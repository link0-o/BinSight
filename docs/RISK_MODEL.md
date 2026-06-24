# Risk Model

BinSight separates observed evidence from interpretation.

## Severity

- `low`: unusual but weak signal.
- `medium`: suspicious capability or hardening weakness.
- `high`: strong malicious capability or multiple suspicious signals.
- `critical`: direct evidence of dangerous behavior with strong supporting context.

## Evidence Types

- imported library
- imported function or symbol
- suspicious string
- section property
- missing hardening feature
- disassembly snippet
- RAG knowledge reference

## False Positive Control

Rules should describe capability, not intent. For example, `CreateRemoteThread` indicates remote-thread capability, not necessarily malware. Reports must mark speculative conclusions as speculation.

