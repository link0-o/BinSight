# Risk Model

BinSight separates observed evidence from interpretation.

## Severity

- `low`: unusual but weak signal.
- `medium`: suspicious capability or hardening weakness.
- `high`: strong malicious capability or multiple suspicious signals.
- `critical`: direct evidence of dangerous behavior with strong supporting context.

Severity is not the same as intent. A capability rule can be `medium` while still meaning
"review this capability", not "this binary is malware".

## Risk Type, Confidence, and Evidence Strength

Each rule finding includes:

- `risk_type`: `capability`, `suspicious`, or `malicious-likely`.
- `confidence`: `low`, `medium`, or `high`.
- `evidence_strength`: `weak`, `medium`, or `strong`.

Single imports, single URLs, model provider URLs, and API key environment variable names are weak evidence.
High-risk conclusions should require strong evidence or multiple independent signals.

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

Default rules use combination requirements where possible. For example, command execution APIs
alone produce a capability finding, while command execution APIs plus dangerous command strings
can produce a high-risk finding. Network APIs alone are low-risk capability evidence; embedded
destinations plus network APIs are suspicious but still not automatically malicious.

## Final Assessment Fusion

When an online AI provider is enabled, BinSight keeps the local baseline and AI assessment separate, then writes a fused `final_assessment`.

- If AI is unavailable or its JSON cannot be parsed, final assessment falls back to local analysis.
- Strong local `malicious-likely` findings at `high` or `critical` severity set a high-risk floor.
- Capability-only local findings can be downgraded by AI when the full context supports a lower risk.
- AI can escalate the final severity when it identifies a higher-risk evidence combination missed by local rules.
