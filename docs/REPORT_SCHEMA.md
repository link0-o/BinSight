# Report Schema

BinSight writes Markdown for humans and JSON for automation.

## JSON Top Level

```json
{
  "target": {},
  "imports": [],
  "sections": [],
  "strings": [],
  "disassembly_snippets": [],
  "rule_findings": [],
  "rag_context": [],
  "ai_analysis": {},
  "warnings": []
}
```

## Important Fields

- `target`: path, format, architecture, bitness, stripped state, size, and content hash.
- `imports`: library and symbol entries.
- `sections`: section name, size, flags, and risk notes.
- `strings`: suspicious strings with categories.
- `disassembly_snippets`: bounded snippets with trigger reason.
- `rule_findings`: deterministic rule hits and evidence.
- `rag_context`: local knowledge entries used for analysis.
- `ai_analysis`: provider, model, summary, severity, risk sources, recommendations, and raw response.

