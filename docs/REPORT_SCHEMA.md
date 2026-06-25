# Report Schema

BinSight writes language-specific Markdown for humans and JSON for automation.

Default scan output:

- `report.zh-CN.md`
- `report.en.md`
- `report.json`

Use `--report-lang zh-CN|en|both` to control Markdown output. JSON field names remain stable English identifiers and do not change with report language.

## JSON Top Level

```json
{
  "analysis_mode": "static",
  "target": {},
  "imports": [],
  "sections": [],
  "strings": [],
  "disassembly_snippets": [],
  "rule_findings": [],
  "rag_context": [],
  "ai_analysis": {},
  "dynamic_observations": {},
  "warnings": []
}
```

## Important Fields

- `target`: path, format, architecture, bitness, stripped state, size, and content hash.
- `analysis_mode`: `static` or `static_with_dynamic_report`.
- `imports`: library and symbol entries.
- `sections`: section name, size, flags, entropy, and risk notes.
- `strings`: suspicious strings with categories.
- `disassembly_snippets`: bounded snippets with trigger reason.
- `rule_findings`: deterministic rule hits and evidence.
- `rag_context`: local knowledge entries used for analysis.
- `ai_analysis`: provider, model, summary, severity, risk sources, recommendations, and raw response.
- `dynamic_observations`: optional Linux Docker or imported runtime observation evidence. Static scans leave `present` false.

## Dynamic Observation Fields

`dynamic_observations` uses stable English fields:

- `present`: whether a dynamic report was attached.
- `platform`: observed platform, initially `linux`.
- `mode`: observation mode, initially `linux-docker`.
- `timeout_seconds`, `timed_out`, `exit_code`, `network_mode`.
- `process_events`, `file_events`, `network_events`, and `syscall_summary`.
- `stdout`, `stderr`, and `warnings`.
