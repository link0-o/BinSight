# Report Schema

BinSight writes language-specific Markdown for humans and JSON for automation.

Default scan output:

- `report.zh-CN.md`
- `report.en.md`
- `report.json`

Use `--report-lang zh-CN|en|both` to control Markdown output. JSON field names remain stable English identifiers and do not change with report language.
Markdown reports are language-localized for human readers. In `both` mode, online AI assessment text is requested separately for Chinese and English Markdown when a provider is enabled. JSON keeps one stable primary assessment for automation.
Chinese Markdown is written as UTF-8 with BOM for reliable Windows editor encoding detection. JSON remains UTF-8 without BOM.

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
  "local_analysis": {},
  "ai_analysis": {},
  "final_assessment": {},
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
- `rule_findings`: deterministic rule hits, risk type, confidence, evidence strength, and evidence.
- `rag_context`: local knowledge entries used for analysis.
- `local_analysis`: deterministic baseline built from local rules.
- `ai_analysis`: independent model assessment when an online provider is enabled; with `provider=none`, it mirrors local analysis.
- `final_assessment`: fused conclusion from local and AI assessments. Automation should use this as the primary report verdict.
- `dynamic_observations`: optional Linux Docker or imported runtime observation evidence. Static scans leave `present` false.

## Assessment Fields

`local_analysis`, `ai_analysis`, and `final_assessment` intentionally remain separate:

- `local_analysis`: `severity`, `summary`, `risk_sources`, and `recommendations`.
- `ai_analysis`: provider metadata plus `severity`, `confidence`, `summary`, `decision_basis`, `risk_sources`, `recommendations`, and `raw_response`.
- `final_assessment`: `severity`, `summary`, `decision_basis`, `risk_sources`, and `recommendations`.

If AI parsing or the provider call fails, `final_assessment` falls back to `local_analysis` and the failure is recorded in `warnings`.

## Rule Finding Fields

Each `rule_findings[]` item includes stable English fields:

- `id`, `title`, `severity`, `description`, `recommendation`, `tags`, and `evidence`.
- `risk_type`: `capability`, `suspicious`, or `malicious-likely`.
- `confidence`: `low`, `medium`, or `high`.
- `evidence_strength`: `weak`, `medium`, or `strong`.

Consumers should avoid treating `capability` findings as confirmed malicious behavior.

## Dynamic Observation Fields

`dynamic_observations` uses stable English fields:

- `present`: whether a dynamic report was attached.
- `platform`: observed platform, initially `linux`.
- `mode`: observation mode, initially `linux-docker`.
- `timeout_seconds`, `timed_out`, `exit_code`, `network_mode`.
- `process_events`, `file_events`, `network_events`, and `syscall_summary`.
- `stdout`, `stderr`, and `warnings`.
