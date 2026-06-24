# Skill and MCP Plan

BinSight should eventually have a project-specific Codex skill and an MCP server, but neither is required for the first CLI version.

## Project Skill

Suggested skill name:

```text
binsight-binary-risk-analysis
```

The skill should guide agents working on BinSight to:

- keep scanner behavior deterministic;
- preserve evidence-grounded conclusions;
- read risk taxonomy before changing severity logic;
- read report schema before changing JSON or Markdown output;
- avoid turning the scanner into an unconstrained agent loop.

## Future MCP Server

The MCP layer should wrap stable CLI/report behavior:

- `analyze_binary(path)`
- `get_imports(report_json)`
- `explain_finding(report_json, finding_id)`
- `compare_reports(left_json, right_json)`

The MCP server should not replace deterministic scanning logic.

