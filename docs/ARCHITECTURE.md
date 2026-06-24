# Architecture

BinSight uses a workflow-driven AI design:

```text
binary input
  -> deterministic scanner
  -> rule engine
  -> local RAG retrieval
  -> optional LLM analysis
  -> Markdown + JSON report
```

The scanner controls tool execution. The LLM does not decide whether to run `objdump`, `readelf`, or `strings`; it only receives structured scan results and retrieved knowledge.

## Components

- `ProcessRunner`: invokes external tools and captures output.
- `BinaryAnalyzer`: detects ELF/PE and extracts metadata, imports, sections, strings, and disassembly snippets.
- `StringScanner`: classifies suspicious strings.
- `RiskRuleEngine`: matches deterministic YAML rules and emits evidence.
- `LocalRagIndex`: retrieves local knowledge documents by keyword scoring.
- `LlmClient`: adapts OpenAI-compatible APIs, Ollama, or offline mode.
- `ReportWriter`: writes Markdown and JSON reports.

## Agent Boundary

Full agent behavior is intentionally deferred. A future MCP or chat layer may answer follow-up questions from the JSON report, but the scan pipeline remains deterministic and testable.

