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

The scanner controls evidence extraction. The LLM does not decide whether to parse binaries or run optional enrichment tools; it only receives structured scan results and retrieved knowledge.

## Design Principle

BinSight follows the [Industrial Component First Rule](DESIGN_PRINCIPLES.md). Mature embeddable libraries are preferred over custom parsers or required CLI tool dependencies.

Current status:

- LIEF is the production PE/ELF parsing path for format, architecture, imports, and sections.
- The built-in PE parser and external-tool ELF parser are **Temporary / Prototype / Educational Implementation** fallback paths.
- `objdump` and `llvm-objdump` are optional disassembly enrichment tools, not core scan dependencies.

## Components

- `ProcessRunner`: invokes optional external tools and captures output.
- `BinaryAnalyzer`: uses LIEF first for ELF/PE metadata, imports, and sections, then falls back only when LIEF is disabled or parsing fails.
- `StringScanner`: classifies suspicious strings.
- `RiskRuleEngine`: matches deterministic YAML rules and emits evidence.
- `LocalRagIndex`: retrieves local knowledge documents by keyword scoring.
- `LlmClient`: adapts OpenAI-compatible APIs, Ollama, or offline mode.
- `ReportWriter`: writes Markdown and JSON reports.

## Agent Boundary

Full agent behavior is intentionally deferred. A future MCP or chat layer may answer follow-up questions from the JSON report, but the scan pipeline remains deterministic and testable.
