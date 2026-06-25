# Architecture

BinSight uses a workflow-driven AI design:

```text
binary input
  -> CLI or Qt GUI entrypoint
  -> deterministic scanner
  -> rule engine
  -> optional dynamic observation import
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

- `binsight`: CLI entrypoint. It owns scripting-compatible commands and the `gui` launcher/fallback.
- `binsight-gui`: optional Qt 6 Widgets desktop UI for Windows and graphical Linux sessions. It reuses `binsight_core` and does not duplicate scanning logic.
- `ProcessRunner`: invokes optional external tools and captures output.
- `BinaryAnalyzer`: uses LIEF first for ELF/PE metadata, imports, sections, and static packing indicators, then falls back only when LIEF is disabled or parsing fails.
- `LinuxDockerObserver`: optional lightweight Linux dynamic observation. It runs only through the explicit `observe linux-docker` command and is not a malware-grade sandbox.
- `StringScanner`: classifies suspicious strings.
- `RiskRuleEngine`: matches deterministic YAML rules and emits evidence.
- `LocalRagIndex`: retrieves local knowledge documents by keyword scoring.
- `LlmClient`: adapts OpenAI-compatible APIs, Ollama, or offline mode.
- `ReportWriter`: writes Markdown and JSON reports.

## Agent Boundary

Full agent behavior is intentionally deferred. A future MCP or chat layer may answer follow-up questions from the JSON report, but the scan pipeline remains deterministic and testable.

## Analysis Modes

- `static`: default mode. It never executes the target and may report `static_inconclusive` when packing or obfuscation hides evidence.
- `static_with_dynamic_report`: static scan plus an imported dynamic observation report. Dynamic evidence is kept separate from static evidence.

Windows samples are not executed by BinSight. High-risk packed Windows files should be analyzed in a dedicated VM or professional sandbox.
