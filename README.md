# BinSight

中文文档: [README.zh-CN.md](README.zh-CN.md)

BinSight scans executable files and produces evidence-grounded risk reports. The first version is a C++20 CLI that uses a deterministic scan pipeline, local risk rules, local RAG knowledge, and an optional LLM analysis step.

The scanner is deliberately not a fully autonomous agent. Tool execution is fixed and auditable; the LLM explains risk from observed evidence.

## Features

- ELF and PE format detection.
- Library, import, section, string, and bounded disassembly extraction.
- YAML risk rules with evidence output.
- Local Markdown knowledge retrieval for RAG context.
- Markdown and JSON reports.
- LLM providers:
  - `none` for offline rule-only reports.
  - `openai` for OpenAI-compatible chat completions.
  - `ollama` for local Ollama generation.

## Build

```bash
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build
```

The current prototype builds without third-party C++ dependencies so it can run in restricted environments. The module boundaries still allow later replacement with CLI11, yaml-cpp, nlohmann/json, or Catch2 if desired.

## Usage

Offline analysis:

```bash
./build/binsight scan ./sample --provider none --out report.md --json report.json
```

OpenAI-compatible analysis:

```bash
export OPENAI_API_KEY=...
./build/binsight scan ./sample \
  --provider openai \
  --base-url https://api.openai.com/v1 \
  --model gpt-4.1-mini \
  --api-key-env OPENAI_API_KEY \
  --out report.md \
  --json report.json
```

Ollama analysis:

```bash
./build/binsight scan ./sample \
  --provider ollama \
  --base-url http://localhost:11434 \
  --model llama3.1 \
  --out report.md \
  --json report.json
```

## Output

The Markdown report is intended for humans. The JSON report is intended for automation, tests, and future MCP/agent integration. Risk conclusions include evidence references such as imported functions, suspicious strings, sections, libraries, and disassembly snippets.
