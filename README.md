# BinSight

中文文档: [README.zh-CN.md](README.zh-CN.md)

BinSight scans executable files and produces evidence-grounded risk reports. It uses a deterministic scan pipeline, local risk rules, local RAG knowledge, and an optional LLM analysis step. The scanner is not a fully autonomous agent: tool execution is fixed and auditable, while the LLM explains risk from observed evidence.

## Features

- Native Linux and Windows CLI builds.
- ELF and PE format detection.
- LIEF-backed production PE/ELF parsing for imports, sections, architecture, and bitness.
- Built-in fallback parser for dependency-restricted or offline development builds.
- Suspicious ASCII and UTF-16LE string extraction without an external `strings` command.
- Optional bounded disassembly snippets when `objdump` or `llvm-objdump` is available.
- YAML-style risk rules, local Markdown RAG context, and Markdown/JSON reports.
- Safe-by-default static mode plus explicit Linux Docker dynamic observation.
- LLM providers:
  - `none` for offline rule-only reports.
  - `openai` for OpenAI-compatible chat completions, including DeepSeek.
  - `ollama` for local Ollama generation.

## Download

For normal use, download a package from GitHub Releases:

- `BinSight-vX.Y.Z-windows-x86_64.zip`
- `BinSight-vX.Y.Z-linux-x86_64.tar.gz`

Windows:

```powershell
.\bin\binsight.exe scan .\sample.exe
```

Linux:

```bash
./bin/binsight scan ./sample
```

The release package includes `rules/`, `knowledge/`, `docs/`, and `docker/`. If `--rules-dir` or `--knowledge-dir` is not provided, BinSight looks for those directories beside the executable package layout.

## Build From Source

Linux:

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

Windows with Visual Studio 2022:

```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build --build-config Release --output-on-failure
```

Production parser build with LIEF:

```bash
cmake -S . -B build -DBINSIGHT_USE_LIEF=ON
```

`BINSIGHT_USE_LIEF` is ON by default. Use `-DBINSIGHT_USE_LIEF=OFF` only for dependency-restricted or offline development builds.

BinSight follows the [Industrial Component First Rule](docs/DESIGN_PRINCIPLES.md): mature embeddable components are preferred over custom parsers or required CLI tool dependencies. LIEF is the production PE/ELF parser. The built-in parser is a **Temporary / Prototype / Educational Implementation** fallback.

## Usage

Offline analysis:

```bash
./build/binsight scan ./sample
```

Static analysis is the default and never executes the target.

Linux lightweight dynamic observation:

```bash
docker build -t binsight-observer:latest docker/linux-observer
./build/binsight observe linux-docker ./sample \
  --out dynamic.json \
  --i-understand-risk
./build/binsight scan ./sample --dynamic-report dynamic.json
```

Docker observation is not a malware-grade sandbox. It uses constrained container settings and disables networking by default, but containers share the host kernel. Use it only on lab machines or samples you are prepared to execute. For high-risk packed malware, use a dedicated VM or professional sandbox.

By default BinSight writes:

- `report.zh-CN.md`
- `report.en.md`
- `report.json`

Choose a single Markdown language when needed:

```bash
./build/binsight scan ./sample --report-lang zh-CN
./build/binsight scan ./sample --report-lang en
```

Interactive configuration:

```bash
./build/binsight config wizard
./build/binsight config show
```

DeepSeek through the OpenAI-compatible provider:

```bash
export DEEPSEEK_API_KEY=...
./build/binsight scan ./sample \
  --provider openai \
  --base-url https://api.deepseek.com \
  --model deepseek-chat \
  --api-key-env DEEPSEEK_API_KEY
```

On Windows, store API keys in Windows Credential Manager:

```powershell
.\bin\binsight.exe config set-key --provider deepseek
.\bin\binsight.exe config wizard
```

The config file stores only non-sensitive values and a credential reference name. API keys are not written to reports, JSON, or plaintext config files.

OpenAI:

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

Ollama:

```bash
./build/binsight scan ./sample \
  --provider ollama \
  --base-url http://localhost:11434 \
  --model llama3.1 \
  --out report.md \
  --json report.json
```

## Reports

Markdown reports are language-specific and intended for humans. The JSON report is intended for automation, tests, and future MCP/agent integration. Risk conclusions include evidence references such as imported functions, suspicious strings, sections, libraries, RAG context, and optional disassembly snippets.

## Release

Local package:

```bash
cmake --build build --target package
```

GitHub release:

```bash
git tag v0.1.0
git push origin v0.1.0
```

Tag pushes trigger the release workflow and upload Linux/Windows packages to GitHub Releases.
