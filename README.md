# BinSight

中文文档: [README.zh-CN.md](README.zh-CN.md)

BinSight scans executable files and produces evidence-grounded risk reports. It uses a deterministic scan pipeline, local risk rules, local RAG knowledge, and an optional LLM analysis step. The scanner is not a fully autonomous agent: tool execution is fixed and auditable, while the LLM explains risk from observed evidence.

## Features

- Native Linux and Windows CLI builds.
- Optional Qt 6 Widgets GUI for Windows and desktop Linux.
- ELF and PE format detection.
- LIEF-backed production PE/ELF parsing for imports, sections, architecture, and bitness.
- Built-in fallback parser for dependency-restricted or offline development builds.
- Suspicious ASCII and UTF-16LE string extraction without an external `strings` command.
- Optional bounded disassembly snippets when `objdump` or `llvm-objdump` is available.
- YAML-style risk rules, local Markdown RAG context, and Markdown/JSON reports.
- Safe-by-default static mode plus explicit Linux Docker dynamic observation.
- LLM providers:
  - `none` for offline rule-only reports.
  - `openai` for the official OpenAI Responses API.
  - `openai-compatible` for generic `/chat/completions` compatible endpoints.
  - Provider presets for DeepSeek, Kimi/Moonshot, GLM/Zhipu, Qwen/DashScope, SiliconFlow, and OpenRouter.
  - `anthropic` and `deepseek-anthropic` for Anthropic-compatible messages APIs.
  - `ollama` for local Ollama generation.

## Download

For normal use, download a package from GitHub Releases:

- `BinSight-vX.Y.Z-windows-x86_64.zip`
- `BinSight-vX.Y.Z-linux-x86_64.tar.gz`

Windows:

```powershell
.\bin\binsight.exe scan .\sample.exe
.\bin\binsight.exe gui
```

Linux:

```bash
./bin/binsight scan ./sample
./bin/binsight gui
```

The release package includes `rules/`, `knowledge/`, `docs/`, and `docker/`. If the build includes Qt, it also includes `bin/binsight-gui` or `bin/binsight-gui.exe`. If `--rules-dir` or `--knowledge-dir` is not provided, BinSight looks for those directories beside the executable package layout.

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

GUI build:

```bash
cmake -S . -B build -DBINSIGHT_BUILD_GUI=AUTO
cmake -S . -B build -DBINSIGHT_BUILD_GUI=ON   # require Qt 6 Widgets
cmake -S . -B build -DBINSIGHT_BUILD_GUI=OFF  # CLI only
```

`AUTO` is the default. When Qt 6 Widgets is available, CMake builds `binsight-gui`; otherwise the CLI remains fully functional.

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

Graphical configuration and scanning:

```bash
./build/binsight gui
./build/binsight-gui
```

The GUI supports English/Chinese interface text, file drag and drop, output directory selection, report language selection, provider/model presets, secure API key saving when the platform supports it, and report preview/open buttons. On Linux without `DISPLAY` or `WAYLAND_DISPLAY`, `binsight gui` falls back with a CLI usage hint instead of trying to open a window.
The model selector is editable, so users can type a vendor-specific model ID that is not yet in the preset list. The AI Config tab also includes a lightweight model connection test that sends only a short connectivity prompt, not a binary report.

DeepSeek OpenAI-compatible API:

```bash
export DEEPSEEK_API_KEY=...
./build/binsight scan ./sample \
  --provider deepseek \
  --model deepseek-v4-flash
```

DeepSeek Anthropic-compatible API:

```bash
export DEEPSEEK_API_KEY=...
./build/binsight scan ./sample \
  --provider deepseek-anthropic \
  --model deepseek-v4-pro
```

Other OpenAI-compatible presets:

```bash
./build/binsight scan ./sample --provider kimi --model kimi-latest
./build/binsight scan ./sample --provider glm --model glm-5.2
./build/binsight scan ./sample --provider qwen --model qwen-plus
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
  --model gpt-5.5 \
  --api-key-env OPENAI_API_KEY \
  --out report.md \
  --json report.json
```

For third-party OpenAI-compatible endpoints, use `--provider openai-compatible` or a vendor preset such as `deepseek`, `kimi`, `glm`, or `qwen`.

Test a provider/model before scanning:

```bash
./build/binsight config test-llm --provider deepseek --model deepseek-v4-flash
./build/binsight config test-llm --provider kimi --model kimi-latest
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
