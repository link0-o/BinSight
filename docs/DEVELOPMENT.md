# Development

## Layout

- `include/binsight/`: public project headers.
- `src/`: implementation.
- `tests/`: unit and integration-style tests.
- `rules/`: YAML-style risk rules.
- `knowledge/`: local RAG documents.
- `docs/`: English documentation.
- `docs/zh-CN/`: Chinese documentation.

## Linux Build

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

## Windows Build

Install Visual Studio 2022 with the C++ desktop workload:

```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build --build-config Release --output-on-failure
```

## GUI Build

The GUI is an optional Qt 6 Widgets executable. Qt is the selected industrial component for the desktop UI because it is mature, cross-platform, embeddable in a CMake/C++ build, and avoids a custom windowing stack. The GUI supports English and Chinese interface text and keeps report language selection separate from UI language.

```bash
cmake -S . -B build -DBINSIGHT_BUILD_GUI=AUTO
cmake --build build
```

`BINSIGHT_BUILD_GUI` accepts:

- `AUTO`: build `binsight-gui` when Qt 6 Widgets is found; otherwise build CLI only.
- `ON`: require Qt 6 Widgets and fail configuration if it is missing.
- `OFF`: build CLI only.

Linux package prerequisite example:

```bash
sudo apt-get install qt6-base-dev
```

Windows developers can install Qt 6 for MSVC 2022 and make it discoverable with `CMAKE_PREFIX_PATH` if CMake cannot find it automatically.

The GUI must reuse `binsight_core` and `scan_pipeline`; it must not duplicate parser, rule, RAG, LLM, or report generation logic.

## Parser Dependencies

BinSight follows the [Industrial Component First Rule](DESIGN_PRINCIPLES.md). Production-grade parsing should prefer a mature embeddable component over custom parsing code or required CLI tool dependencies.

LIEF is the production PE/ELF parsing path and is enabled by default:

```bash
cmake -S . -B build -DBINSIGHT_USE_LIEF=ON
```

Use this only for dependency-restricted or offline development builds:

```bash
cmake -S . -B build -DBINSIGHT_USE_LIEF=OFF
```

The fallback parser covers the minimum evidence needed when LIEF is unavailable:

- ELF/PE magic and architecture detection.
- PE import directory parsing.
- PE section table parsing.
- ASCII and UTF-16LE string extraction.

This built-in parser is classified as **Temporary / Prototype / Educational Implementation**. It exists as a fallback for offline or dependency-restricted development and must not be treated as the production parser while LIEF satisfies the same requirement.

## External Tools

Runtime scanning treats these tools as optional when available:

- `objdump` or `llvm-objdump`: bounded disassembly snippets.
- `curl`: only for online LLM providers such as `openai`, `anthropic`, `deepseek`, `kimi`, `glm`, `qwen`, or `ollama`.
- `docker`: only for explicit `observe linux-docker`.

Missing optional tools should produce warnings rather than process crashes.

## Linux Docker Observation

Build the lightweight observer image:

```bash
docker build -t binsight-observer:latest docker/linux-observer
```

Run observation only when you explicitly accept the risk:

```bash
./build/binsight observe linux-docker ./sample --out dynamic.json --i-understand-risk
./build/binsight scan ./sample --dynamic-report dynamic.json
```

This mode is **not** a malware-grade sandbox. It uses Docker, `strace`, disabled networking by default, and resource limits to collect lightweight runtime evidence.

## Packaging

Local package:

```bash
cmake --build build --target package
```

Release packages include the executable, `rules/`, `knowledge/`, `docs/`, `docker/`, both READMEs, and `LICENSE`.
If Qt is available at package build time, packages also include `binsight-gui` / `binsight-gui.exe`.

## CI

GitHub Actions runs:

- Ubuntu build and tests.
- Windows build and tests.
- CLI help smoke test.
- GUI build and `binsight-gui --help` smoke test when Qt is available.

Pushing a `v*` tag runs the release workflow and publishes Linux/Windows packages.
