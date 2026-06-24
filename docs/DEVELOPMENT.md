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

## Parser Dependencies

BinSight follows the [Industrial Component First Rule](DESIGN_PRINCIPLES.md). Production-grade parsing should prefer a mature embeddable component over custom parsing code or required CLI tool dependencies.

Coding agents must follow the repository-level [AGENTS.md](../AGENTS.md) before modifying this project. That file is the AI auto-read production red-line entrypoint, not optional contributor documentation.

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
- `curl`: only for `openai` or `ollama` providers.

Missing optional tools should produce warnings rather than process crashes.

## Packaging

Local package:

```bash
cmake --build build --target package
```

Release packages include the executable, `rules/`, `knowledge/`, `docs/`, both READMEs, and `LICENSE`.

## CI

GitHub Actions runs:

- Ubuntu build and tests.
- Windows build and tests.
- CLI help smoke test.

Pushing a `v*` tag runs the release workflow and publishes Linux/Windows packages.
