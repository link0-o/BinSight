# Development

## Layout

- `include/binsight/`: public project headers.
- `src/`: implementation.
- `tests/`: Catch2 tests.
- `rules/`: YAML risk rules.
- `knowledge/`: local RAG documents.
- `docs/`: architecture and project documentation.

## Build

```bash
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build
```

The current prototype intentionally avoids third-party C++ dependencies so it can build without network access. Planned dependency-backed replacements are CLI11 for argument parsing, yaml-cpp for full YAML, nlohmann/json for richer JSON handling, and Catch2 for test ergonomics.

## External Tools

Runtime scanning expects standard binary utilities when available:

- `file`
- `readelf`
- `objdump`
- `strings`

Missing tools should produce warnings rather than process crashes.
