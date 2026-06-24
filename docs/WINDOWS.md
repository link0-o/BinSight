# Windows Guide

## Recommended Path: Native Windows Package

Download the Windows package from GitHub Releases:

```text
BinSight-vX.Y.Z-windows-x86_64.zip
```

After extraction:

```text
BinSight/
  bin/binsight.exe
  rules/default-rules.yaml
  knowledge/*.md
  docs/
```

Run an offline scan:

```powershell
.\bin\binsight.exe scan .\sample.exe --provider none --out report.md --json report.json
```

When `--rules-dir` and `--knowledge-dir` are omitted, BinSight searches the release package layout automatically.

## PE Support

The native Windows build prioritizes PE files:

- `.exe`
- `.dll`
- common Windows PE samples

Core PE evidence is currently extracted by the built-in fallback parser:

- format, architecture, and bitness
- DLL imports
- imported functions
- sections
- ASCII and UTF-16LE suspicious strings

If `objdump` or `llvm-objdump` is installed, BinSight also attempts bounded disassembly snippets. Missing disassembly tools do not fail the scan; they only add a report warning.

Per the [Industrial Component First Rule](DESIGN_PRINCIPLES.md), this built-in parser is a **Temporary / Prototype / Educational Implementation**. LIEF is the preferred production direction for embedded PE/ELF parsing.

## DeepSeek

```powershell
$env:DEEPSEEK_API_KEY="your key"

.\bin\binsight.exe scan .\sample.exe `
  --provider openai `
  --base-url https://api.deepseek.com `
  --model deepseek-chat `
  --api-key-env DEEPSEEK_API_KEY `
  --out report-deepseek.md `
  --json report-deepseek.json
```

Use `--provider none` first when you only want to validate the scan pipeline.

## Build From Source

Install Visual Studio 2022 with the C++ desktop workload, then run:

```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build --build-config Release --output-on-failure
```

Run:

```powershell
.\build\Release\binsight.exe scan .\sample.exe --provider none --out report.md --json report.json
```

## Optional Tools

These tools are optional for the native Windows build:

- `llvm-objdump`: optional disassembly snippets.
- `curl`: needed only for `openai` or `ollama` providers. Windows 10/11 usually includes it.

Without optional disassembly tools, reports still include imports, sections, strings, rules, and RAG context.

## WSL2 Fallback

WSL2 remains useful if you prefer Linux tooling:

```bash
sudo apt update
sudo apt install -y git cmake ninja-build g++ binutils file curl

git clone https://github.com/link0-o/BinSight.git
cd BinSight
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure
```

Scan a Windows file from WSL:

```bash
./build/binsight scan "/mnt/c/Users/<user>/Downloads/sample.exe" \
  --provider none \
  --out report.md \
  --json report.json
```
