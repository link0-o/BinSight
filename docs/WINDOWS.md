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
.\bin\binsight.exe scan .\sample.exe
```

Open the GUI when the release package includes it:

```powershell
.\bin\binsight.exe gui
```

The GUI supports drag and drop, AI provider/model presets, secure API key saving through Windows Credential Manager, and buttons to open the generated Chinese report, English report, JSON report, and output directory.

Default outputs:

```text
report.zh-CN.md
report.en.md
report.json
```

When `--rules-dir` and `--knowledge-dir` are omitted, BinSight searches the release package layout automatically.

## PE Support

The native Windows build prioritizes PE files:

- `.exe`
- `.dll`
- common Windows PE samples

Core PE evidence is extracted by the LIEF-backed production parser in release builds:

- format, architecture, and bitness
- DLL imports
- imported functions
- sections
- ASCII and UTF-16LE suspicious strings

If `objdump` or `llvm-objdump` is installed, BinSight also attempts bounded disassembly snippets. Missing disassembly tools do not fail the scan; they only add a report warning.

Per the [Industrial Component First Rule](DESIGN_PRINCIPLES.md), LIEF is the production PE/ELF parser. The built-in parser remains available only as a **Temporary / Prototype / Educational Implementation** fallback when LIEF is disabled or unavailable.

## Packed Samples

The Windows build does not automatically execute unknown `.exe` files. For packed or strongly obfuscated PE samples, BinSight reports static indicators such as high-entropy sections, sparse imports, writable executable sections, and dynamic import resolution. If these indicators are present, the report may include `static_inconclusive`.

Use a dedicated VM, professional sandbox, or imported Sysmon/Windows Event Log evidence for high-risk packed samples. `observe linux-docker` is for Linux ELF samples only and does not run Windows PE files.

## DeepSeek

```powershell
.\bin\binsight.exe config set-key --provider deepseek
.\bin\binsight.exe config wizard

.\bin\binsight.exe scan .\sample.exe `
  --provider deepseek `
  --model deepseek-v4-flash
```

`config set-key` stores the API key in Windows Credential Manager. The config file stores only a credential reference name, not the plaintext key.

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
.\build\Release\binsight.exe scan .\sample.exe
.\build\Release\binsight.exe gui
```

To require the GUI during a source build, install Qt 6 Widgets for MSVC 2022 and configure with:

```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBINSIGHT_BUILD_GUI=ON
```

## Optional Tools

These tools are optional for the native Windows build:

- `llvm-objdump`: optional disassembly snippets.
- `curl`: needed only for online LLM providers such as `openai`, `deepseek`, `kimi`, `glm`, `anthropic`, or `ollama`. Windows 10/11 usually includes it.

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
