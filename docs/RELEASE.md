# Release Guide

## Versioning

Use git tags in the form:

```text
v0.2.0
```

The CMake project version should be updated before creating a new release tag.

## Local Package

Configure and build:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build --build-config Release --output-on-failure
```

Create a package:

```bash
cmake --build build --target package
```

The package contains:

- `bin/binsight` or `bin/binsight.exe`
- `bin/binsight-gui` or `bin/binsight-gui.exe` when Qt is available at build time
- required Qt runtime DLLs in Windows GUI packages, deployed with Qt's official `windeployqt`
- `rules/`
- `knowledge/`
- `docs/`
- `docker/`
- `README.md`
- `README.zh-CN.md`
- `LICENSE`

## GitHub Release

Create and push a tag:

```bash
git tag v0.2.0
git push origin v0.2.0
```

The release workflow builds and uploads:

- `BinSight-v0.2.0-linux-x86_64.tar.gz`
- `BinSight-v0.2.0-windows-x86_64.zip`

The Windows release job validates that GUI packages contain `Qt6Core.dll`, `Qt6Widgets.dll`, and `platforms/qwindows.dll`.

## Smoke Test

After downloading a release package:

Windows:

```powershell
.\bin\binsight.exe --help
.\bin\binsight.exe gui
.\bin\binsight.exe scan .\sample.exe --provider none --out report.md --json report.json
```

Linux:

```bash
./bin/binsight --help
./bin/binsight gui
./bin/binsight scan ./sample --provider none --out report.md --json report.json
docker build -t binsight-observer:latest docker/linux-observer
```

The scan should work without API keys. Missing optional disassembly tools should appear as warnings, not crashes.
On Linux servers without a graphical session, `binsight gui` should print a CLI fallback message. If Qt was not available during packaging, `binsight gui` should report that the GUI component is not installed.
