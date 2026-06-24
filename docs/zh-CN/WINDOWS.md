# Windows 使用指南

## 推荐方式：原生 Windows 发行包

从 GitHub Releases 下载：

```text
BinSight-vX.Y.Z-windows-x86_64.zip
```

解压后目录大致是：

```text
BinSight/
  bin/binsight.exe
  rules/default-rules.yaml
  knowledge/*.md
  docs/
```

运行离线扫描：

```powershell
.\bin\binsight.exe scan .\sample.exe
```

默认生成：

```text
report.zh-CN.md
report.en.md
report.json
```

不传 `--rules-dir` 和 `--knowledge-dir` 时，程序会自动从发行包目录查找 `rules/` 和 `knowledge/`。

## Windows 上能扫什么

原生 Windows 版优先支持 PE 文件：

- `.exe`
- `.dll`
- 常见 Windows PE 样本

当前核心 PE 信息由内置 fallback parser 提取：

- 文件格式、架构、位数
- DLL imports
- imported functions
- sections
- ASCII / UTF-16LE 可疑字符串

如果系统安装了 `objdump` 或 `llvm-objdump`，BinSight 会额外尝试提取有限反汇编片段。没有这些工具也不会失败，只会在报告 `Warnings / 警告` 里说明反汇编不可用。

根据[工业组件优先法则](DESIGN_PRINCIPLES.md)，该内置 parser 属于 **Temporary / Prototype / Educational Implementation**。LIEF 是生产级 PE/ELF 可嵌入解析的优先方向。

## 使用 DeepSeek

PowerShell：

```powershell
.\bin\binsight.exe config set-key --provider deepseek
.\bin\binsight.exe config wizard

.\bin\binsight.exe scan .\sample.exe `
  --provider openai `
  --base-url https://api.deepseek.com `
  --model deepseek-chat
```

`config set-key` 会把 API key 保存到 Windows Credential Manager。配置文件只保存凭据引用名，不保存明文 key。

如果只是验证扫描链路，先用 `--provider none`，不会联网，也不会产生模型费用。

## 从源码构建

安装 Visual Studio 2022，并勾选 C++ 桌面开发工具。然后在 Developer PowerShell 或普通 PowerShell 中执行：

```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build --build-config Release --output-on-failure
```

运行：

```powershell
.\build\Release\binsight.exe scan .\sample.exe
```

## 可选工具

这些工具不是原生 Windows 版完成基础 PE 扫描的硬依赖：

- `llvm-objdump`：用于可选反汇编片段。
- `curl`：Windows 10/11 通常自带；仅 `openai` 或 `ollama` 模式需要。

如果不安装可选反汇编工具，报告仍然会包含 imports、sections、strings、rules 和 RAG。

## WSL2 备用方式

如果你更习惯 Linux 工具链，仍然可以在 WSL2 中构建和运行：

```bash
sudo apt update
sudo apt install -y git cmake ninja-build g++ binutils file curl

git clone https://github.com/link0-o/BinSight.git
cd BinSight
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure
```

扫描 Windows 文件：

```bash
./build/binsight scan "/mnt/c/Users/<你的用户名>/Downloads/sample.exe" \
  --provider none \
  --out report.md \
  --json report.json
```

## 常见问题

### 为什么没有 objdump 也能扫 PE？

BinSight 已经内置 PE header、import directory、section table 和字符串扫描。`objdump` 只用于补充反汇编片段。

### report.md 在哪里？

在你运行命令的当前目录。比如你在解压目录运行命令，报告就在解压目录下。

### 路径里有中文或空格怎么办？

PowerShell 中给路径加引号：

```powershell
.\bin\binsight.exe scan "C:\Users\link\Downloads\关机.exe" --provider none
```

### Windows Release 包可以直接上传 GitHub 吗？

可以。推送 `v*` tag 后，GitHub Actions 会自动生成 Windows zip 和 Linux tar.gz，详见 [发行版说明](RELEASE.md)。
