# BinSight

English documentation: [README.md](README.md)

BinSight 是一个用于扫描可执行文件并生成风险分析报告的 C++20 CLI。它采用“确定性扫描管线 + 本地规则 + 本地 RAG + 可选 LLM 分析”的结构：程序负责固定、可审计的取证流程，AI 只基于证据解释风险。

## 功能

- 支持 Linux 和 Windows 原生命令行程序。
- 识别 ELF 和 PE 可执行文件。
- 当前内置 fallback parser 可提取 PE imports 和 sections，Windows 扫描 PE 不再依赖 WSL。
- 内置 ASCII 和 UTF-16LE 字符串提取，不再依赖外部 `strings` 命令。
- 如果系统存在 `objdump` 或 `llvm-objdump`，会额外提取有限反汇编片段；缺失时只写 warning。
- 使用 YAML 风格风险规则、本地 Markdown RAG 知识库，输出 Markdown 和 JSON 报告。
- 支持三种分析模式：
  - `none`：离线规则分析，不调用模型。
  - `openai`：调用 OpenAI 兼容 `/chat/completions` 接口，包括 DeepSeek。
  - `ollama`：调用本地 Ollama `/api/generate` 接口。

## 下载使用

普通用户优先下载 GitHub Releases 里的发行包：

- `BinSight-vX.Y.Z-windows-x86_64.zip`
- `BinSight-vX.Y.Z-linux-x86_64.tar.gz`

Windows：

```powershell
.\bin\binsight.exe scan .\sample.exe
```

Linux：

```bash
./bin/binsight scan ./sample
```

发行包会包含 `rules/`、`knowledge/` 和 `docs/`。如果没有传 `--rules-dir` 或 `--knowledge-dir`，BinSight 会自动从发行包目录查找默认规则和知识库。

## 从源码构建

Linux：

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

Windows + Visual Studio 2022：

```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build --build-config Release --output-on-failure
```

可选启用 LIEF：

```bash
cmake -S . -B build -DBINSIGHT_USE_LIEF=ON
```

即使没有启用 LIEF，内置解析器也能完成基础 PE/ELF 识别、PE 导入表、节区和字符串扫描，适合离线或受限环境。

BinSight 遵守[工业组件优先法则](docs/zh-CN/DESIGN_PRINCIPLES.md)：成熟可嵌入组件优先于自研 parser 或必需 CLI 工具依赖。当前内置 parser 属于 **Temporary / Prototype / Educational Implementation** fallback；LIEF 是生产级解析的优先方向。

## 使用

离线分析：

```bash
./build/binsight scan ./sample
```

默认会生成：

- `report.zh-CN.md`
- `report.en.md`
- `report.json`

只生成单一语言 Markdown：

```bash
./build/binsight scan ./sample --report-lang zh-CN
./build/binsight scan ./sample --report-lang en
```

交互式配置：

```bash
./build/binsight config wizard
./build/binsight config show
```

DeepSeek：

```bash
export DEEPSEEK_API_KEY=...
./build/binsight scan ./sample \
  --provider openai \
  --base-url https://api.deepseek.com \
  --model deepseek-chat \
  --api-key-env DEEPSEEK_API_KEY
```

Windows 上可以把 API key 保存到 Windows Credential Manager：

```powershell
.\bin\binsight.exe config set-key --provider deepseek
.\bin\binsight.exe config wizard
```

配置文件只保存非敏感配置和凭据引用名，不会把 API key 写入报告、JSON 或明文配置文件。

OpenAI：

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

Ollama：

```bash
./build/binsight scan ./sample \
  --provider ollama \
  --base-url http://localhost:11434 \
  --model llama3.1 \
  --out report.md \
  --json report.json
```

## 文档

- [架构说明](docs/zh-CN/ARCHITECTURE.md)
- [风险模型](docs/zh-CN/RISK_MODEL.md)
- [报告结构](docs/zh-CN/REPORT_SCHEMA.md)
- [LLM 与 RAG](docs/zh-CN/LLM_RAG.md)
- [开发说明](docs/zh-CN/DEVELOPMENT.md)
- [Windows 使用指南](docs/zh-CN/WINDOWS.md)
- [发行版说明](docs/zh-CN/RELEASE.md)
- [设计原则](docs/zh-CN/DESIGN_PRINCIPLES.md)
- [Skill 与 MCP 计划](docs/zh-CN/SKILL_MCP_PLAN.md)

## 输出

Markdown 报告按语言分离，默认同时输出中文和英文两个版本。JSON 报告保持结构化英文字段，面向自动化、测试和后续 MCP/agent 集成。风险结论会尽量指向明确证据，例如导入函数、可疑字符串、节区、库、RAG 上下文和可选反汇编片段。

## 发行版

本地打包：

```bash
cmake --build build --target package
```

GitHub 自动发布：

```bash
git tag v0.1.0
git push origin v0.1.0
```

推送 `v*` tag 后，GitHub Actions 会自动构建 Linux/Windows 压缩包并上传到 GitHub Releases。
