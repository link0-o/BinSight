# BinSight

English documentation: [README.md](README.md)

BinSight 是一个用于扫描可执行文件并生成风险分析报告的 C++20 CLI。它采用“确定性扫描管线 + 本地规则 + 本地 RAG + 可选 LLM 分析”的结构：程序负责固定、可审计的取证流程，AI 只基于证据解释风险。

## 功能

- 支持 Linux 和 Windows 原生命令行程序。
- 可选 Qt 6 Widgets 图形界面，支持 Windows 和带桌面环境的 Linux。
- 识别 ELF 和 PE 可执行文件。
- 使用 LIEF 作为生产级 PE/ELF 主解析路径，提取 imports、sections、架构和位数。
- 保留内置 fallback parser，供依赖受限或离线开发构建使用。
- 内置 ASCII 和 UTF-16LE 字符串提取，不再依赖外部 `strings` 命令。
- 如果系统存在 `objdump` 或 `llvm-objdump`，会额外提取有限反汇编片段；缺失时只写 warning。
- 使用 YAML 风格风险规则、本地 Markdown RAG 知识库，输出 Markdown 和 JSON 报告。
- 默认安全的静态模式，以及需要显式确认风险的 Linux Docker 动态观测模式。
- 支持三种分析模式：
  - `none`：离线规则分析，不调用模型。
  - `openai`：调用 OpenAI 官方 Responses API。
  - `openai-compatible`：调用通用 `/chat/completions` 兼容接口。
  - 内置 DeepSeek、Kimi/Moonshot、GLM/Zhipu、Qwen/DashScope、SiliconFlow、OpenRouter 等 Provider preset。
  - `anthropic` 和 `deepseek-anthropic`：调用 Anthropic 兼容 Messages API。
  - `ollama`：调用本地 Ollama `/api/generate` 接口。

## 下载使用

普通用户优先下载 GitHub Releases 里的发行包：

- `BinSight-vX.Y.Z-windows-x86_64.zip`
- `BinSight-vX.Y.Z-linux-x86_64.tar.gz`

Windows：

```powershell
.\bin\binsight.exe scan .\sample.exe
.\bin\binsight.exe gui
```

Linux：

```bash
./bin/binsight scan ./sample
./bin/binsight gui
```

发行包会包含 `rules/`、`knowledge/`、`docs/` 和 `docker/`。如果构建时包含 Qt，还会包含 `bin/binsight-gui` 或 `bin/binsight-gui.exe`。如果没有传 `--rules-dir` 或 `--knowledge-dir`，BinSight 会自动从发行包目录查找默认规则和知识库。

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

使用 LIEF 的生产级解析构建：

```bash
cmake -S . -B build -DBINSIGHT_USE_LIEF=ON
```

`BINSIGHT_USE_LIEF` 默认开启。只有在依赖受限或离线开发构建时，才建议显式传 `-DBINSIGHT_USE_LIEF=OFF`。

图形界面构建：

```bash
cmake -S . -B build -DBINSIGHT_BUILD_GUI=AUTO
cmake -S . -B build -DBINSIGHT_BUILD_GUI=ON   # 强制要求 Qt 6 Widgets
cmake -S . -B build -DBINSIGHT_BUILD_GUI=OFF  # 只构建 CLI
```

`AUTO` 是默认值。CMake 找到 Qt 6 Widgets 时会构建 `binsight-gui`；找不到时只构建 CLI，扫描能力不受影响。

BinSight 遵守[工业组件优先法则](docs/zh-CN/DESIGN_PRINCIPLES.md)：成熟可嵌入组件优先于自研 parser 或必需 CLI 工具依赖。LIEF 是生产级 PE/ELF parser；当前内置 parser 属于 **Temporary / Prototype / Educational Implementation** fallback。

## 使用

离线分析：

```bash
./build/binsight scan ./sample
```

静态分析是默认模式，不会执行目标文件。

Linux 轻量动态观测：

```bash
docker build -t binsight-observer:latest docker/linux-observer
./build/binsight observe linux-docker ./sample \
  --out dynamic.json \
  --i-understand-risk
./build/binsight scan ./sample --dynamic-report dynamic.json
```

Docker 动态观测不是恶意软件级别沙箱。它会使用受限容器参数并默认禁网，但容器仍共享宿主机内核。只建议在实验机或你愿意承担运行风险的样本上使用。高风险强壳样本应使用专用虚拟机或专业沙箱。

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

图形化扫描和配置：

```bash
./build/binsight gui
./build/binsight-gui
```

GUI 支持中英文界面、拖拽文件、选择输出目录、选择报告语言、Provider/模型 preset、安全保存 API key、扫描结果摘要和打开报告按钮。Linux 没有 `DISPLAY` 或 `WAYLAND_DISPLAY` 时，`binsight gui` 不会强行打开窗口，而是提示继续使用 CLI。
模型下拉框支持手动输入，因此厂商新增模型但 preset 还没更新时，可以直接填真实 model id。AI 配置页还提供轻量“测试模型联通”功能，只发送一条很短的联通测试提示，不会上传二进制报告。

DeepSeek：

```bash
export DEEPSEEK_API_KEY=...
./build/binsight scan ./sample \
  --provider deepseek \
  --model deepseek-v4-flash
```

DeepSeek Anthropic 兼容接口：

```bash
export DEEPSEEK_API_KEY=...
./build/binsight scan ./sample \
  --provider deepseek-anthropic \
  --model deepseek-v4-pro
```

其他 OpenAI 兼容 Provider preset：

```bash
./build/binsight scan ./sample --provider kimi --model kimi-latest
./build/binsight scan ./sample --provider glm --model glm-5.2
./build/binsight scan ./sample --provider qwen --model qwen-plus
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
  --model gpt-5.5 \
  --api-key-env OPENAI_API_KEY \
  --out report.md \
  --json report.json
```

第三方 OpenAI 兼容接口请使用 `--provider openai-compatible`，或直接使用 `deepseek`、`kimi`、`glm`、`qwen` 等厂商 preset。

扫描前测试 Provider/模型是否联通：

```bash
./build/binsight config test-llm --provider deepseek --model deepseek-v4-flash
./build/binsight config test-llm --provider kimi --model kimi-latest
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
