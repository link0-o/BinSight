# BinSight

BinSight 是一个用于扫描可执行文件并生成风险分析报告的 C++20 CLI 原型。第一版采用“确定性扫描管线 + 本地规则 + 本地 RAG + 可选 LLM 分析”的结构：工具调用由程序控制，AI 只负责基于证据解释风险。

英文文档: [README.md](README.md)

## 功能

- 识别 ELF 和 PE 可执行文件。
- 提取依赖库、导入符号、节区、可疑字符串和有限反汇编片段。
- 使用 YAML 风格规则生成可审计的风险证据。
- 从本地 Markdown 知识库检索 RAG 上下文。
- 输出 Markdown 人读报告和 JSON 机器报告。
- 支持三种分析模式：
  - `none`：离线规则分析，不调用模型。
  - `openai`：调用 OpenAI 兼容 `/chat/completions` 接口。
  - `ollama`：调用本地 Ollama `/api/generate` 接口。

## 构建

如果你是在 Windows 上使用，请先看 [Windows 使用指南](docs/zh-CN/WINDOWS.md)。当前推荐方式是 WSL2，不是直接生成原生 `binsight.exe`。

```bash
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build
```

当前原型不依赖第三方 C++ 库，适合在无网络或受限环境中构建。后续可以把手写 CLI/YAML/JSON/测试替换为 CLI11、yaml-cpp、nlohmann/json 和 Catch2。

## 使用

离线分析：

```bash
./build/binsight scan ./sample --provider none --out report.md --json report.json
```

OpenAI 兼容接口：

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
- [Skill 与 MCP 计划](docs/zh-CN/SKILL_MCP_PLAN.md)

## 设计边界

BinSight 第一版不是全自主 agent。扫描流程固定执行，结果可重复、可测试、可审计。未来可以在稳定 JSON 报告之上添加 MCP 或交互式 agent，用于追问和深挖，但核心取证逻辑仍应保持确定性。

## 输出

Markdown 报告采用中英双语标题和字段，便于中文阅读和英文术语对照。JSON 报告保持结构化字段，面向自动化、测试和后续 MCP/agent 集成。
