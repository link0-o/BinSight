# 架构说明

BinSight 使用工作流驱动的 AI 架构：

```text
二进制输入
  -> 确定性扫描器
  -> 本地规则引擎
  -> 本地 RAG 检索
  -> 可选 LLM 分析
  -> Markdown + JSON 报告
```

扫描器负责控制工具调用。LLM 不决定是否运行 `objdump`、`readelf` 或 `strings`，只接收结构化扫描结果和检索到的知识上下文。

## 核心模块

- `ProcessRunner`：调用外部工具并捕获输出。
- `BinaryAnalyzer`：识别 ELF/PE，提取元数据、导入、节区、字符串和反汇编片段。
- `StringScanner`：分类可疑字符串。
- `RiskRuleEngine`：匹配本地规则并输出证据。
- `LocalRagIndex`：从本地知识库检索相关条目。
- `LlmClient`：适配 OpenAI 兼容接口、Ollama 或离线模式。
- `ReportWriter`：输出 Markdown 和 JSON 报告。

## Agent 边界

第一版不做全自主 agent。后续可以增加 MCP 或聊天层，让 AI 基于 JSON 报告回答追问，但扫描流程本身仍应保持确定性。

