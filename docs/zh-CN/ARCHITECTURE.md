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

扫描器负责控制证据提取。LLM 不决定是否解析二进制或运行可选增强工具，只接收结构化扫描结果和检索到的知识上下文。

## 设计原则

BinSight 遵守[工业组件优先法则](DESIGN_PRINCIPLES.md)。成熟的可嵌入库优先于自研 parser 或必需 CLI 工具依赖。

当前状态：

- LIEF 是 PE/ELF 的生产级主解析路径，用于格式、架构、imports 和 sections。
- 当前内置 PE parser 和外部工具 ELF parser 属于 **Temporary / Prototype / Educational Implementation** fallback。
- `objdump` 和 `llvm-objdump` 只作为可选反汇编增强工具，不是核心扫描依赖。

## 核心模块

- `ProcessRunner`：调用可选外部工具并捕获输出。
- `BinaryAnalyzer`：优先用 LIEF 提取 ELF/PE 元数据、导入和节区；只有 LIEF 禁用或解析失败时才进入 fallback。
- `StringScanner`：分类可疑字符串。
- `RiskRuleEngine`：匹配本地规则并输出证据。
- `LocalRagIndex`：从本地知识库检索相关条目。
- `LlmClient`：适配 OpenAI 兼容接口、Ollama 或离线模式。
- `ReportWriter`：输出 Markdown 和 JSON 报告。

## Agent 边界

第一版不做全自主 agent。后续可以增加 MCP 或聊天层，让 AI 基于 JSON 报告回答追问，但扫描流程本身仍应保持确定性。
