# 报告结构

BinSight 输出面向人工阅读的分语言 Markdown，以及面向自动化的 JSON。

默认扫描输出：

- `report.zh-CN.md`
- `report.en.md`
- `report.json`

可以用 `--report-lang zh-CN|en|both` 控制 Markdown 输出语言。JSON 字段名保持稳定英文标识，不随报告语言变化。
Markdown 报告面向人工阅读，会按语言本地化。`both` 模式下，如果启用了在线 Provider，中文和英文 Markdown 会分别请求对应语言的 AI 评估文本。JSON 继续保留一份稳定主评估，面向自动化消费。
Windows 版中文 Markdown 会以 UTF-8 BOM 写出，方便 Windows 编辑器自动识别编码。Linux/macOS Markdown 保持无 BOM UTF-8。JSON 仍保持无 BOM UTF-8，便于自动化解析。

## JSON 顶层结构

```json
{
  "analysis_mode": "static",
  "target": {},
  "imports": [],
  "sections": [],
  "strings": [],
  "disassembly_snippets": [],
  "rule_findings": [],
  "rag_context": [],
  "local_analysis": {},
  "ai_analysis": {},
  "final_assessment": {},
  "dynamic_observations": {},
  "warnings": []
}
```

## 字段说明

- `analysis_mode`：`static` 或 `static_with_dynamic_report`。
- `target`：路径、格式、架构、位数、是否 stripped、大小和内容哈希。
- `imports`：依赖库和导入符号。
- `sections`：节区名称、大小、标志、熵和风险备注。
- `strings`：可疑字符串及其分类。
- `disassembly_snippets`：有限反汇编片段和触发原因。
- `rule_findings`：本地规则命中结果、风险类型、置信度、证据强度和证据列表。
- `rag_context`：参与分析的本地知识条目。
- `local_analysis`：由本地规则生成的确定性基线评估。
- `ai_analysis`：在线 Provider 启用时的 AI 独立评估；`provider=none` 时镜像本地评估。
- `final_assessment`：本地和 AI 融合后的最终结论。自动化消费时应优先读取该字段。
- `dynamic_observations`：可选 Linux Docker、Windows ETW 或导入的运行时观测证据。纯静态扫描中 `present` 为 false。
- `warnings`：工具缺失、解析失败或不支持格式等非致命问题。

## 评估字段

`local_analysis`、`ai_analysis` 和 `final_assessment` 会刻意分开保存：

- `local_analysis`：`severity`、`summary`、`risk_sources` 和 `recommendations`。
- `ai_analysis`：Provider 元数据，以及 `severity`、`confidence`、`summary`、`decision_basis`、`risk_sources`、`recommendations` 和 `raw_response`。
- `final_assessment`：`severity`、`summary`、`decision_basis`、`risk_sources` 和 `recommendations`。

如果 AI 调用或解析失败，`final_assessment` 会回退到 `local_analysis`，失败原因写入 `warnings`。

## 规则命中字段

每个 `rule_findings[]` 条目包含稳定英文 JSON 字段：

- `id`、`title`、`severity`、`description`、`recommendation`、`tags` 和 `evidence`。
- `risk_type`：`capability`、`suspicious` 或 `malicious-likely`。
- `confidence`：`low`、`medium` 或 `high`。
- `evidence_strength`：`weak`、`medium` 或 `strong`。

自动化消费者不应把 `capability` 类型的命中直接当作已确认恶意行为。

## 动态观测字段

`dynamic_observations` 使用稳定英文 JSON 字段：

- `present`：是否附加动态报告。
- `platform`：观测平台，例如 `linux` 或 `windows`。
- `mode`：观测模式，例如 `linux-docker` 或 `windows_etw`。
- `timeout_seconds`、`timed_out`、`exit_code`、`network_mode`。
- `process_events`、`file_events`、`network_events` 和 `syscall_summary`。
- `stdout`、`stderr` 和 `warnings`。
