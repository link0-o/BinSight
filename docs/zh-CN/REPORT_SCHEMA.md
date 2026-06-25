# 报告结构

BinSight 输出面向人工阅读的分语言 Markdown，以及面向自动化的 JSON。

默认扫描输出：

- `report.zh-CN.md`
- `report.en.md`
- `report.json`

可以用 `--report-lang zh-CN|en|both` 控制 Markdown 输出语言。JSON 字段名保持稳定英文标识，不随报告语言变化。

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
  "ai_analysis": {},
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
- `rule_findings`：本地规则命中结果和证据列表。
- `rag_context`：参与分析的本地知识条目。
- `ai_analysis`：模型提供方、模型名、摘要、风险来源和建议。
- `dynamic_observations`：可选 Linux Docker 或导入的运行时观测证据。纯静态扫描中 `present` 为 false。
- `warnings`：工具缺失、解析失败或不支持格式等非致命问题。

## 动态观测字段

`dynamic_observations` 使用稳定英文 JSON 字段：

- `present`：是否附加动态报告。
- `platform`：观测平台，第一版为 `linux`。
- `mode`：观测模式，第一版为 `linux-docker`。
- `timeout_seconds`、`timed_out`、`exit_code`、`network_mode`。
- `process_events`、`file_events`、`network_events` 和 `syscall_summary`。
- `stdout`、`stderr` 和 `warnings`。
