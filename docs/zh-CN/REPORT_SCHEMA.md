# 报告结构

BinSight 输出两种报告：

- Markdown：面向人工阅读。
- JSON：面向测试、自动化和未来 MCP/agent 集成。

## JSON 顶层结构

```json
{
  "target": {},
  "imports": [],
  "sections": [],
  "strings": [],
  "disassembly_snippets": [],
  "rule_findings": [],
  "rag_context": [],
  "ai_analysis": {},
  "warnings": []
}
```

## 字段说明

- `target`：路径、格式、架构、位数、是否 stripped、大小和内容哈希。
- `imports`：依赖库和导入符号。
- `sections`：节区名称、大小、标志和风险备注。
- `strings`：可疑字符串及其分类。
- `disassembly_snippets`：有限反汇编片段和触发原因。
- `rule_findings`：本地规则命中结果和证据列表。
- `rag_context`：参与分析的本地知识条目。
- `ai_analysis`：模型提供方、模型名、摘要、风险来源和建议。
- `warnings`：工具缺失、解析失败或不支持格式等非致命问题。

