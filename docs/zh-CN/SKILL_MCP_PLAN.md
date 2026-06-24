# Skill 与 MCP 计划

BinSight 后续适合增加项目专用 Codex Skill 和 MCP Server，但第一版不依赖它们。

## 项目 Skill

建议 Skill 名称：

```text
binsight-binary-risk-analysis
```

这个 Skill 应指导后续 agent：

- 保持扫描流程确定性。
- 保持风险结论基于证据。
- 修改风险等级前先阅读风险模型。
- 修改 JSON/Markdown 输出前先阅读报告结构。
- 避免把核心扫描器改成不受约束的 agent 循环。

## 后续 MCP Server

MCP 层应包装稳定的 CLI 和 JSON 报告能力：

- `analyze_binary(path)`
- `get_imports(report_json)`
- `explain_finding(report_json, finding_id)`
- `compare_reports(left_json, right_json)`

MCP 不应替代确定性扫描逻辑，只负责把稳定能力暴露给 AI 工具调用。

