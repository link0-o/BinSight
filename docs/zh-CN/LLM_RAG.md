# LLM 与 RAG

第一版 RAG 使用本地 Markdown 知识库，不引入向量数据库。规则命中、导入符号、可疑字符串和标签会被转换成查询词，用于检索 `knowledge/` 中相关条目。

启用在线 Provider 时，模型是第二个风险评估者，不只是把本地结论改写成自然语言。BinSight 会保留三层输出：

- `local_analysis`：本地规则生成的确定性基线。
- `ai_analysis`：模型基于结构化证据和 RAG 上下文给出的独立评估。
- `final_assessment`：融合本地和 AI 后的最终结论，也是报告的主要结论。

## 分析模式

- `none`：不调用模型，只输出确定性规则分析。
- `openai`：通过 `curl` 调用 OpenAI 官方 `/responses` 接口。
- `openai-compatible`：通过 `curl` 调用通用 `/chat/completions` 兼容接口。
- Provider preset：`deepseek`、`kimi`、`glm`、`qwen`/`dashscope`、`siliconflow`、`openrouter` 会自动填充 base URL、模型、key 环境变量和安全凭据名默认值。
- `anthropic`：调用 Anthropic 兼容 `/v1/messages` 接口。
- `deepseek-anthropic`：调用 DeepSeek 的 Anthropic 兼容接口。
- `ollama`：通过 `curl` 调用本地 Ollama `/api/generate` 接口。

GUI 的模型字段支持手动输入。preset 只是便捷选项，不是封闭列表。

可以在扫描前测试模型联通，且不会发送二进制报告：

```bash
binsight config test-llm --provider deepseek --model deepseek-v4-flash
```

测试请求只发送一条很短的 `Reply with OK.` 提示。

## 配置与 API Key

推荐使用交互式向导：

```bash
binsight config wizard
```

非敏感默认配置会保存到用户配置目录。API key 不会写入明文配置文件、报告或 JSON。Windows 上可以用 `binsight config set-key --provider deepseek` 将 key 保存到 Windows Credential Manager，配置文件只保存凭据引用名。当前构建如果所在平台没有安全凭据存储支持，则降级为使用环境变量。

运行时调用 `curl` 时会使用临时 curl 配置文件，避免 API key 出现在命令行参数中。

## 提示词原则

- 只基于扫描证据和本地知识解释风险。
- 明确区分确定证据和推测。
- 指出每个风险来自哪些库、函数、字符串、节区或反汇编片段。
- 给出简洁、可执行的复核建议。
- 遵守 `--report-lang`：中文报告请求中文模型输出，英文报告请求英文模型输出。
- AI 评估字段必须返回结构化 JSON；Markdown 报告由 BinSight 生成。
- 当本地规则存在强 `malicious-likely` 证据时，最终融合结论保留高风险下限。
