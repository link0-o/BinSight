# LLM 与 RAG

第一版 RAG 使用本地 Markdown 知识库，不引入向量数据库。规则命中、导入符号、可疑字符串和标签会被转换成查询词，用于检索 `knowledge/` 中相关条目。

## 分析模式

- `none`：不调用模型，只输出确定性规则分析。
- `openai`：通过 `curl` 调用 OpenAI 兼容 `/chat/completions` 接口。
- `ollama`：通过 `curl` 调用本地 Ollama `/api/generate` 接口。

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
