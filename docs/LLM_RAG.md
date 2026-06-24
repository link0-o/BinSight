# LLM and RAG

RAG is local and auditable in the first version. Markdown files in `knowledge/` are loaded and scored with keyword matching against imports, rule findings, tags, and suspicious strings.

## Provider Modes

- `none`: no network call; writes deterministic local analysis.
- `openai`: calls an OpenAI-compatible `/chat/completions` endpoint through `curl`.
- `ollama`: calls Ollama `/api/generate` through `curl`.

## Configuration and API Keys

Use the interactive wizard for normal setup:

```bash
binsight config wizard
```

Non-sensitive defaults are stored in the user config directory. API keys are not written to plaintext config files, reports, or JSON. On Windows, `binsight config set-key --provider deepseek` stores the key in Windows Credential Manager and saves only the credential reference name in config. On platforms without secure storage support in this build, use an API key environment variable.

Runtime `curl` calls use a temporary curl config file so the API key is not exposed as a command-line argument.

## Prompting Principles

- Use only observed evidence and retrieved local knowledge.
- Separate confirmed evidence from speculation.
- Name the source of each risk.
- Prefer concise recommendations over broad claims.
- Follow `--report-lang`: Chinese reports request Chinese model output, English reports request English model output.
