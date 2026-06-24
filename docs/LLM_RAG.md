# LLM and RAG

RAG is local and auditable in the first version. Markdown files in `knowledge/` are loaded and scored with keyword matching against imports, rule findings, tags, and suspicious strings.

## Provider Modes

- `none`: no network call; writes deterministic local analysis.
- `openai`: calls an OpenAI-compatible `/chat/completions` endpoint through `curl`.
- `ollama`: calls Ollama `/api/generate` through `curl`.

## Prompting Principles

- Use only observed evidence and retrieved local knowledge.
- Separate confirmed evidence from speculation.
- Name the source of each risk.
- Prefer concise recommendations over broad claims.

