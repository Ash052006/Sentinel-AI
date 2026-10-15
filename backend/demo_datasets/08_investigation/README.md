# Investigation

Gemini-backed investigation of a correlation.

## Inputs

- `workflow.json`

## Observed / expected behaviour

Library-only: no API route and no persistence table. Requires a configured Gemini key; without it the agent cannot produce a verdict.

## Run

```bash
python -c "from app.agents.investigation import ..."
```

## Requirements

- GEMINI_API_KEY
- Qdrant reachable (RAG)
