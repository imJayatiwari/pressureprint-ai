# PressurePrint AI

Detects social engineering by analyzing a whole conversation (English + Hinglish).
Team 404BIDDEN · HackIndia 2026

## Run it

```bash
pip install -r requirements.txt
python -m uvicorn app:app --reload
# open http://localhost:8000
```

## Test it

```bash
python -m pytest -q
```

## Files

| File | What it does |
|------|--------------|
| `engine.py` | Detection engine: signals, escalation, risk score, reasons, advice |
| `app.py` | FastAPI server: `POST /analyze`, `GET /samples`, `GET /health` |
| `static/index.html` | Web UI (paste chat, see risk, reasons, flagged messages) |
| `samples.py` | Demo scam chats and safe chats |
| `test_engine.py` | Tests |

## API

`POST /analyze` with `{"text": "line 1\nline 2"}` returns
`score`, `level` (Low/Medium/High), `signals`, `reasons`, `advice`, `escalation`, and flagged `messages`.

## How the engine works

1. Splits the chat into messages (supports `Name: text` and WhatsApp export lines).
2. Matches 8 signals per message: impersonation, urgency, fear, secrecy, lure, sensitive request, link or remote-access request, trust building. English and Hinglish patterns.
3. Scores each distinct signal, adds an escalation bonus when pressure or false authority comes before a sensitive ask, and a combo bonus for secrecy + urgency.
4. Returns risk level, reasons, and safety advice.

## Ideas to add at the hackathon

- LLM layer (Claude or Gemini API) that returns the same JSON, merged with the rule score. Helps with Hinglish spelling variations.
- Per-message risk timeline chart showing how pressure builds.
- History page (SQLite) and a "report to 1930 / cybercrime.gov.in" button.
- Browser extension or WhatsApp-export upload.
