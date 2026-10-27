# PressurePrint AI

**Detecting Social Engineering Through Conversation Pattern Analysis**

Team 404BIDDEN · HackIndia AI & CyberTech Hackathon 2026
Team: Jaya Devi (Team Leader), Diya Srivastava

Most scam detectors check one message at a time. Real scammers do not work that way. They build trust, create pressure, and then ask for an OTP or money. Each message looks harmless alone, but the whole conversation gives them away.

PressurePrint AI reads the **whole conversation** (English and Hinglish), finds where pressure builds, and tells you how risky it is and why.

## Screenshots

| High risk (fake bank call, Hinglish) | Safe chat |
|---|---|
| ![High risk](screenshots/scam-high.png) | ![Low risk](screenshots/normal-low.png) |

## Features

- Reads the whole chat, not single messages (English + Hinglish)
- Risk score 0-100 with Low / Medium / High level
- **Risk timeline chart** showing how pressure builds message by message
- 8 warning signs: impersonation, urgency, fear, secrecy, lure, sensitive request, link or remote access, trust building
- Escalation detection (pressure first, then a sensitive ask)
- Plain-language reasons and safety advice
- **Report panel** for Medium/High risk: call 1930, open cybercrime.gov.in, copy a ready report summary
- 11 demo chats (scams, safe chats, real alerts) and 16 automated tests
- Nothing is stored

## Tech stack

Python · FastAPI · Uvicorn · Pydantic · pytest · HTML, CSS, JavaScript (no framework)

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
| `static/index.html` | Web UI: paste chat, see risk, timeline, reasons, report panel |
| `samples.py` | Demo scam chats and safe chats |
| `test_engine.py` | Automated tests |

## API

`POST /analyze` with `{"text": "line 1\nline 2"}` returns
`score`, `level` (Low/Medium/High), `signals`, `reasons`, `advice`, `escalation`, `timeline` and flagged `messages`.

## How the engine works

1. Splits the chat into messages (supports `Name: text` and WhatsApp export lines).
2. Matches 8 signals per message using English and Hinglish patterns.
3. Scores each distinct signal, adds an escalation bonus when pressure or false authority comes before a sensitive ask, and a combo bonus for secrecy plus urgency.
4. Recomputes the score after every message to draw the timeline.
5. Returns risk level, reasons and safety advice.

## Current status

The detection engine is **rule-based**. It is fast, explainable and works offline.

## Roadmap

- LLM layer (Gemini or Claude API) merged with the rule score, for better Hinglish spelling variations
- History page (SQLite)
- WhatsApp export upload and browser extension
- More languages
