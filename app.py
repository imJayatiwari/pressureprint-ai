from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from pathlib import Path

from engine import analyze

BASE = Path(__file__).parent
app = FastAPI(title="PressurePrint AI")


class Chat(BaseModel):
    text: str


@app.post("/analyze")
def analyze_chat(chat: Chat):
    result = analyze(chat.text[:20000])
    if "error" in result:
        return JSONResponse(result, status_code=400)
    return result


@app.get("/samples")
def samples():
    from samples import SAMPLES, as_text
    return {name: as_text(name) for name in SAMPLES}


@app.get("/health")
def health():
    return {"status": "ok"}


app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")


@app.get("/")
def index():
    return FileResponse(BASE / "static" / "index.html")
