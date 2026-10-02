from pathlib import Path
from typing import Optional

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from detector.risk_engine import evaluate_message_risk

FRONTEND = Path(__file__).resolve().parent.parent / "frontend" / "index.html"   # works from any folder

app = FastAPI(title="Digital Scam Guardian", version="1.1")


class MessagePayload(BaseModel):
    sender: str = Field(min_length=1, max_length=100)
    message: str = Field(min_length=1, max_length=2000)    # rejects empty or huge input
    upi_mentioned: Optional[str] = None                     # optional; only used if it appears in the message


@app.get("/", response_class=HTMLResponse)
def read_root():
    if FRONTEND.exists():
        return FRONTEND.read_text(encoding="utf-8")
    return "frontend/index.html not found."


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.post("/api/analyze")
def analyze_endpoint(payload: MessagePayload):
    # The message is analysed in memory and is neither stored nor logged.
    return evaluate_message_risk(payload.sender, payload.message, payload.upi_mentioned)