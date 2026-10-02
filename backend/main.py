from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import os

# Import our unified risk engine
from detector.risk_engine import evaluate_message_risk

app = FastAPI(title="Digital Scam Guardian", version="1.0")

# Request body model for API analysis
class MessagePayload(BaseModel):
    sender: str
    message: str
    upi_mentioned: str = None

@app.get("/", response_class=HTMLResponse)
def read_root():
    """Serves the elderly-first frontend interface."""
    html_path = os.path.join("frontend", "index.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    return "Frontend index.html not found. Please check your project structure."

@app.post("/api/analyze")
def analyze_endpoint(payload: MessagePayload):
    """API endpoint that runs the unified risk evaluation engine."""
    result = evaluate_message_risk(
        sender=payload.sender,
        message_text=payload.message,
        upi_mentioned=payload.upi_mentioned
    )
    return result