"""Compares a message with what is normal for that contact (scripted demo baseline)."""
import re
import sqlite3
from contextlib import closing
from pathlib import Path

from detector.detector import asks_for_money

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "contacts.db"  # works from any folder

# Demo baseline: (name, relation, usual UPI ID, asks for money normally?). Edit freely.
SEED_CONTACTS = [
    ("Mom", "Family", "mom@okaxis", 0),
    ("Dad", "Family", "dad@oksbi", 0),
    ("Son", "Family", "son@okhdfcbank", 0),
    ("Rahul", "Friend", "rahul@okicici", 1)   # friends often split bills,
]

MONEY_RE = re.compile(
    r"\b(?:money|upi|rupees?|paytm|phonepe|gpay|google pay|transfer|paise)\b"
    r"|(?:₹|\brs\.?|\binr)\s*\d|\b\d[\d,]*\s*(?:rs|rupees?|inr)\b", re.I)
NEW_ID_RE = re.compile(r"\b(?:new|different|another)\s+(?:upi|account|number|id|payment)\b", re.I)
USUAL_RE = re.compile(r"\b(?:usual|same|saved|old|regular)\s+(?:upi|paytm|gpay|phonepe|account|id|number)\b", re.I)
UPI_ID_RE = re.compile(r"\b[\w.\-]{2,}@[a-z]{2,}\b", re.I)
EMAIL_HOSTS = {"gmail", "yahoo", "outlook", "hotmail", "icloud"}

_db_ready = False


def init_contact_db():
    """Create and fill the table once per run, not on every message."""
    global _db_ready
    if _db_ready:
        return
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS contacts (
            name TEXT PRIMARY KEY, relation TEXT, normal_upi TEXT, asks_for_money_normally BOOLEAN)""")
        conn.executemany("INSERT OR REPLACE INTO contacts VALUES (?, ?, ?, ?)", SEED_CONTACTS)
        conn.commit()
    _db_ready = True


def _ids_in(text, client_value=None):
    """Payment IDs actually present in the message. A value sent by the client counts only if the text contains it."""
    ids = {m.lower() for m in UPI_ID_RE.findall(text) if m.split("@")[1].lower() not in EMAIL_HOSTS}
    if client_value and client_value.lower() in text.lower():
        ids.add(client_value.lower())
    return ids


def analyze_sender_behavior(sender_name, message_text, upi_mentioned=None):
    init_contact_db()
    name = (sender_name or "").strip()
    with closing(sqlite3.connect(DB_PATH)) as conn:
        row = conn.execute(
            "SELECT normal_upi, asks_for_money_normally FROM contacts WHERE lower(name) = lower(?)", (name,)
        ).fetchone()

    score, reasons = 0, []
    asks_money = asks_for_money(message_text)
    usual = bool(USUAL_RE.search(message_text))

    if row:
        normal_upi, asks_normally = row
        if asks_money and not asks_normally:
            score += 15 if usual else 40   # a money request using a "usual" ID is far less alarming
            reasons.append(f"{name} does not usually ask for money.")
        ids = _ids_in(message_text, upi_mentioned)
        new_id = bool(NEW_ID_RE.search(message_text)) or any(i != normal_upi.lower() for i in ids)
        if asks_money and new_id and not usual:
            score += 35
            reasons.append(f"It asks you to pay to a new payment ID that {name} has not used before.")
    else:
        score += 15
        reasons.append(f"You do not have '{name}' saved as a contact.")
        if asks_money:
            score += 20
            reasons.append("Someone you do not know is asking for money.")

    return {"sender": name, "sender_score": min(score, 100), "sender_reasons": reasons, "known_contact": bool(row)}