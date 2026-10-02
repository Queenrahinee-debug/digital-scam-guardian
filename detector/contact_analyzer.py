import sqlite3
import os

DB_PATH = "data/contacts.db"

def init_contact_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS contacts (
            name TEXT PRIMARY KEY,
            relation TEXT,
            normal_upi TEXT,
            asks_for_money_normally BOOLEAN
        )
    ''')
    cursor.execute("INSERT OR REPLACE INTO contacts VALUES ('Mom', 'Family', 'mom@okaxis', 0)")
    cursor.execute("INSERT OR REPLACE INTO contacts VALUES ('Son', 'Family', 'son@okhdfc', 0)")
    conn.commit()
    conn.close()

def analyze_sender_behavior(sender_name, message_text, upi_mentioned=None):
    init_contact_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT normal_upi, asks_for_money_normally FROM contacts WHERE name = ?", (sender_name,))
    row = cursor.fetchone()
    
    score = 0
    reasons = []
    text_lower = message_text.lower()
    
    if row:
        normal_upi, asks_money_normally = row
        if ("money" in text_lower or "rupees" in text_lower or "rs" in text_lower or "upi" in text_lower) and not asks_money_normally:
            score += 40
            reasons.append(f"Unusual behavior: '{sender_name}' does not normally request funds in their history.")
            
        if upi_mentioned and upi_mentioned != normal_upi:
            score += 35
            reasons.append(f"Mentions a new or unfamiliar payment ID instead of their saved profile ID.")
    else:
        score += 15
        reasons.append(f"Sender '{sender_name}' is not in your saved contacts list.")
        
    conn.close()
    return {
        "sender": sender_name,
        "sender_score": score,
        "sender_reasons": reasons
    }