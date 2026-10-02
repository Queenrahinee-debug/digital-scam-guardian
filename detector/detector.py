import re

def analyze_message(message_text, sender="Unknown"):
    score = 0
    reasons = []
    text_lower = message_text.lower()
    
    # 1. Urgency Indicators (Separated cleanly)
    urgency_keywords = ["immediately", "urgent", "today", "hurry", "urgently"]
    if any(word in text_lower for word in urgency_keywords):
        score += 30
        reasons.append("Uses high-pressure or urgent language.")
        
    # Account threats (Separate rule)
    threat_keywords = ["blocked", "closed", "expire", "suspension"]
    if any(word in text_lower for word in threat_keywords):
        score += 30
        reasons.append("Threatens account restriction or closure.")
        
    # 2. Financial Request
    financial_keywords = ["upi", "fee", "fees", "rs", "rupees", "send money", "transfer", "pay"]
    if any(word in text_lower for word in financial_keywords):
        score += 35
        reasons.append("Requests a financial transaction or payment.")
        
    # 3. Credentials / KYC
    credential_keywords = ["kyc", "otp", "pin", "password", "bank account"]
    if any(word in text_lower for word in credential_keywords):
        score += 30
        reasons.append("Mentions sensitive actions like KYC updates or credentials.")
        
    # 4. Secrecy / Isolation
    secrecy_keywords = ["don't call", "do not call", "dont call", "keep this secret"]
    if any(word in text_lower for word in secrecy_keywords):
        score += 25
        reasons.append("Instructs you not to verify or call back.")

    if score >= 60:
        risk_level = "HIGH"
        action = f"This looks unusual for {sender}. Her account may be compromised, or someone may be pretending to be her. Call {sender} directly on her usual phone number before taking any action."
    elif score >= 30:
        risk_level = "SUSPICIOUS"
        action = f"Proceed with caution. Verify independently with {sender} through trusted channels."
    else:
        risk_level = "LOW"
        action = "No major risk indicators detected."
        
    return {
        "sender": sender,
        "score": score,
        "risk_level": risk_level,
        "reasons": reasons,
        "recommended_action": action
    }