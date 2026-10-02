import re

def analyze_message(message_text, sender="Unknown"):
    """
    Analyzes message text using indicator groups to assign a score,
    risk level, and plain-language reasons.
    """
    score = 0
    reasons = []
    text_lower = message_text.lower()
    
    # 1. Urgency / High Pressure Indicators
    urgency_keywords = ["immediately", "urgent", "today", "blocked", "closed", "expire", "hurry"]
    if any(word in text_lower for word in urgency_keywords):
        score += 30
        reasons.append("Creates false urgency or threatens account restriction.")
        
    # 2. Financial Request / Payment Indicators
    financial_keywords = ["upi", "fee", "fees", "rs", "rupees", "send money", "transfer", "pay"]
    if any(word in text_lower for word in financial_keywords):
        score += 35
        reasons.append("Requests a financial transaction or payment.")
        
    # 3. Credential / KYC / Bank Action Indicators
    credential_keywords = ["kyc", "otp", "pin", "password", "bank account", "credit card"]
    if any(word in text_lower for word in credential_keywords):
        score += 30
        reasons.append("Mentions sensitive actions like KYC updates or account credentials.")
        
    # 4. Secrecy / Isolation Indicators
    secrecy_keywords = ["don't call", "do not call", "dont call", "keep this secret", "don't tell"]
    if any(word in text_lower for word in secrecy_keywords):
        score += 25
        reasons.append("Instructs you not to verify or call back.")

    # Determine Risk Level and Action based on combined scores
    if score >= 60:
        risk_level = "HIGH"
        action = "Do not click links, share details, or send money. Verify independently."
    elif score >= 30:
        risk_level = "SUSPICIOUS"
        action = "Proceed with caution. Check with family or official channels before acting."
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

if __name__ == "__main__":
    # Test run with a sample scam message
    test_msg = "Dear customer, your SBI bank account is blocked today. Click link to update KYC immediately."
    result = analyze_message(test_msg, sender="BankAlert")
    print("Test Analysis Result:")
    print(result)