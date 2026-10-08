"""Rule-based content analysis.

Every rule is one line: (signal name, regex, points, plain-language reason).
Regexes use word boundaries (\b) so "rs" no longer matches inside "hours".
"""
import re

# A money REQUEST = an asking/sending verb close to a money word (UPI app, amount, fee...).
# A plain mention ("Rs 1,200 debited", "fees due on the 10th") is NOT a request and scores nothing.
_MONEY = (r"(?:upi|paytm|phonepe|gpay|google pay|money|paise|rupees?|fees?"
          r"|(?:₹|\brs\.?|\binr)\s*\d[\d,]*|\b\d[\d,]*\s*(?:rs|rupees?|inr))")
_VERB = r"(?:send|transfer|pay|lend|loan|borrow|deposit|bhej(?:o|na)?|kar ?de|de ?do|chahiye)"
_MONEY_REQUEST = rf"\b{_VERB}\b.{{0,60}}\b{_MONEY}|\b{_MONEY}.{{0,30}}\b{_VERB}\b"

_RULES = [
    ("urgency",
     r"\b(?:immediately|urgent(?:ly)?|right now|asap|hurry|emergency|last warning|jaldi|turant)\b"
     r"|within \d+ (?:minutes?|hours?)",
     25, "It tries to rush you."),
    ("threat",
     r"\baccount\b.{0,40}\b(?:blocked|suspended|closed|deactivated)\b"
     r"|\bwill be (?:blocked|closed|suspended)\b",
     30, "It says your bank account will be blocked or closed."),
    ("financial", _MONEY_REQUEST, 30, "It asks you to send or pay money."),
    ("credential_request",
     r"\b(?:send|share|tell|give|provide|enter|reply with|forward)\b.{0,30}\b(?:otp|pin|password|cvv|(?:\d[- ]digit |verification |security |secret )code)\b",
     40, "It asks for your PIN, password or secret code (OTP)."),
    ("kyc", r"\bkyc\b", 20, "It talks about updating your bank details (KYC). Scammers use this a lot."),
    ("secrecy",
     r"\bdo(?:n[’']?t| not) (?:call|tell)\b|\bkeep (?:this )?(?:a )?secret\b|\bbaad mein call\b|\bmat batana\b",
     25, "It tells you not to call or not to tell anyone."),
    ("authority",
     r"\b(?:police|cbi|trai|customs|arrest|warrant|money laundering|digital arrest)\b",
     25, "It says it is from the police or the government, or talks about arrest."),
    ("prize",
     r"\byou have won\b|\bwinner\b|\blottery\b|\blucky draw\b|\bprize\b|\bcongratulations\b",
     30, "It says you have won a prize."),
]
_COMPILED = [(n, re.compile(p, re.IGNORECASE), pts, why) for n, p, pts, why in _RULES]


_ASKS_MONEY = re.compile(_MONEY_REQUEST, re.IGNORECASE)


def asks_for_money(text):
    """True only when the message asks the reader to send or pay money."""
    return bool(_ASKS_MONEY.search(text))


def analyze_message(message_text, sender="Unknown"):
    score, reasons, signals = 0, [], []

    for name, pattern, points, reason in _COMPILED:
        if pattern.search(message_text):
            score += points
            reasons.append(reason)
            signals.append(name)

    # Signals are stronger together: money + pressure/secrecy is the classic scam shape.
    if "financial" in signals and {"urgency", "secrecy"} & set(signals):
        score += 15
        reasons.append("It asks for money and also rushes you or asks for secrecy. Scammers do this a lot.")

    score = min(score, 100)
    if score >= 60:
        risk_level = "HIGH"
    elif score >= 30:
        risk_level = "SUSPICIOUS"
    else:
        risk_level = "LOW"

    # Neutral wording: the risk engine writes the final, sender-aware advice.
    action = f"Verify this message from {sender} on a number or channel you already trust before acting."

    return {
        "sender": sender,
        "score": score,
        "risk_level": risk_level,
        "reasons": reasons,
        "signals": signals,
        "recommended_action": action,
    }