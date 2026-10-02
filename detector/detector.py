"""Rule-based content analysis.

Every rule is one line: (signal name, regex, points, plain-language reason).
Regexes use word boundaries (\b) so "rs" no longer matches inside "hours".
"""
import re

_RULES = [
    ("urgency",
     r"\b(?:immediately|urgent(?:ly)?|right now|asap|hurry|emergency|last warning|jaldi|turant)\b"
     r"|within \d+ (?:minutes?|hours?)",
     25, "Uses high-pressure or urgent language."),
    ("threat",
     r"\baccount\b.{0,40}\b(?:blocked|suspended|closed|deactivated)\b"
     r"|\bwill be (?:blocked|closed|suspended)\b",
     30, "Threatens account restriction or closure."),
    ("financial",
     r"\bupi\b|\bpaytm\b|\bphonepe\b|\bgpay\b|\bgoogle pay\b|\btransfer\b|\bmoney\b|\bfees?\b|\bpaise\b"
     r"|(?:₹|\brs\.?|\binr)\s*\d|\b\d[\d,]*\s*(?:rs|rupees?|inr)\b",
     30, "Requests a financial transaction or payment."),
    ("credential_request",
     r"\b(?:send|share|tell|give|provide|enter|reply with|forward)\b.{0,30}\b(?:otp|pin|password|cvv)\b",
     40, "Asks you to share a password, PIN or OTP."),
    ("kyc", r"\bkyc\b", 20, "Mentions a KYC update, a common scam pretext."),
    ("secrecy",
     r"\bdo(?:n[’']?t| not) (?:call|tell)\b|\bkeep (?:this )?(?:a )?secret\b|\bbaad mein call\b|\bmat batana\b",
     25, "Tells you not to call back or not to tell anyone."),
    ("authority",
     r"\b(?:police|cbi|trai|customs|arrest|warrant|money laundering|digital arrest)\b",
     25, "Claims to be police or an official body, or threatens arrest."),
    ("prize",
     r"\byou have won\b|\bwinner\b|\blottery\b|\blucky draw\b|\bprize\b|\bcongratulations\b",
     30, "Claims you have won a prize."),
]
_COMPILED = [(n, re.compile(p, re.IGNORECASE), pts, why) for n, p, pts, why in _RULES]


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
        reasons.append("Combines a money request with pressure or secrecy, a classic scam pattern.")

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