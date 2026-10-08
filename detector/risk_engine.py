"""Combines the four layers into one verdict.

Why not a weighted average (40/30/20/10)? An average dilutes a strong single signal: a clearly fake link
(10% weight) could never lift a message out of "safe". Here each layer gives a risk 0-100 and the layers are
combined with "noisy-OR": risk = 1 - product(1 - layer_risk * trust). Any strong layer raises the verdict,
agreement between layers raises it more, and layers that do not apply (no link) simply add nothing.
"""
import re
from detector.detector import analyze_message
from detector.link_analyzer import extract_urls, analyze_link
from detector.contact_analyzer import analyze_sender_behavior
from detector.train_model import get_model

TRUST = {"rules": 0.9, "sender": 0.9, "link": 0.9}   # ML trust is set from how much data it saw
HIGH_AT, SUSPICIOUS_AT = 60, 31                      # risk thresholds, matching the 0-39 / 40-69 / 70-100 scale in the UI
OTP_NOTICE = re.compile(r"\botp\b.{0,80}\bdo(?:n[’']?t| not) share\b|\bdo(?:n[’']?t| not) share\b.{0,40}\botp\b", re.I | re.S)
PRIORITY = ["fake copy", "new payment id", "send or pay money", "does not usually", "not to call", "rush", "pin, password", "arrest", "link", "kyc"]


def _combine(pairs):
    keep = 1.0
    for risk, trust in pairs:
        keep *= 1 - (risk / 100) * trust
    return round((1 - keep) * 100)


def _advice(level, sender, known, signals, has_links):
    if level == "LOW":
        return "We did not find anything worrying. Still, be careful with links and with anyone who asks for money."
    if level == "HIGH" and known:
        return (f"This does not sound like how {sender} usually writes. {sender}'s phone may have been hacked, "
                f"or a scammer may be pretending to be {sender}. Call {sender} on the number you already have "
                f"before you do anything.")
    if level == "HIGH" and "financial" in signals and not has_links:
        return ("Do not send any money. Call this person on a number you already know, "
                "or ask someone in your family, before you do anything.")
    if level == "HIGH":
        return ("Do not reply, do not tap any link and do not send money. If it says it is from your bank "
                "or the police, call them on the number printed on your bank card.")
    who = sender if known else "the sender"
    return f"Wait before you do anything. Check with {who} by calling a number you already know."


def _headline(level, signals, has_links):
    if level == "LOW":
        return "This message looks safe"
    if "financial" in signals:
        return "Don't send money yet"
    if "credential_request" in signals:
        return "Don't share any code or PIN"
    if has_links:
        return "Don't open this link"
    return "Be careful with this message"


def evaluate_message_risk(sender, message_text, upi_mentioned=None):
    rules = analyze_message(message_text, sender)
    who = analyze_sender_behavior(sender, message_text, upi_mentioned)

    # Links
    urls = extract_urls(message_text)
    link_score, link_reasons = 0, []
    for u in urls:
        a = analyze_link(u)
        link_score += a["link_score"]
        link_reasons += a["link_reasons"]
    link_risk = min(100, link_score * 2)

    # ML: counts only when it is more than 50% sure; trusted more once it has seen real amounts of data
    try:
        vec, model, ml_info = get_model()
        p = float(model.predict_proba(vec.transform([message_text]))[0][1])
        ml_risk = max(0.0, (p - 0.5) * 2) * 100
        ml_trust = 0.5 if ml_info["n_total"] >= 500 else 0.2
        ml_safety = round((1 - p) * 100)
        if ml_info["holdout"]:
            ml_note = f"A small computer helper trained on {ml_info['n_total']} sample messages. It is only a hint."
        else:
            ml_note = f"A small computer helper trained on only {ml_info['n_total']} sample messages. We treat it as a weak hint."
    except Exception:
        ml_risk, ml_trust, ml_safety, ml_note = 0.0, 0.0, None, "The computer helper is not available."

    risk = _combine([(rules["score"], TRUST["rules"]), (who["sender_score"], TRUST["sender"]),
                     (link_risk, TRUST["link"]), (ml_risk, ml_trust)])

    reasons = list(dict.fromkeys(rules["reasons"] + who["sender_reasons"] + link_reasons))
    reasons.sort(key=lambda r: next((i for i, k in enumerate(PRIORITY) if k in r.lower()), 99))

    # A genuine OTP notice warns "do not share"; do not treat it as a scam
    if OTP_NOTICE.search(message_text) and "credential_request" not in rules["signals"] and not urls:
        risk = min(risk, 20)
        reasons = ["This looks like a normal secret-code message from a bank or shop. Never tell this code to anyone."]

    if risk >= HIGH_AT:
        level, label, badge, color = "HIGH", "High Risk", "badge-high", "red"
    elif risk >= SUSPICIOUS_AT:
        level, label, badge, color = "SUSPICIOUS", "Moderate Risk", "badge-medium", "orange"
    else:
        level, label, badge, color = "LOW", "Safe", "badge-low", "green"

    return {
        "sender": sender, "message": message_text,
        "risk_level": {"HIGH": "HIGH RISK", "SUSPICIOUS": "SUSPICIOUS", "LOW": "LOW RISK"}[level],
        "level_label": {"HIGH": "DANGER", "SUSPICIOUS": "BE CAREFUL", "LOW": "LOOKS SAFE"}[level], "badge_class": badge, "score_color": color, "score_label": label,
        "risk": risk, "reputation_score": 100 - risk,
        "headline": _headline(level, rules["signals"], bool(urls)),
        "recommended_action": _advice(level, sender, who["known_contact"], rules["signals"], bool(urls)),
        "reasons": reasons,
        "technical_breakdown": {
            "rule_score": {"value": f"{100 - rules['score']} / 100 safe",
                           "explanation": "Looked at the words for rushing, money requests and secrecy."},
            "sender_score": {"value": f"{100 - who['sender_score']} / 100 safe",
                             "explanation": f"Checked if this message is normal for {sender}."},
            "link_score": {
                "value": f"{max(0, 100 - link_risk)} / 100 safe" if urls else "No link in the message",
                "explanation": "Checked the link for fake websites and short links." if urls else "There is no link to check.",
                "color_style": ("#27ae60" if link_risk < 30 else "#c53030") if urls else "#94a3b8"},
            "ml_score": {"value": f"{ml_safety} / 100 safe" if ml_safety is not None else "Not available",
                         "explanation": ml_note},
        },
    }