import json
from detector.detector import analyze_message
from detector.link_analyzer import extract_urls, analyze_link
from detector.contact_analyzer import analyze_sender_behavior
from detector.train_model import train_scam_classifier

def evaluate_message_risk(sender, message_text, upi_mentioned=None):
    rule_result = analyze_message(message_text, sender)
    sender_result = analyze_sender_behavior(sender, message_text, upi_mentioned)
    
    urls = extract_urls(message_text)
    link_score = 0
    link_reasons = []
    has_links = len(urls) > 0
    
    if has_links:
        for url in urls:
            link_analysis = analyze_link(url)
            link_score += link_analysis["link_score"]
            link_reasons.extend(link_analysis["link_reasons"])
        link_safety = max(0, 100 - int(link_score * 2.0))
        link_display_value = f"{link_safety} / 100 safety"
        link_desc = "Scanned embedded URLs for suspicious domains or look-alike traps."
        link_color_style = "#27ae60" if link_safety >= 70 else "#c53030"
    else:
        link_display_value = "Not applicable (no link found)"
        link_desc = "No hyperlinks detected in the message text to analyze."
        link_color_style = "#94a3b8" # neutral grey
        
    try:
        vectorizer, model = train_scam_classifier()
        X_test = vectorizer.transform([message_text])
        ml_prob = model.predict_proba(X_test)[0][1]
    except Exception as e:
        ml_prob = 0.0
        
    # Multi-layered weight distribution: Rules (40%), Sender History (30%), ML (20%), Links (10%)
    raw_penalty = (rule_result["score"] * 0.4) + (sender_result["sender_score"] * 0.3) + (link_score * 0.1) + (int(ml_prob * 30) * 0.2)
    
    reputation_score = max(0, min(100, 100 - int(raw_penalty * 1.5)))
    
    rule_safety = max(0, 100 - int(rule_result["score"] * 1.2))
    sender_safety = max(0, 100 - int(sender_result["sender_score"] * 1.5))
    ml_safety = int((1.0 - ml_prob) * 100)
    
    all_reasons = rule_result["reasons"] + sender_result["sender_reasons"] + link_reasons
    
    priority_keywords = ["money", "payment", "call", "urgent", "behavior", "credentials"]
    def get_priority(reason):
        r_lower = reason.lower()
        for idx, kw in enumerate(priority_keywords):
            if kw in r_lower:
                return idx
        return 99

    sorted_reasons = sorted(list(set(all_reasons)), key=get_priority)
    action = rule_result["recommended_action"]
    
    if raw_penalty >= 45:
        risk_level = "HIGH RISK"
        badge_class = "badge-high"
    elif raw_penalty >= 20:
        risk_level = "SUSPICIOUS"
        badge_class = "badge-medium"
    else:
        risk_level = "LOW RISK"
        badge_class = "badge-low"
        
    if reputation_score >= 70:
        score_color = "green"
        score_label = "Safe"
    elif reputation_score >= 40:
        score_color = "orange"
        score_label = "Moderate Risk"
    else:
        score_color = "red"
        score_label = "High Risk"

    return {
        "sender": sender,
        "message": message_text,
        "risk_level": risk_level,
        "badge_class": badge_class,
        "reputation_score": reputation_score,
        "score_color": score_color,
        "score_label": score_label,
        "reasons": sorted_reasons,
        "recommended_action": action,
        "technical_breakdown": {
            "rule_score": {
                "value": f"{rule_safety} / 100 safety",
                "explanation": "Evaluated the text for pressure tactics, financial demands, and isolation cues."
            },
            "sender_score": {
                "value": f"{sender_safety} / 100 safety",
                "explanation": f"Checked {sender}'s baseline history for unusual funding requests."
            },
            "link_score": {
                "value": link_display_value,
                "explanation": link_desc,
                "color_style": link_color_style
            },
            "ml_score": {
                "value": f"{ml_safety} / 100 safety",
                "explanation": "Supporting text-pattern signal from a model trained on general SMS/phishing corpora."
            }
        }
    }