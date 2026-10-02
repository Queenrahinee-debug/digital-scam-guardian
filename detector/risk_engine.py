import json
import re
from detector.detector import analyze_message
from detector.link_analyzer import extract_urls, analyze_link
from detector.contact_analyzer import analyze_sender_behavior
from detector.train_model import train_scam_classifier

def evaluate_message_risk(sender, message_text, upi_mentioned=None):
    """
    Combines rule-based checks, ML classification, link analysis, 
    and sender context into a final risk assessment.
    """
    # 1. Run Rule-based analysis
    rule_result = analyze_message(message_text, sender)
    
    # 2. Run Sender / Known-Contact analysis
    sender_result = analyze_sender_behavior(sender, message_text, upi_mentioned)
    
    # 3. Run Link analysis if URLs are present
    urls = extract_urls(message_text)
    link_score = 0
    link_reasons = []
    for url in urls:
        link_analysis = analyze_link(url)
        link_score += link_analysis["link_score"]
        link_reasons.extend(link_analysis["link_reasons"])
        
    # 4. Run ML Classification score
    try:
        vectorizer, model = train_scam_classifier()
        X_test = vectorizer.transform([message_text])
        ml_prob = model.predict_proba(X_test)[0][1] # Probability of being a scam/risky
        ml_score = int(ml_prob * 50) # Scale to a 0-50 weight
    except Exception as e:
        ml_score = 0
        
    # 5. Aggregate Total Score
    total_score = rule_result["score"] + sender_result["sender_score"] + link_score + ml_score
    
    # Combine all unique reasons
    all_reasons = list(set(rule_result["reasons"] + sender_result["sender_reasons"] + link_reasons))
    
    # Determine Final Risk Level & Elderly-First Action
    if total_score >= 70:
        risk_level = "HIGH"
        action = "🛑 STOP! Do not click links, send money, or share OTP/PIN. This matches a known scam pattern."
    elif total_score >= 35:
        risk_level = "SUSPICIOUS"
        action = "⚠️ CAUTION. This message looks unusual. Verify independently by calling your family member or official support."
    else:
        risk_level = "LOW"
        action = "✅ Looks safe. No major risk signals detected."
        
    return {
        "sender": sender,
        "message": message_text,
        "total_score": total_score,
        "risk_level": risk_level,
        "reasons": all_reasons,
        "recommended_action": action
    }

if __name__ == "__main__":
    # Test with a high-risk disguised contact scenario
    test_scenario = "Can you send 5000 rupees urgently to this new UPI ID? Don't call me."
    result = evaluate_message_risk("Mom", test_scenario, upi_mentioned="fraud-upi@oksbi")
    print("Unified Risk Engine Evaluation:")
    print(json.dumps(result, indent=4))