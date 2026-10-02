import sys
import os

# Add the root directory to path so Python can find the 'detector' folder
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from detector.risk_engine import evaluate_message_risk

# Define the test scenarios you want to run
test_cases = [
    ("Rahul (Friend/Colleague)", "Rahul", "Can you send 5000 rupees urgently to this new UPI ID? Don't call me.", "unfamiliar-id@upi"),
    ("Unknown Number", "+919876543210", "Can you send 5000 rupees urgently to this new UPI ID? Don't call me.", "unfamiliar-id@upi"),
    ("Mom (Normal Request)", "Mom", "Hey, can you transfer 1200 for the electricity bill to our usual paytm id?", "usual-paytm@paytm"),
    ("Bank OTP Notice", "HDFC Bank", "Your OTP for txn of INR 450.00 at Swiggy is 829104. Do not share with anyone.", None),
    ("Calm Scam (KYC Pretext)", "Unknown Support", "Hello sir, regarding your pending KYC update, please tap the link below to verify at https://fake-kyc-update.com", None),
    ("Hinglish Scam", "Friend", "Bhai emergency hai, 2000 Paytm karde jaldi, baad mein call karta hu.", "fake@paytm")
]

print("=" * 60)
print("RUNNING DIGITAL SCAM GUARDIAN TEST SCENARIOS")
print("=" * 60)

for label, sender, message, upi in test_cases:
    result = evaluate_message_risk(sender, message, upi_mentioned=upi)
    print(f"\n[Test Case]: {label}")
    print(f"Sender: {sender}")
    print(f"Message: \"{message}\"")
    print(f"-> Verdict: {result['risk_level']} | Safety Reputation Score: {result['reputation_score']}/100 ({result['score_label']})")
    print(f"-> Recommended Action: {result['recommended_action']}")

print("\n" + "=" * 60)
print("ALL TESTS COMPLETED SUCCESSFULLY!")
print("=" * 60)