"""Quick demo scenarios with expected outcomes. Prints PASS/FAIL, so it can no longer claim success on its own.
Run from anywhere:  python tests/run_scenarios.py
These are a smoke test, not a validation. Real evidence comes from tests/evaluate.py on the hold-out file."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from detector.risk_engine import evaluate_message_risk

# (name, sender, message, acceptable verdicts)
SCENARIOS = [
    ("Rahul (known friend) asks for money, new UPI ID", "Rahul",
     "Can you send 5000 rupees urgently to this new UPI ID? Don't call me.", {"HIGH RISK"}),
    ("Unknown number, same message", "+919876543210",
     "Can you send 5000 rupees urgently to this new UPI ID? Don't call me.", {"HIGH RISK"}),
    ("Mom (usual payment ID; sample profile says Mom rarely asks for money)", "Mom",
     "Hey, can you transfer 1200 for the electricity bill to our usual paytm id?", {"LOW RISK", "SUSPICIOUS"}),
    ("Genuine bank OTP notice", "HDFC Bank",
     "Your OTP for txn of INR 450.00 at Swiggy is 829104. Do not share with anyone.", {"LOW RISK"}),
    ("Calm scam (KYC pretext + fake link)", "Unknown Support",
     "Hello sir, regarding your pending KYC update, please tap the link below to verify at https://fake-kyc-update.com",
     {"HIGH RISK"}),
    ("Hinglish scam", "Friend",
     "Bhai emergency hai, 2000 Paytm karde jaldi, baad mein call karta hu.", {"HIGH RISK"}),
    ("Normal family chat", "Mom",
     "Hi beta, are you coming home for dinner tonight?", {"LOW RISK"}),
    ("Normal message mentioning 'hours' (old 'rs' bug)", "Dad",
     "Call me in a few hours, we are having dinner late.", {"LOW RISK"}),
    ("Genuine shopping site link", "Rahul",
     "Check this jacket I found: https://www.flipkart.com/jackets", {"LOW RISK"}),
]

print("=" * 64)
print("DIGITAL SCAM GUARDIAN: SCENARIO CHECKS")
print("=" * 64)
passed = 0
for name, sender, message, ok in SCENARIOS:
    r = evaluate_message_risk(sender, message)
    good = r["risk_level"] in ok
    passed += good
    print(f"\n[{'PASS' if good else 'FAIL'}] {name}")
    print(f"  Sender: {sender}")
    print(f"  Message: {message}")
    print(f"  Verdict: {r['risk_level']} (safety {r['reputation_score']}/100) | expected: {' or '.join(sorted(ok))}")
    print(f"  Advice: {r['recommended_action']}")
    for reason in r["reasons"]:
        print(f"    - {reason}")

print("\n" + "=" * 64)
print(f"{passed} of {len(SCENARIOS)} scenarios matched expectations.")
if passed < len(SCENARIOS):
    print("Some scenarios did not match. Check the FAIL lines above.")
print("=" * 64)
sys.exit(0 if passed == len(SCENARIOS) else 1)