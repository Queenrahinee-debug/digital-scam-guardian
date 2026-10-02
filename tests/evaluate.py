"""Scores the detector on a labelled file. Usage: python tests/evaluate.py [data/test_messages.json]
Run it on the hold-out file once, record the numbers, and do NOT tune your rules on that file afterwards."""
import json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from detector.risk_engine import evaluate_message_risk

path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "data" / "test_messages.json"
text = path.read_text(encoding="utf-8").strip() if path.exists() else ""
if not text:
    sys.exit(f"{path} is empty. Add labelled messages first (sender, message, label).")

tp = fp = tn = fn = 0
wrong = []
for item in json.loads(text):
    result = evaluate_message_risk(item["sender"], item["message"])
    flagged = result["risk_level"] != "LOW RISK"          # SUSPICIOUS and HIGH both count as a warning
    risky = item["label"] != "safe"
    tp += flagged and risky; fp += flagged and not risky
    tn += (not flagged) and (not risky); fn += (not flagged) and risky
    if flagged != risky:
        wrong.append((item.get("id"), item["label"], result["risk_level"], item["message"][:70]))

n = tp + fp + tn + fn
print(f"Messages: {n} | TP {tp}  FP {fp}  TN {tn}  FN {fn}")
print(f"Accuracy {(tp + tn) / n:.1%} | Precision {tp / max(tp + fp, 1):.1%} | Recall {tp / max(tp + fn, 1):.1%}")
print("\nMistakes (put these in your limitations slide):")
for w in wrong:
    print(" ", w)