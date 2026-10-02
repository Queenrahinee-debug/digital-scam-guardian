"""Trains the small text classifier ONCE per run and reports honest metrics.

Training data = data/dev_messages.json (+ optional data/SMSSpamCollection, the UCI file with lines "ham<TAB>text").
Never train on data/test_messages.json: that file is your untouched hold-out set.
"""
import json
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parent.parent
DEV_FILE = ROOT / "data" / "dev_messages.json"
PUBLIC_FILE = ROOT / "data" / "SMSSpamCollection"
_cache = None


def load_training_data():
    texts, labels = [], []
    with open(DEV_FILE, encoding="utf-8") as f:
        for item in json.load(f):
            texts.append(item["message"])
            labels.append(0 if item["label"] == "safe" else 1)   # scam/suspicious -> 1
    sources = [f"dev_messages.json ({len(texts)})"]
    if PUBLIC_FILE.exists():
        n = 0
        for line in PUBLIC_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
            tag, _, text = line.partition("\t")
            if tag in ("ham", "spam") and text:
                texts.append(text)
                labels.append(1 if tag == "spam" else 0)
                n += 1
        sources.append(f"SMSSpamCollection ({n})")
    return texts, labels, sources


def _fit(texts, labels):
    vec = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True)
    model = LogisticRegression(max_iter=1000, class_weight="balanced")
    model.fit(vec.fit_transform(texts), labels)
    return vec, model


def get_model():
    """Returns (vectorizer, model, info). Trained on first call, then reused (it was retrained per request before)."""
    global _cache
    if _cache is None:
        texts, labels, sources = load_training_data()
        info = {"n_total": len(texts), "sources": sources, "holdout": None}
        if len(texts) >= 200 and len(set(labels)) == 2:       # too little data -> metrics would be meaningless
            tr_x, te_x, tr_y, te_y = train_test_split(texts, labels, test_size=0.2, stratify=labels, random_state=42)
            vec, model = _fit(tr_x, tr_y)
            pred = model.predict(vec.transform(te_x))
            info["holdout"] = {
                "train_size": len(tr_x), "test_size": len(te_x),
                "accuracy": round(accuracy_score(te_y, pred), 3),
                "precision": round(precision_score(te_y, pred), 3),
                "recall": round(recall_score(te_y, pred), 3),
            }
        vec, model = _fit(texts, labels)                       # final model uses all the data
        _cache = (vec, model, info)
    return _cache


def train_scam_classifier():          # kept so older imports still work
    vec, model, _ = get_model()
    return vec, model


if __name__ == "__main__":
    print(get_model()[2])