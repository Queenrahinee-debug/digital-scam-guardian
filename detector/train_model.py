import json
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

def train_scam_classifier():
    # 1. Load our development messages dataset
    with open("data/dev_messages.json", "r") as f:
        data = json.load(f)
        
    texts = [item["message"] for item in data]
    # Convert labels: 'scam' or 'suspicious' to 1 (risky), 'safe' to 0
    labels = [1 if item["label"] in ["scam", "suspicious"] else 0 for item in data]
    
    # 2. Vectorize the text (convert words to numerical features)
    vectorizer = TfidfVectorizer(stop_words='english')
    X = vectorizer.fit_transform(texts)
    
    # 3. Train a simple Logistic Regression model
    model = LogisticRegression()
    model.fit(X, labels)
    
    print("ML Model trained successfully on development data!")
    return vectorizer, model

if __name__ == "__main__":
    train_scam_classifier()