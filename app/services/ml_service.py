import json
from pathlib import Path
from joblib import load
from config import Config

MODEL_DIR = Path(Config.MODEL_DIR)

_message_model = None
_message_vectorizer = None
_tx_model = None
_iso_model = None

def _safe_load(path):
    return load(path) if path.exists() else None

def load_models():
    global _message_model, _message_vectorizer, _tx_model, _iso_model
    if _message_model is None:
        _message_model = _safe_load(MODEL_DIR / "message_model.joblib")
    if _message_vectorizer is None:
        _message_vectorizer = _safe_load(MODEL_DIR / "message_vectorizer.joblib")
    if _tx_model is None:
        _tx_model = _safe_load(MODEL_DIR / "transaction_model.joblib")
    if _iso_model is None:
        _iso_model = _safe_load(MODEL_DIR / "transaction_isolation.joblib")

def predict_message_probability(text: str) -> float:
    load_models()
    if _message_model is None or _message_vectorizer is None:
        return 0.5
    X = _message_vectorizer.transform([text or ""])
    prob = float(_message_model.predict_proba(X)[0][1])
    return prob

def predict_transaction_probability(features: dict) -> float:
    load_models()
    if _tx_model is None:
        return 0.5
    import pandas as pd
    X = pd.DataFrame([features])
    prob = float(_tx_model.predict_proba(X)[0][1])
    return prob

def anomaly_score(features: dict) -> float:
    load_models()
    if _iso_model is None:
        return 0.0
    import pandas as pd
    X = pd.DataFrame([features])
    # decision_function: higher is more normal; convert to anomaly score 0..1
    score = float(_iso_model.decision_function(X)[0])
    anomaly = max(0.0, min(1.0, 1.0 - ((score + 0.5) / 1.0)))
    return anomaly

def top_message_tokens(text: str, n=5):
    load_models()
    if _message_model is None or _message_vectorizer is None:
        return []
    try:
        X = _message_vectorizer.transform([text or ""])
        vocab = _message_vectorizer.get_feature_names_out()
        coefs = _message_model.coef_[0]
        active = X.toarray()[0] > 0
        scores = [(vocab[i], coefs[i]) for i in range(len(vocab)) if active[i]]
        scores.sort(key=lambda x: x[1], reverse=True)
        return [w for w, _ in scores[:n]]
    except Exception:
        return []
