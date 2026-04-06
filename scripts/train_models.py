from pathlib import Path
import random
import numpy as np
import pandas as pd
from joblib import dump
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.pipeline import make_pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.base import BaseEstimator, TransformerMixin

ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / "models"
MODEL_DIR.mkdir(exist_ok=True)

def make_message_data():
    scam = [
        "Urgent: your account will be blocked. Verify OTP now and click http://bit.ly/verify to avoid suspension.",
        "KYC update required immediately. Share OTP, PIN and CVV to continue service.",
        "You won a lottery prize. Confirm bank details and pay a small processing fee.",
        "Refund ready. Call customer care now and tell OTP to receive cashback.",
        "Your UPI payment failed. Login and verify password now at www.bank-verify.click.",
        "Final warning: account freeze. Send OTP and password immediately.",
        "Claim reward voucher now. Tap the link and upload card photo.",
        "Immediate action required. Share passcode and click shortened link for refund.",
        "Payment reversal available. Call helpline and share CVV to confirm.",
        "KYC team needs your OTP to prevent deactivation.",
    ]
    safe = [
        "Your salary has been credited to account ending 5555.",
        "Your monthly statement is ready in the mobile app.",
        "Reminder: your card bill is due on 10th of this month.",
        "Branch appointment confirmed for KYC update.",
        "Transaction alert: INR 1,200 paid at merchant store.",
        "Your account balance is above minimum threshold.",
        "Bank notice: revised interest rates effective next month.",
        "Security alert: login from a new device was blocked by app settings.",
        "Thank you for using our services.",
        "Statement downloaded successfully from internet banking.",
    ]
    texts = scam + safe
    y = [1]*len(scam) + [0]*len(safe)
    # augment
    for _ in range(50):
        t = random.choice(scam) if random.random() < 0.55 else random.choice(safe)
        if random.random() < 0.5:
            t = t.replace("OTP", random.choice(["OTP", "passcode", "verification code"]))
        texts.append(t)
        y.append(1 if t in scam else 0)
    return pd.DataFrame({"text": texts, "label": y})

def make_tx_data(n=1200):
    rows = []
    for _ in range(n):
        amount = np.clip(np.random.lognormal(mean=8.0, sigma=1.0), 100, 500000)
        beneficiary_risk = np.random.randint(0, 100)
        hour = np.random.randint(0, 24)
        geo = np.random.binomial(1, 0.15)
        scam_min = np.random.choice([5, 10, 15, 30, 45, 60, 9999], p=[.08,.08,.10,.15,.10,.09,.40])
        repeat = np.random.binomial(1, 0.15)
        intl = np.random.binomial(1, 0.1)
        cash = np.random.binomial(1, 0.12)
        score = 0
        score += 1 if amount > 50000 else 0
        score += 1 if beneficiary_risk > 60 else 0
        score += 1 if geo else 0
        score += 1 if scam_min <= 60 else 0
        score += 1 if repeat else 0
        score += 1 if intl else 0
        score += 1 if cash else 0
        label = 1 if score >= 3 or (amount > 120000 and beneficiary_risk > 40) else 0
        rows.append([amount, beneficiary_risk, hour, geo, scam_min, repeat, intl, cash, label])
    return pd.DataFrame(rows, columns=["amount","beneficiary_risk","hour_of_day","geo_mismatch","scam_message_minutes","repeated_small_txn","international_flag","cash_withdrawal","label"])

def train_message():
    df = make_message_data()
    X_train, X_test, y_train, y_test = train_test_split(df["text"], df["label"], test_size=0.2, random_state=42, stratify=df["label"])
    vect = TfidfVectorizer(ngram_range=(1,2), min_df=1, stop_words="english")
    Xtr = vect.fit_transform(X_train)
    model = LogisticRegression(max_iter=1000, class_weight="balanced")
    model.fit(Xtr, y_train)
    pred = model.predict(vect.transform(X_test))
    print("Message classifier")
    print(classification_report(y_test, pred, digits=4))
    print(confusion_matrix(y_test, pred))
    dump(vect, MODEL_DIR / "message_vectorizer.joblib")
    dump(model, MODEL_DIR / "message_model.joblib")

def train_transaction():
    df = make_tx_data()
    y = df.pop("label")
    X_train, X_test, y_train, y_test = train_test_split(df, y, test_size=0.2, random_state=42, stratify=y)
    tx_model = RandomForestClassifier(n_estimators=250, random_state=42, class_weight="balanced")
    tx_model.fit(X_train, y_train)
    pred = tx_model.predict(X_test)
    print("Transaction classifier")
    print(classification_report(y_test, pred, digits=4))
    print(confusion_matrix(y_test, pred))
    dump(tx_model, MODEL_DIR / "transaction_model.joblib")
    iso = IsolationForest(n_estimators=200, contamination=0.12, random_state=42)
    iso.fit(X_train)
    dump(iso, MODEL_DIR / "transaction_isolation.joblib")

if __name__ == "__main__":
    train_message()
    train_transaction()
    print("Models saved to", MODEL_DIR)
