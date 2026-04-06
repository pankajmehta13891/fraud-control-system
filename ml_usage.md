# ML Training Pipeline — FraudShield

This module trains and saves all machine learning models used by the FraudShield fraud control system. It covers three models: a scam message text classifier, a transaction fraud classifier, and an unsupervised transaction anomaly detector.

---

## File

```
app/ml/train_models.py
```

---

## What It Does

Running this script trains three models end-to-end and saves them as `.joblib` files under the `models/` directory:

| Model file | Purpose |
|---|---|
| `message_vectorizer.joblib` | TF-IDF vectorizer fitted on scam/safe message text |
| `message_model.joblib` | Logistic Regression scam message classifier |
| `transaction_model.joblib` | Random Forest supervised fraud classifier |
| `transaction_isolation.joblib` | Isolation Forest unsupervised anomaly detector |

---

## Models

### 1. Scam Message Classifier

Detects whether an incoming SMS, email, or WhatsApp-style message is a fraud attempt.

**Data:** Synthetic labelled corpus of scam messages (OTP fraud, fake KYC, fake refund, UPI phishing, impersonation) and safe bank messages. Augmented with 50 additional samples via random variation of scam keywords.

**Pipeline:**
```
Raw text
  → TfidfVectorizer (unigrams + bigrams, min_df=1, English stopwords)
  → LogisticRegression (max_iter=1000, class_weight="balanced")
  → Scam probability + binary label (1 = scam, 0 = safe)
```

**Class imbalance:** Handled via `class_weight="balanced"` in the classifier — no manual SMOTE needed at this corpus size.

**Saved artifacts:**
- `message_vectorizer.joblib` — must be loaded alongside the model to transform new text
- `message_model.joblib` — the fitted classifier

---

### 2. Transaction Fraud Classifier

Detects whether a financial transaction is fraudulent based on structured features.

**Data:** 1,200 synthetic transactions generated with realistic distributions. Fraud label is derived from a risk scoring rule (3+ risk flags, or high amount + high beneficiary risk).

**Features:**

| Feature | Description |
|---|---|
| `amount` | Transaction amount (log-normal distribution, clipped 100–500,000) |
| `beneficiary_risk` | Risk score of the receiving party (0–100) |
| `hour_of_day` | Hour transaction was made (0–23) |
| `geo_mismatch` | 1 if transaction location differs from usual (15% base rate) |
| `scam_message_minutes` | Minutes since last suspicious message received by customer |
| `repeated_small_txn` | 1 if part of a repeated small transaction pattern |
| `international_flag` | 1 if international transfer |
| `cash_withdrawal` | 1 if cash withdrawal |

**Pipeline:**
```
Structured feature matrix
  → RandomForestClassifier (250 trees, class_weight="balanced")
  → Fraud label (1 = fraud, 0 = legitimate)
```

**Saved artifact:** `transaction_model.joblib`

---

### 3. Transaction Anomaly Detector (Isolation Forest)

Detects statistically unusual transaction behaviour without needing fraud labels — useful for catching novel fraud patterns not covered by the supervised model.

**Pipeline:**
```
Same structured feature matrix (training split only)
  → IsolationForest (200 estimators, contamination=0.12)
  → Anomaly score (-1 = anomaly, 1 = normal)
```

`contamination=0.12` tells the model to expect roughly 12% of transactions to be anomalous, consistent with the fraud rate in the synthetic data.

**Saved artifact:** `transaction_isolation.joblib`

---

## Output — Evaluation Metrics

After training, the script prints classification reports and confusion matrices to stdout for both supervised models.

Example output format:
```
Message classifier
              precision    recall  f1-score   support
           0     0.9231    0.9231    0.9231        13
           1     0.9286    0.9286    0.9286        14
    accuracy                         0.9259        27

[[12  1]
 [ 1 13]]

Transaction classifier
              precision    recall  f1-score   support
           0     0.9512    0.9756    0.9633       164
           1     0.9400    0.8846    0.9114        78
    accuracy                         0.9458       242
```

---

## How to Run

### Prerequisites

```bash
pip install scikit-learn numpy pandas joblib
```

### Train all models

```bash
python app/ml/train_models.py
```

This will:
1. Generate synthetic training data in memory
2. Train all three models
3. Print evaluation metrics to the terminal
4. Save four `.joblib` files to `models/`

### Verify saved models

```bash
ls models/
# message_vectorizer.joblib
# message_model.joblib
# transaction_model.joblib
# transaction_isolation.joblib
```

---

## Loading Models for Inference

```python
from joblib import load
from pathlib import Path

MODEL_DIR = Path("models")

# Scam message prediction
vectorizer = load(MODEL_DIR / "message_vectorizer.joblib")
msg_model  = load(MODEL_DIR / "message_model.joblib")

text = "Urgent: your account will be blocked. Share OTP now."
prob = msg_model.predict_proba(vectorizer.transform([text]))[0][1]
print(f"Scam probability: {prob:.2%}")

# Transaction fraud prediction
tx_model = load(MODEL_DIR / "transaction_model.joblib")
iso_model = load(MODEL_DIR / "transaction_isolation.joblib")

import pandas as pd
txn = pd.DataFrame([{
    "amount": 95000,
    "beneficiary_risk": 75,
    "hour_of_day": 2,
    "geo_mismatch": 1,
    "scam_message_minutes": 10,
    "repeated_small_txn": 0,
    "international_flag": 0,
    "cash_withdrawal": 1
}])

fraud_pred  = tx_model.predict(txn)[0]
fraud_prob  = tx_model.predict_proba(txn)[0][1]
anomaly     = iso_model.predict(txn)[0]   # -1 = anomaly, 1 = normal

print(f"Fraud prediction : {fraud_pred} ({fraud_prob:.2%})")
print(f"Anomaly score    : {'anomaly' if anomaly == -1 else 'normal'}")
```

---

## Retraining with Real Data

The current `make_message_data()` and `make_tx_data()` functions generate synthetic data for demo purposes. To retrain on real data:

1. Replace `make_message_data()` with a loader that reads from your labelled message database.
2. Replace `make_tx_data()` with a query from your transactions table, ensuring columns match the feature list exactly.
3. For production use, add SMOTE oversampling if the fraud class is below 10% of samples:

```python
from imblearn.over_sampling import SMOTE
sm = SMOTE(random_state=42)
X_train_res, y_train_res = sm.fit_resample(X_train, y_train)
```

4. Re-run the training script and redeploy the updated `.joblib` files.

---

## Notes

- Models are saved to `models/` relative to the project root, resolved via `Path(__file__).resolve().parents[1]`. The directory is created automatically if it does not exist.
- The vectorizer and classifier for messages **must always be saved and loaded together** — the vectorizer's vocabulary is fitted on training data and is required to transform new inputs correctly.
- The `contamination` parameter in Isolation Forest should be updated to reflect the actual fraud rate in your production data.
- All models are serialized with `joblib` for efficient loading of large numpy arrays. Do not use `pickle` as a substitute.
