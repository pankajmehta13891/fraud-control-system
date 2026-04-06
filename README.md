
# 🛡️ FraudShield — Banking Fraud Control System

> An enterprise-grade, AI-powered fraud control system for banks — combining real-time scam message detection, customer risk intelligence, transaction anomaly monitoring, AML pattern analysis, and end-to-end compliance audit trails.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-3.x-black?logo=flask)
![SQLite](https://img.shields.io/badge/Database-SQLite%2FPostgreSQL-lightgrey?logo=sqlite)
![ML](https://img.shields.io/badge/ML-scikit--learn%20%7C%20XGBoost-orange?logo=scikit-learn)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Demo--Ready-brightgreen)

---

## 📌 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [Architecture](#-architecture)
- [Project Structure](#-project-structure)
- [Modules](#-modules)
- [Machine Learning Pipeline](#-machine-learning-pipeline)
- [Database Schema](#-database-schema)
- [API Reference](#-api-reference)
- [Roles & Permissions](#-roles--permissions)
- [Getting Started](#-getting-started)
- [Seeding Demo Data](#-seeding-demo-data)
- [Deployment on Render](#-deployment-on-render)
- [Testing](#-testing)
- [Future Enhancements](#-future-enhancements)

---

## 🔍 Overview

**FraudShield** is a fully-featured, internal fraud control system built for banking operations teams. It allows bankers, fraud analysts, and compliance officers to detect, investigate, and act on fraudulent activity — from suspicious customer messages to anomalous transactions — all within a single secure portal.

The system combines:
- **Rule-based engines** for deterministic fraud signal detection
- **NLP/ML classifiers** trained on scam message patterns
- **Anomaly detection models** for transaction-level fraud
- **AML pattern recognition** for money laundering signals
- **Operational workflows** for calling, freezing, escalating, and resolving cases
- **Immutable audit logs** for regulatory compliance

---

## ✨ Key Features

| Feature | Description |
|---|---|
| 📩 Message Verification | Analyze any SMS / email / WhatsApp-style message for fraud indicators |
| 🔢 Risk Scoring | Every message and customer gets a 0–100 risk score with full explanation |
| 👤 Customer Risk Profiles | KYC status, transaction anomalies, complaint history, device changes |
| 💸 Transaction Correlation | Link suspicious messages to UPI payments, withdrawals, and beneficiary changes |
| 🧩 AML Detection | Flag structuring, layering, rapid cash-in/cash-out, and unusual transfers |
| 🧑‍💼 Banker Operations | Call, freeze, alert, escalate, or resolve cases from a single dashboard |
| 🗂️ Audit Trail | Every action is timestamped, attributed, and reason-coded for compliance |
| 📊 Reports | Daily fraud reports, top-risk customer lists, case summaries — exportable to CSV |
| 🔐 Role-Based Access | Banker / Fraud Analyst / Compliance Officer / Admin with scoped permissions |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Flask Web Portal                      │
│  Login → Dashboard → Message Review → Customer → Audit Log  │
└───────────────────────────┬─────────────────────────────────┘
                            │
          ┌─────────────────┼──────────────────┐
          │                 │                  │
   ┌──────▼──────┐  ┌───────▼──────┐  ┌───────▼───────┐
   │  Rule-Based │  │  ML/NLP      │  │  Risk Scoring  │
   │  Detection  │  │  Classifier  │  │  Engine        │
   │  Engine     │  │  (TF-IDF +   │  │  (Composite    │
   │             │  │   LR/SVM)    │  │   Weighted)    │
   └──────┬──────┘  └───────┬──────┘  └───────┬───────┘
          │                 │                  │
          └─────────────────▼──────────────────┘
                            │
              ┌─────────────▼──────────────┐
              │        SQLite / PostgreSQL  │
              │  messages · transactions    │
              │  customers · alerts         │
              │  audit_logs · case_notes    │
              └────────────────────────────┘
```

---

## 📁 Project Structure

```
fraudshield/
│
├── app/
│   ├── __init__.py              # Flask app factory
│   ├── routes/
│   │   ├── auth.py              # Login / logout
│   │   ├── dashboard.py         # Main dashboard
│   │   ├── messages.py          # Message verification
│   │   ├── customers.py         # Customer profiles
│   │   ├── transactions.py      # Transaction monitoring
│   │   ├── alerts.py            # Alerts queue
│   │   ├── audit.py             # Audit logs
│   │   ├── reports.py           # Report generation
│   │   └── admin.py             # Admin settings
│   │
│   ├── models/
│   │   ├── user.py
│   │   ├── customer.py
│   │   ├── message.py
│   │   ├── transaction.py
│   │   ├── alert.py
│   │   └── audit_log.py
│   │
│   ├── services/
│   │   ├── fraud_detector.py    # Core fraud detection pipeline
│   │   ├── risk_scorer.py       # Composite risk scoring engine
│   │   ├── aml_engine.py        # AML pattern detection
│   │   ├── customer_risk.py     # Customer risk profile builder
│   │   ├── transaction_corr.py  # Transaction-message correlation
│   │   └── action_service.py    # Freeze / call / escalate logic
│   │
│   ├── rules/
│   │   ├── message_rules.py     # Rule-based signal checkers
│   │   ├── url_rules.py         # URL and domain risk rules
│   │   └── aml_rules.py         # AML pattern rules
│   │
│   ├── ml/
│   │   ├── train_message_clf.py # NLP scam classifier training
│   │   ├── train_txn_clf.py     # Transaction fraud model training
│   │   ├── train_anomaly.py     # Isolation Forest anomaly model
│   │   ├── predict.py           # Inference helpers
│   │   └── saved_models/        # Serialized .pkl model files
│   │
│   ├── templates/
│   │   ├── base.html
│   │   ├── login.html
│   │   ├── dashboard.html
│   │   ├── message_verify.html
│   │   ├── customer_profile.html
│   │   ├── transactions.html
│   │   ├── alerts.html
│   │   ├── audit_logs.html
│   │   ├── reports.html
│   │   └── admin.html
│   │
│   └── static/
│       ├── css/
│       ├── js/
│       └── img/
│
├── database/
│   ├── schema.sql               # Full DB schema
│   └── db.py                    # DB connection helpers
│
├── data/
│   ├── seed_data.py             # Demo data generator
│   ├── sample_messages.csv      # Labelled scam/safe messages
│   └── sample_transactions.csv  # Synthetic transaction records
│
├── tests/
│   ├── test_fraud_detector.py
│   ├── test_risk_scorer.py
│   ├── test_routes.py
│   └── test_ml_models.py
│
├── utils/
│   ├── masking.py               # PII masking helpers
│   ├── reason_codes.py          # Standardised reason code registry
│   └── export.py                # CSV / PDF export utilities
│
├── config.py                    # App configuration
├── requirements.txt
├── run.py                       # Entry point
├── .env.example
├── Procfile                     # For Render deployment
└── README.md
```

---

## 🧩 Modules

### 1. Fraud Message Verification
The core module. Accepts any raw message text and runs a three-layer analysis pipeline:

**Layer 1 — Rule-Based Checks**
- OTP / PIN / CVV / password requests
- Urgency language (`act now`, `account blocked`, `expires in 24 hours`)
- Suspicious or shortened URLs
- Fake bank / RBI / NPCI / UPI domain patterns
- Sender ID spoofing indicators
- Fake refund, reward, prize, lottery, or KYC language
- Suspicious callback numbers
- Grammatical anomaly indicators

**Layer 2 — NLP/ML Classifier**
- TF-IDF feature extraction on message body
- Logistic Regression / SVM trained on labelled scam vs safe corpus
- Outputs scam probability (0.0 – 1.0)

**Layer 3 — Composite Risk Score**
- Weighted combination of rule score + ML probability + sender reputation + URL risk + urgency score + customer profile risk
- Final score: **0–100**
- Category: `SAFE` / `SUSPICIOUS` / `HIGH RISK` / `CRITICAL`

---

### 2. Customer Risk Intelligence
Builds and maintains a live risk profile per customer:
- KYC completeness score
- Suspicious message count
- Fraud alert history
- Transaction velocity and anomalies
- Device and location change frequency
- Recent complaint history
- Vulnerability flags

Outputs: customer risk score, `COMPLIANT` / `RISKY` classification, top risky users list.

---

### 3. Fraud Transaction Correlation
Links suspicious messages to transaction events within a configurable time window:
- UPI payment after scam message received
- Beneficiary change after suspected phishing
- High-value transfer after OTP request message
- Repeated small transactions (structuring signal)
- Unusual card transactions post-message

---

### 4. AML / Suspicious Pattern Detection
Flags money laundering patterns:
- Structuring (multiple deposits just below reporting threshold)
- Layering across linked accounts
- Rapid cash-in / cash-out cycles
- Repeated or unusual international transfers
- Unexplained beneficiary changes

---

### 5. Banker Operations
From the alerts queue, bankers can take action on any affected customer:

| Action | Description |
|---|---|
| 📞 Call Customer | Simulated outbound call — action logged with timestamp |
| 📱 Send Alert SMS | Dispatches a fraud warning SMS to the customer |
| 🔒 Freeze Account | Marks account frozen; triggers compliance notification |
| 📋 Request KYC Update | Flags customer for re-verification |
| ⬆️ Escalate to Compliance | Moves case to compliance officer queue |
| ✅ Mark Safe | Closes alert as false positive with reason code |
| 🚨 Confirm Fraud | Confirms fraud; triggers reporting pipeline |

---

### 6. Audit & Compliance
Every action — review, call, freeze, escalate, resolve — is logged with:
- Banker/analyst username
- Timestamp
- Action type and reason code
- Customer and message reference
- Final decision

Audit logs are immutable and exportable for regulatory submissions.

---

## 🤖 Machine Learning Pipeline

### Scam Message Classifier
```
Input: Raw message text
  ↓
Preprocessing: lowercase, strip punctuation, remove stopwords
  ↓
Feature Extraction: TF-IDF (unigrams + bigrams, max 5000 features)
  ↓
Model: Logistic Regression / Naive Bayes / SVM
  ↓
Output: scam_probability (0.0–1.0)
```

**Class imbalance handling:** SMOTE oversampling on minority (scam) class.

**Evaluation metrics:** Precision, Recall, F1-Score, AUC-ROC, Confusion Matrix.

### Transaction Fraud Classifier
Features: amount, time of day, geo mismatch flag, beneficiary risk score, days since last transaction, recent scam message proximity score.

Model: Random Forest / XGBoost with SMOTE balancing.

### Anomaly Detection
Model: Isolation Forest on customer transaction behaviour vectors.

Flags statistically unusual activity even when no labelled fraud signal exists.

---

## 🗄️ Database Schema

```sql
users                -- portal login accounts with roles
customers            -- bank customers with KYC and risk fields
messages             -- submitted messages for analysis
message_predictions  -- ML + rule scores per message
transactions         -- customer transaction records
alerts               -- active fraud alerts
customer_risk_scores -- historical risk snapshots
kyc_profiles         -- KYC documents and status
action_logs          -- every banker action taken
audit_logs           -- immutable compliance audit trail
case_notes           -- internal investigation notes
rule_configurations  -- configurable detection rules
```

Full schema: [`database/schema.sql`](database/schema.sql)

---

## 🌐 API Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/login` | Authenticate banker / analyst |
| `POST` | `/predict/message` | Analyse a fraud message |
| `POST` | `/predict/transaction` | Score a transaction for fraud |
| `GET` | `/customer/<id>` | Fetch customer risk profile |
| `GET` | `/alerts` | List active fraud alerts |
| `POST` | `/call_customer` | Log a customer call action |
| `POST` | `/freeze_account` | Freeze a customer account |
| `POST` | `/send_alert_sms` | Send fraud warning to customer |
| `POST` | `/kyc/request_update` | Flag customer for KYC re-check |
| `GET` | `/audit/logs` | Retrieve audit log entries |
| `POST` | `/reports/generate` | Generate and export a report |

---

## 🔐 Roles & Permissions

| Feature | Banker | Fraud Analyst | Compliance Officer | Admin |
|---|:---:|:---:|:---:|:---:|
| View Dashboard | ✅ | ✅ | ✅ | ✅ |
| Verify Messages | ✅ | ✅ | — | ✅ |
| Call / Alert Customer | ✅ | ✅ | — | ✅ |
| Freeze Account | ✅ | ✅ | — | ✅ |
| Transaction Correlation | — | ✅ | — | ✅ |
| Escalate Cases | ✅ | ✅ | — | ✅ |
| View Audit Logs | — | — | ✅ | ✅ |
| Generate Reports | — | ✅ | ✅ | ✅ |
| Configure Rules | — | — | — | ✅ |
| User Management | — | — | — | ✅ |

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- pip
- (Optional) PostgreSQL if not using SQLite

### 1. Clone the repository
```bash
git clone https://github.com/your-org/fraudshield.git
cd fraudshield
```

### 2. Create a virtual environment
```bash
python -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure environment variables
```bash
cp .env.example .env
```

Edit `.env`:
```env
SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///fraudshield.db   # or postgresql://...
FLASK_ENV=development
```

### 5. Initialise the database
```bash
flask db init
flask db migrate
flask db upgrade
```

### 6. Train ML models
```bash
python app/ml/train_message_clf.py
python app/ml/train_txn_clf.py
python app/ml/train_anomaly.py
```

### 7. Run the application
```bash
python run.py
```

Visit: [http://localhost:5000](http://localhost:5000)

**Default demo login:**
```
Username : admin@fraudshield.bank
Password : Admin@1234
```

---

## 🌱 Seeding Demo Data

Populate the system with realistic synthetic data for demonstration:

```bash
python data/seed_data.py
```

This seeds:
- 5 banker / analyst / compliance / admin user accounts
- 50 synthetic customers with varying KYC and risk profiles
- 100 labelled fraud and safe messages (OTP scams, fake KYC, fake refunds, UPI fraud, phishing)
- 200 transaction records with some correlated to suspicious messages
- Active alerts with linked customers
- Sample audit log entries and case notes

### Sample Demo Scenarios Included

| Scenario | Risk Level | Description |
|---|---|---|
| OTP Scam | 🔴 Critical | `"Your SBI account will be blocked. Share OTP 4521 immediately."` |
| Fake Refund | 🔴 High Risk | `"NEFT refund of ₹9,800 pending. Click to claim: bit.ly/ref-claim"` |
| Fake KYC | 🟠 Suspicious | `"Complete your KYC via this link or account will close in 24 hrs."` |
| UPI Fraud | 🟠 High Risk | `"You received ₹500. Accept on GPay: upi-pay.fraudsite.com"` |
| Safe Message | 🟢 Safe | `"Your OTP is 839201. Valid for 5 minutes. Do not share."` (verified sender) |

---

## ☁️ Deployment on Render

### 1. Push to GitHub
```bash
git add .
git commit -m "Initial commit"
git push origin main
```

### 2. Create a new Web Service on [Render](https://render.com)
- **Build Command:** `pip install -r requirements.txt`
- **Start Command:** `gunicorn run:app`
- **Environment Variables:** Add `SECRET_KEY`, `DATABASE_URL`, `FLASK_ENV=production`

### 3. Add a PostgreSQL database on Render
Set `DATABASE_URL` to the Render PostgreSQL connection string.

### 4. Seed data after first deploy
Use the Render shell:
```bash
python data/seed_data.py
```

The `Procfile` is pre-configured:
```
web: gunicorn run:app
```

---

## 🧪 Testing

```bash
# Run all tests
pytest tests/

# Run with coverage report
pytest tests/ --cov=app --cov-report=term-missing

# Individual test suites
pytest tests/test_fraud_detector.py
pytest tests/test_risk_scorer.py
pytest tests/test_routes.py
pytest tests/test_ml_models.py
```

Key test areas:
- Rule-based detection accuracy on known scam patterns
- ML model precision/recall on held-out test set
- Risk score range and category boundary validation
- API endpoint responses and auth enforcement
- Audit log creation on every banker action

---

## 🔮 Future Enhancements

| Enhancement | Description |
|---|---|
| 📸 OCR Screenshot Detection | Upload a screenshot of a scam message for analysis |
| 💬 WhatsApp / Email Integration | Pull messages directly from live channels |
| 📞 Call Centre Integration | Real telephony via Twilio or Exotel |
| 🕸️ Fraud Ring Detection | Graph-based analysis to uncover linked fraud networks |
| ⚡ Real-Time Streaming | Kafka or Redis Streams for live message ingestion |
| 📋 Case Management Workflow | Full investigation lifecycle with SLA tracking |
| 🌐 Multilingual Detection | Hindi, Tamil, Bengali scam message pattern support |
| 📱 Mobile App | Field banker interface for on-the-go alerts |

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Commit your changes: `git commit -m "Add: your feature description"`
4. Push to the branch: `git push origin feature/your-feature-name`
5. Open a Pull Request

Please follow PEP 8 style guidelines and include tests for new features.

---

## 📄 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## 📬 Contact

For queries, demo requests, or integration support:

**Maintainer:** [@your-github-handle](https://github.com/your-github-handle)  
**Email:** your-email@domain.com

---

<p align="center">Built for banking security teams · Powered by Python, Flask & scikit-learn</p>
=======
# fraud-control-system
AI-powered banking fraud control system — real-time scam message detection, transaction anomaly monitoring, customer risk profiling, and compliance audit trails.
>>>>>>> d792dfc9d092fa279bd81ed227e3de6fcd3e81bc
