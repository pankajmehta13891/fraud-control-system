from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from .extensions import db, login_manager

ROLE_BANKER = "Banker"
ROLE_ANALYST = "Fraud Analyst"
ROLE_COMPLIANCE = "Compliance Officer"
ROLE_ADMIN = "Admin"


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(40), nullable=False, default=ROLE_BANKER)
    password_hash = db.Column(db.String(255), nullable=False)
    active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_ref = db.Column(db.String(30), unique=True, nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    phone_masked = db.Column(db.String(20), nullable=False)
    email_masked = db.Column(db.String(120), nullable=True)
    account_masked = db.Column(db.String(30), nullable=False)
    account_status = db.Column(db.String(20), default="Active")
    kyc_status = db.Column(db.String(20), default="Pending")
    account_age_months = db.Column(db.Integer, default=12)
    device_change_frequency = db.Column(db.Integer, default=0)
    location_mismatch_count = db.Column(db.Integer, default=0)
    complaint_count = db.Column(db.Integer, default=0)
    vulnerability_indicator = db.Column(db.Integer, default=0)
    transaction_velocity = db.Column(db.Float, default=0.0)
    message_frequency = db.Column(db.Integer, default=0)
    linked_user_flag = db.Column(db.String(20), default="Compliant")


class KYCProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customer.id"), nullable=False)
    kyc_complete = db.Column(db.Boolean, default=False)
    kyc_score = db.Column(db.Integer, default=0)
    last_update = db.Column(db.DateTime, default=datetime.utcnow)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customer.id"), nullable=True)
    sender_name = db.Column(db.String(120), nullable=True)
    sender_id = db.Column(db.String(120), nullable=True)
    phone_or_email = db.Column(db.String(120), nullable=True)
    channel = db.Column(db.String(20), default="SMS")
    body = db.Column(db.Text, nullable=False)
    url_count = db.Column(db.Integer, default=0)
    short_link_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class MessagePrediction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey("message.id"), nullable=False)
    scam_probability = db.Column(db.Float, nullable=False)
    risk_score = db.Column(db.Integer, nullable=False)
    risk_category = db.Column(db.String(30), nullable=False)
    reasons_json = db.Column(db.Text, nullable=False)
    keywords_json = db.Column(db.Text, nullable=False)
    action_recommendation = db.Column(db.String(255), nullable=False)
    model_probability = db.Column(db.Float, default=0.0)
    rule_score = db.Column(db.Float, default=0.0)


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customer.id"), nullable=True)
    txn_ref = db.Column(db.String(30), unique=True, nullable=False)
    txn_type = db.Column(db.String(40), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    beneficiary = db.Column(db.String(120), nullable=True)
    beneficiary_risk = db.Column(db.Integer, default=0)
    hour_of_day = db.Column(db.Integer, default=12)
    geo_mismatch = db.Column(db.Integer, default=0)
    scam_message_minutes = db.Column(db.Integer, default=9999)
    repeated_small_txn = db.Column(db.Integer, default=0)
    international_flag = db.Column(db.Integer, default=0)
    cash_withdrawal = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class TransactionPrediction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.Integer, db.ForeignKey("transaction.id"), nullable=False)
    fraud_probability = db.Column(db.Float, nullable=False)
    risk_score = db.Column(db.Integer, nullable=False)
    risk_category = db.Column(db.String(30), nullable=False)
    reasons_json = db.Column(db.Text, nullable=False)
    anomaly_score = db.Column(db.Float, default=0.0)
    model_probability = db.Column(db.Float, default=0.0)


class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    alert_type = db.Column(db.String(40), nullable=False)
    severity = db.Column(db.String(20), default="Medium")
    message_id = db.Column(db.Integer, db.ForeignKey("message.id"), nullable=True)
    transaction_id = db.Column(db.Integer, db.ForeignKey("transaction.id"), nullable=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customer.id"), nullable=True)
    assigned_role = db.Column(db.String(40), default="Fraud Analyst")
    status = db.Column(db.String(20), default="Open")
    last_action = db.Column(db.String(120), default="Created")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class CustomerRiskScore(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customer.id"), nullable=False)
    risk_score = db.Column(db.Integer, nullable=False)
    risk_classification = db.Column(db.String(20), nullable=False)
    reason_summary = db.Column(db.Text, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)


class ActionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.Integer, db.ForeignKey("alert.id"), nullable=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customer.id"), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    action = db.Column(db.String(80), nullable=False)
    reason_code = db.Column(db.String(80), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    entity_type = db.Column(db.String(40), nullable=False)
    entity_id = db.Column(db.Integer, nullable=False)
    action = db.Column(db.String(80), nullable=False)
    reason_code = db.Column(db.String(80), nullable=True)
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class CaseNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.Integer, db.ForeignKey("alert.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    note = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class RuleConfiguration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rule_name = db.Column(db.String(80), unique=True, nullable=False)
    rule_value = db.Column(db.String(255), nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)


# ✅ FIXED USER LOADER (CRITICAL)
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))