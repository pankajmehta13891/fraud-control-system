import json
from datetime import datetime, timedelta
from flask import current_app
from ..extensions import db
from ..models import User, Customer, KYCProfile, Message, MessagePrediction, Transaction, TransactionPrediction, Alert, CustomerRiskScore, AuditLog, RuleConfiguration, ROLE_BANKER, ROLE_ANALYST, ROLE_COMPLIANCE, ROLE_ADMIN
from ..utils.security import mask_phone, mask_email, mask_account
from .risk_service import analyze_message, analyze_transaction, compute_customer_risk
from .audit_service import log_audit

def _ensure_user(username, full_name, role, password):
    user = User.query.filter_by(username=username).first()
    if not user:
        user = User(username=username, full_name=full_name, role=role, active=True)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
    return user

def seed_database():
    # only seed if no users exist
    if User.query.count() > 0:
        return

    users = [
        ("banker", " Banker", ROLE_BANKER, "banker123"),
        ("analyst", "Fraud Analyst", ROLE_ANALYST, "analyst123"),
        ("compliance", "Compliance Officer", ROLE_COMPLIANCE, "compliance123"),
        ("admin", "Admin", ROLE_ADMIN, "admin123"),
    ]
    for u in users:
        _ensure_user(*u)

    c1 = Customer(customer_ref="CUST1001", full_name="Amit Sharma", phone_masked=mask_phone("9876543210"), email_masked=mask_email("amit@example.com"), account_masked=mask_account("1111222233334444"), account_status="Active", kyc_status="Incomplete", account_age_months=5, device_change_frequency=4, location_mismatch_count=2, complaint_count=3, vulnerability_indicator=2, transaction_velocity=7.2, message_frequency=8, linked_user_flag="Risky")
    c2 = Customer(customer_ref="CUST1002", full_name="Neha Verma", phone_masked=mask_phone("9812345678"), email_masked=mask_email("neha@example.com"), account_masked=mask_account("2222333344445555"), account_status="Active", kyc_status="Complete", account_age_months=24, device_change_frequency=0, location_mismatch_count=0, complaint_count=0, vulnerability_indicator=0, transaction_velocity=1.3, message_frequency=1, linked_user_flag="Compliant")
    c3 = Customer(customer_ref="CUST1003", full_name="Rahul Mehta", phone_masked=mask_phone("9898989898"), email_masked=mask_email("rahul@example.com"), account_masked=mask_account("3333444455556666"), account_status="Active", kyc_status="Incomplete", account_age_months=8, device_change_frequency=2, location_mismatch_count=1, complaint_count=1, vulnerability_indicator=1, transaction_velocity=4.6, message_frequency=4, linked_user_flag="Risky")
    c4 = Customer(customer_ref="CUST1004", full_name="Sara Khan", phone_masked=mask_phone("9000011111"), email_masked=mask_email("sara@example.com"), account_masked=mask_account("4444555566667777"), account_status="Active", kyc_status="Complete", account_age_months=36, device_change_frequency=0, location_mismatch_count=0, complaint_count=0, vulnerability_indicator=0, transaction_velocity=0.9, message_frequency=1, linked_user_flag="Compliant")
    db.session.add_all([c1, c2, c3, c4])
    db.session.commit()

    for c in Customer.query.all():
        db.session.add(KYCProfile(customer_id=c.id, kyc_complete=(c.kyc_status == "Complete"), kyc_score=80 if c.kyc_status == "Complete" else 40, last_update=datetime.utcnow() - timedelta(days=20)))
    db.session.commit()

    messages = [
        (c1.id, "SBI Bank", "SBI123", "sms@sbi-alerts.com", "SMS", "Urgent: Your account will be blocked. Verify OTP 482919 now and click http://bit.ly/verify-sbi to avoid suspension."),
        (c1.id, "Refund Team", "REF001", "refund@service.com", "WhatsApp", "You are eligible for cashback refund. Share OTP and account details to receive refund immediately."),
        (c2.id, "HDFC Bank", "HDFC01", "alerts@hdfcbank.com", "SMS", "Your salary of INR 52,000 has been credited to your account ending 5555."),
        (c3.id, "KYC Desk", "KYC88", "kyc-support@securemail.xyz", "Email", "Immediate KYC verification required. Click www.bank-verify.click and upload your card photo and CVV."),
        (c4.id, "UPI", "UPI099", "noreply@upi.in", "SMS", "Pay INR 4,999 to complete the transaction. Call customer care 1800-000-999 if you did not authorize this."),
        (c3.id, "Prize Desk", "PRZ77", "lottery@promo.top", "Email", "Congratulations! You won a reward voucher. Confirm your bank details to collect the prize."),
    ]
    msg_rows = []
    for cust_id, sname, sid, contact, channel, body in messages:
        m = Message(customer_id=cust_id, sender_name=sname, sender_id=sid, phone_or_email=contact, channel=channel, body=body, url_count=body.count("http") + body.count("www."), short_link_count=body.lower().count("bit.ly"))
        db.session.add(m)
        msg_rows.append(m)
    db.session.commit()
    for m in Message.query.all():
        analyze_message(m.id)
    db.session.commit()

    txns = [
        (c1.id, "TXN1001", "UPI", 4999, "Merchant A", 80, 21, 1, 15, 0, 0, 0),
        (c1.id, "TXN1002", "Cash Withdrawal", 20000, "ATM", 10, 18, 0, 30, 0, 0, 1),
        (c2.id, "TXN1003", "Card Purchase", 1500, "Store X", 5, 14, 0, 9999, 0, 0, 0),
        (c3.id, "TXN1004", "Beneficiary Transfer", 75000, "Unknown Beneficiary", 95, 2, 1, 12, 1, 1, 0),
        (c4.id, "TXN1005", "UPI", 999, "Merchant B", 10, 20, 0, 9999, 0, 0, 0),
        (c3.id, "TXN1006", "Cash Withdrawal", 30000, "ATM", 40, 23, 1, 45, 0, 0, 1),
    ]
    for row in txns:
        db.session.add(Transaction(
            customer_id=row[0], txn_ref=row[1], txn_type=row[2], amount=row[3], beneficiary=row[4], beneficiary_risk=row[5],
            hour_of_day=row[6], geo_mismatch=row[7], scam_message_minutes=row[8], repeated_small_txn=row[9],
            international_flag=row[10], cash_withdrawal=row[11]
        ))
    db.session.commit()
    for t in Transaction.query.all():
        analyze_transaction(t.id)
    db.session.commit()

    # compute customer scores
    for c in Customer.query.all():
        compute_customer_risk(c)

    # alerts from high risks
    for pred in MessagePrediction.query.filter(MessagePrediction.risk_score >= 50).all():
        m = Message.query.get(pred.message_id)
        if not Alert.query.filter_by(message_id=m.id).first():
            db.session.add(Alert(alert_type="Fraud Message", severity="Critical" if pred.risk_score >= 75 else "High", message_id=m.id, customer_id=m.customer_id, assigned_role=ROLE_ANALYST, status="Open", last_action="Seeded alert"))
    for pred in TransactionPrediction.query.filter(TransactionPrediction.risk_score >= 60).all():
        tx = Transaction.query.get(pred.transaction_id)
        if not Alert.query.filter_by(transaction_id=tx.id).first():
            db.session.add(Alert(alert_type="Fraud Transaction", severity="Critical" if pred.risk_score >= 80 else "High", transaction_id=tx.id, customer_id=tx.customer_id, assigned_role=ROLE_ANALYST, status="Open", last_action="Seeded alert"))
    db.session.commit()

    # rule config
    rules = [
        ("message_alert_threshold", "50"),
        ("critical_threshold", "75"),
        ("transaction_alert_threshold", "60"),
        ("auto_freeze_threshold", "80"),
        ("kyc_recheck_days", "90"),
    ]
    for n,v in rules:
        db.session.add(RuleConfiguration(rule_name=n, rule_value=v))
    db.session.commit()

    # audit log seed
    admin = User.query.filter_by(username="admin").first()
    db.session.add(AuditLog(user_id=admin.id, entity_type="system", entity_id=1, action="seed_completed", reason_code="INIT", details="Seed data loaded"))
    db.session.commit()
