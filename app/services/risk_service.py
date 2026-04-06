import json
from datetime import datetime, timedelta
from sqlalchemy import func
from ..extensions import db
from ..models import Customer, Message, MessagePrediction, Transaction, TransactionPrediction, CustomerRiskScore, Alert, KYCProfile, AuditLog, User, ROLE_ANALYST
from .ml_service import predict_message_probability, predict_transaction_probability, anomaly_score
from .rules_engine import message_rules, category_from_score, recommendation_for_category
from .audit_service import log_audit

def compute_customer_risk(customer: Customer) -> dict:
    messages = Message.query.filter_by(customer_id=customer.id).count()
    alerts = Alert.query.filter_by(customer_id=customer.id).count()
    suspicious = MessagePrediction.query.join(Message, Message.id == MessagePrediction.message_id).filter(Message.customer_id == customer.id, MessagePrediction.risk_score >= 50).count()
    txns = Transaction.query.filter_by(customer_id=customer.id).all()
    high_tx = sum(1 for t in txns if t.amount >= 50000 or t.geo_mismatch or t.beneficiary_risk >= 60 or t.scam_message_minutes <= 60)
    kyc = KYCProfile.query.filter_by(customer_id=customer.id).first()
    kyc_penalty = 0 if (kyc and kyc.kyc_complete) else 15
    score = 0
    score += min(20, customer.complaint_count * 4)
    score += min(15, customer.device_change_frequency * 3)
    score += min(15, customer.location_mismatch_count * 3)
    score += min(15, customer.vulnerability_indicator * 5)
    score += min(15, customer.message_frequency * 2)
    score += min(15, customer.transaction_velocity * 2)
    score += min(10, suspicious * 5)
    score += min(10, alerts * 4)
    score += min(10, high_tx * 5)
    score += kyc_penalty
    score = int(min(100, score))
    classification = "Risky" if score >= 50 else "Compliant"
    reasons = []
    if suspicious: reasons.append(f"{suspicious} suspicious message(s)")
    if alerts: reasons.append(f"{alerts} alert(s)")
    if high_tx: reasons.append(f"{high_tx} high-risk transaction(s)")
    if kyc_penalty: reasons.append("KYC incomplete")
    if customer.location_mismatch_count: reasons.append("Location mismatch patterns")
    if customer.device_change_frequency: reasons.append("Frequent device changes")
    row = CustomerRiskScore.query.filter_by(customer_id=customer.id).first()
    if not row:
        row = CustomerRiskScore(customer_id=customer.id, risk_score=score, risk_classification=classification, reason_summary="; ".join(reasons))
        db.session.add(row)
    else:
        row.risk_score = score
        row.risk_classification = classification
        row.reason_summary = "; ".join(reasons)
        row.updated_at = datetime.utcnow()
    db.session.commit()
    return {"risk_score": score, "classification": classification, "reasons": reasons}

def analyze_message(message_id: int):
    msg = Message.query.get_or_404(message_id)

    rule = message_rules(msg.sender_name, msg.sender_id, msg.body, msg.phone_or_email)
    ml_prob = predict_message_probability(msg.body)

    customer = Customer.query.get(msg.customer_id) if msg.customer_id else None

    if customer:
        risk_row = CustomerRiskScore.query.filter_by(customer_id=customer.id).first()
        if risk_row:
            customer_risk = risk_row.risk_score
        else:
            customer_risk = compute_customer_risk(customer)["risk_score"]
    else:
        customer_risk = 10

    link_risk = 20 if msg.url_count else 0
    urgency_boost = 10 if "urgent" in (msg.body or "").lower() else 0

    final = 0.40 * rule["rule_score"] + 0.35 * (ml_prob * 100) + 0.15 * customer_risk + 0.10 * link_risk + urgency_boost
    risk_score = int(min(100, round(final)))

    scam_probability = round(min(0.99, max(0.01, (risk_score / 100) * 0.95 + (ml_prob * 0.05))), 4)
    category = category_from_score(risk_score)
    recommendation = recommendation_for_category(category)

    pred = MessagePrediction(
        message_id=msg.id,
        scam_probability=scam_probability,
        risk_score=risk_score,
        risk_category=category,
        reasons_json=json.dumps(rule["reasons"][:10]),
        keywords_json=json.dumps(rule["keywords"][:10]),
        action_recommendation=recommendation,
        model_probability=ml_prob,
        rule_score=rule["rule_score"],
    )
    db.session.add(pred)

    # ✅ FIXED ALERT LOGIC
    if risk_score >= 50:
        existing_alert = Alert.query.filter_by(
            message_id=msg.id,
            status="Open"
        ).first()

        if not existing_alert:
            alert = Alert(
                alert_type="Fraud Message",
                severity="Critical" if risk_score >= 75 else "High",
                message_id=msg.id,
                customer_id=msg.customer_id,
                assigned_role=ROLE_ANALYST,
                status="Open",
                last_action="Pending review",
            )
            db.session.add(alert)

    db.session.commit()

    log_audit("message", msg.id, "analyzed",
              reason_code=category,
              details={"risk_score": risk_score})

    return pred

def analyze_transaction(transaction_id: int):
    tx = Transaction.query.get_or_404(transaction_id)

    features = {
        "amount": tx.amount,
        "beneficiary_risk": tx.beneficiary_risk,
        "hour_of_day": tx.hour_of_day,
        "geo_mismatch": tx.geo_mismatch,
        "scam_message_minutes": tx.scam_message_minutes,
        "repeated_small_txn": tx.repeated_small_txn,
        "international_flag": tx.international_flag,
        "cash_withdrawal": tx.cash_withdrawal,
    }

    ml_prob = predict_transaction_probability(features)
    anom = anomaly_score(features)

    customer = Customer.query.get(tx.customer_id) if tx.customer_id else None
    customer_risk = compute_customer_risk(customer)["risk_score"] if customer else 10

    rule_score = 0
    reasons = []

    if tx.amount >= 50000:
        rule_score += 20; reasons.append("High-value transfer")
    if tx.geo_mismatch:
        rule_score += 20; reasons.append("Geo mismatch")
    if tx.beneficiary_risk >= 60:
        rule_score += 20; reasons.append("High-risk beneficiary")
    if tx.scam_message_minutes <= 60:
        rule_score += 25; reasons.append("Transaction near scam message")
    if tx.repeated_small_txn:
        rule_score += 10; reasons.append("Repeated small transactions")
    if tx.international_flag:
        rule_score += 10; reasons.append("International transfer pattern")
    if tx.cash_withdrawal:
        rule_score += 10; reasons.append("Cash withdrawal after suspicious event")

    final = 0.35 * rule_score + 0.30 * (ml_prob * 100) + 0.20 * (anom * 100) + 0.15 * customer_risk
    risk_score = int(min(100, round(final)))

    category = category_from_score(risk_score)

    row = TransactionPrediction(
        transaction_id=tx.id,
        fraud_probability=max(ml_prob, anom),
        risk_score=risk_score,
        risk_category=category,
        reasons_json=json.dumps(reasons),
        anomaly_score=anom,
        model_probability=ml_prob,
    )
    db.session.add(row)

    # ✅ FIXED ALERT LOGIC
    if risk_score >= 60:
        existing_alert = Alert.query.filter_by(
            transaction_id=tx.id,
            status="Open"
        ).first()

        if not existing_alert:
            alert = Alert(
                alert_type="Fraud Transaction",
                severity="Critical" if risk_score >= 80 else "High",
                transaction_id=tx.id,
                customer_id=tx.customer_id,
                assigned_role=ROLE_ANALYST,
                status="Open",
                last_action="Pending review",
            )
            db.session.add(alert)

    db.session.commit()

    log_audit("transaction", tx.id, "analyzed",
              reason_code=category,
              details={"risk_score": risk_score})

    return row

def dashboard_metrics():
    total_messages = Message.query.count()
    suspicious = MessagePrediction.query.filter(MessagePrediction.risk_score >= 50).count()
    critical = MessagePrediction.query.filter(MessagePrediction.risk_score >= 75).count()
    alerts_open = Alert.query.filter_by(status="Open").count()
    alerts_closed = Alert.query.filter_by(status="Closed").count()
    affected_customers = db.session.query(func.count(func.distinct(Alert.customer_id))).filter(Alert.customer_id.isnot(None)).scalar() or 0
    return {
        "total_messages": total_messages,
        "suspicious": suspicious,
        "critical": critical,
        "alerts_open": alerts_open,
        "alerts_closed": alerts_closed,
        "affected_customers": affected_customers,
    }

def top_customers(limit=10, risky=True):
    qs = CustomerRiskScore.query.order_by(CustomerRiskScore.risk_score.desc() if risky else CustomerRiskScore.risk_score.asc()).limit(limit).all()
    return qs
