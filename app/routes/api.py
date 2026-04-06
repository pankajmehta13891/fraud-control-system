from pathlib import Path
from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required
from ..extensions import db
from ..models import Message, Transaction, Customer, Alert
from ..services.risk_service import analyze_message, analyze_transaction, compute_customer_risk
from ..services.report_service import generate_reports
from ..services.audit_service import log_action

api_bp = Blueprint("api", __name__)

@api_bp.route("/api/predict/message", methods=["POST"])
@login_required
def api_predict_message():
    data = request.get_json(silent=True) or request.form.to_dict()
    body = data.get("body", "") or ""
    
    msg = Message(
        customer_id=data.get("customer_id") or None,
        sender_name=data.get("sender_name"),
        sender_id=data.get("sender_id"),
        phone_or_email=data.get("phone_or_email"),
        channel=data.get("channel", "SMS"),
        body=body,
        url_count=body.count("http") + body.count("www."),
        short_link_count=body.lower().count("bit.ly"),
    )
    db.session.add(msg)
    db.session.commit()
    
    pred = analyze_message(msg.id)

    # 🚨 INTEGRATED ALERT LOGIC: Create alert if risk is high
    if pred.risk_score >= 50:
        severity = "Critical" if pred.risk_score >= 75 else "High"
        alert = Alert(
            alert_type="SCAM_MESSAGE",
            severity=severity,
            status="OPEN",
            customer_id=msg.customer_id,
            message_id=msg.id
        )
        db.session.add(alert)
        db.session.commit()

    return jsonify({
        "message_id": msg.id,
        "scam_probability": pred.scam_probability,
        "risk_score": pred.risk_score,
        "risk_category": pred.risk_category,
    })

@api_bp.route("/api/predict/transaction", methods=["POST"])
@login_required
def api_predict_transaction():
    data = request.get_json(silent=True) or request.form.to_dict()

    tx = Transaction(
        customer_id=data.get("customer_id") or None,
        txn_ref=data.get("txn_ref") or f"TXN{Transaction.query.count()+1000}",
        txn_type=data.get("txn_type", "UPI"),
        amount=float(data.get("amount", 0)),
        beneficiary=data.get("beneficiary", ""),
        beneficiary_risk=int(data.get("beneficiary_risk", 0)),
        hour_of_day=int(data.get("hour_of_day", 12)),
        geo_mismatch=int(data.get("geo_mismatch", 0)),
        scam_message_minutes=int(data.get("scam_message_minutes", 9999)),
        repeated_small_txn=int(data.get("repeated_small_txn", 0)),
        international_flag=int(data.get("international_flag", 0)),
        cash_withdrawal=int(data.get("cash_withdrawal", 0)),
    )
    db.session.add(tx)
    db.session.commit()

    pred = analyze_transaction(tx.id)

    # 🚨 ALERT LOGIC
    if pred.risk_score >= 50:
        severity = "Critical" if pred.risk_score >= 70 else "High"
        alert = Alert(
            alert_type="TRANSACTION",
            severity=severity,
            status="OPEN",
            customer_id=tx.customer_id,
            transaction_id=tx.id
        )
        db.session.add(alert)
        db.session.commit()

    return jsonify({
        "transaction_id": tx.id,
        "fraud_probability": pred.fraud_probability,
        "risk_score": pred.risk_score,
        "risk_category": pred.risk_category,
    })

@api_bp.route("/api/action", methods=["POST"])
@login_required
def api_action():
    data = request.get_json()
    alert_id = data.get("alert_id")
    action_type = data.get("action")

    alert = Alert.query.get_or_404(alert_id)
    customer = Customer.query.get(alert.customer_id)

    if action_type == "FREEZE" and customer:
        customer.account_status = "Frozen"
        alert.status = "Closed"
        log_action(alert.id, customer.id, "Account Frozen via Dashboard", "FREEZE")
    
    elif action_type == "CALL" and customer:
        alert.status = "In Progress"
        log_action(alert.id, customer.id, "Customer Call Initiated", "CALL")
        
    elif action_type == "ESCALATE":
        alert.severity = "Critical"
        alert.status = "Escalated"
        log_action(alert.id, alert.customer_id, "Alert Escalated", "ESCALATE")

    db.session.commit()
    return jsonify({"status": "success", "new_alert_status": alert.status})

@api_bp.route("/api/alerts")
@login_required
def api_alerts():
    alerts = Alert.query.order_by(Alert.created_at.desc()).all()
    return jsonify([{
        "id": a.id,
        "alert_type": a.alert_type,
        "severity": a.severity,
        "status": a.status,
        "customer_id": a.customer_id,
        "message_id": a.message_id,
        "transaction_id": a.transaction_id,
        "created_at": a.created_at.isoformat(),
    } for a in alerts])

@api_bp.route("/api/reports/generate", methods=["POST"])
@login_required
def api_reports():
    # Path is now correctly imported
    files = generate_reports(str(Path(current_app.root_path).parent))
    return jsonify({"generated": files})