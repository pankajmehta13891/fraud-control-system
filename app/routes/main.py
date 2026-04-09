import json
import csv
import io
import os
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, Response, send_file
from flask_login import login_required, current_user

from ..extensions import db
from ..models import (
    Message, MessagePrediction, Transaction, TransactionPrediction, Customer, Alert, CustomerRiskScore,
    ActionLog, AuditLog, CaseNote, RuleConfiguration, ROLE_BANKER, ROLE_ANALYST, ROLE_COMPLIANCE, ROLE_ADMIN
)
from ..services.risk_service import (
    analyze_message, analyze_transaction, dashboard_metrics, compute_customer_risk, top_customers
)
from ..services.audit_service import log_audit, log_action
from ..services.report_service import generate_reports
from ..utils.security import mask_account
from ..services.rules_engine import message_rules, category_from_score, recommendation_for_category

main_bp = Blueprint("main", __name__)


@main_bp.app_context_processor
def inject_stats():
    stats = {
        "total": MessagePrediction.query.count(),
        "fraud": MessagePrediction.query.filter(MessagePrediction.risk_score >= 50).count(),
        "legit": MessagePrediction.query.filter(MessagePrediction.risk_score < 50).count(),
    }
    return dict(stats=stats)


def role_allowed(*roles):
    return current_user.is_authenticated and current_user.role in roles


def require_roles(*roles):
    def decorator(fn):
        from functools import wraps

        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not role_allowed(*roles):
                flash("You do not have permission to perform this action.", "danger")
                return redirect(url_for("main.dashboard"))
            return fn(*args, **kwargs)

        return wrapper

    return decorator


from flask import render_template, request
from ..models import Alert, CustomerRiskScore, MessagePrediction
# ... other imports

@main_bp.route("/")
@login_required
def dashboard():
    # 1. Get the current page for the Priority Queue
    page = request.args.get('page', 1, type=int)
    
    metrics = dashboard_metrics()
    
    #The Logic Fix ---
    # Create a threshold to only show alerts from the last 24 hours.
    # This ignores thousands of old "simulated" alerts and shrinks your page count.

    time_threshold = datetime.utcnow() - timedelta(hours=24)

    # 2. 🔥 Replace .limit(8).all() with .paginate()
    # We filter for 'OPEN' status so the queue only shows active threats
    pagination = Alert.query.filter(
        Alert.status.ilike('OPEN'),
        Alert.created_at >= time_threshold  # 🔥 This reduces the total pages
    ).order_by(Alert.created_at.desc())\
     .paginate(page=page, per_page=10, error_out=False) # 🔥 Standardized to 10
    
    recent_alerts = pagination.items
    
    # Summaries (these don't need pagination as they are top-5 snapshots)
    risky = CustomerRiskScore.query.order_by(CustomerRiskScore.risk_score.desc()).limit(5).all()
    compliant = CustomerRiskScore.query.order_by(CustomerRiskScore.risk_score.asc()).limit(5).all()
    
    # 📈 Dynamic Trend Metrics
    msg_trend = [
        {"label": "Safe", "value": MessagePrediction.query.filter(MessagePrediction.risk_score < 25).count()},
        {"label": "Suspicious", "value": MessagePrediction.query.filter(MessagePrediction.risk_score.between(25, 49)).count()},
        {"label": "High Risk", "value": MessagePrediction.query.filter(MessagePrediction.risk_score.between(50, 74)).count()},
        {"label": "Critical", "value": MessagePrediction.query.filter(MessagePrediction.risk_score >= 75).count()},
    ]
    
    return render_template(
        "dashboard.html",
        metrics=metrics,
        recent_alerts=recent_alerts, # Current page items
        pagination=pagination,       # 👈 Needed for the UI macro
        risky=risky,
        compliant=compliant,
        msg_trend=msg_trend,
        role=current_user.role
    )


@main_bp.route("/message-verify", methods=["GET", "POST"])
@login_required
def message_verify():
    result = None
    page = request.args.get('page', 1, type=int)

    # --- Step 1: Handle Manual Entry (POST) ---
    if request.method == "POST":
        customer_id = request.form.get("customer_id") or None
        body = request.form.get("body") or ""
        
        msg = Message(
            customer_id=customer_id,
            sender_name=request.form.get("sender_name"),
            sender_id=request.form.get("sender_id"),
            phone_or_email=request.form.get("phone_or_email"),
            channel=request.form.get("channel", "SMS"),
            body=body,
            url_count=body.count("http") + body.count("www."),
            short_link_count=body.lower().count("bit.ly")
        )
        db.session.add(msg)
        db.session.commit()

        result = analyze_message(msg.id)
        flash("Message analysed successfully.", "success")

    # --- Step 2: Generic Pagination with Join ---
    # We join Message and MessagePrediction so we only pull 10 pairs at a time
    pagination = db.session.query(Message, MessagePrediction)\
        .outerjoin(MessagePrediction, Message.id == MessagePrediction.message_id)\
        .order_by(Message.created_at.desc())\
        .paginate(page=page, per_page=10, error_out=False)

    # Convert pagination items into a dictionary for your template's current structure
    # This prevents the "preds.get(m.id)" logic from breaking
    current_messages = [item[0] for item in pagination.items]
    current_preds = {item[0].id: item[1] for item in pagination.items if item[1]}

    customers = Customer.query.order_by(Customer.full_name.asc()).all()

    return render_template(
        "message_verify.html",
        customers=customers,
        messages=current_messages, # Only 10 messages
        preds=current_preds,       # Only 10 predictions
        pagination=pagination,     # Pass the pagination object
        result=result
    )


from flask import render_template, request
from sqlalchemy import or_

@main_bp.route("/transactions")
@login_required
def transaction_monitor():
    # --- Step 1: Get Params ---
    page = request.args.get('page', 1, type=int)
    search = request.args.get("search", "").strip()
    risk_filter = request.args.get("risk", "").strip()
    min_amount = request.args.get("min_amount", "").strip()

    # --- Step 2: Build Joined Query ---
    # We join Transaction with its Prediction so we can filter by Risk Category in SQL
    query = db.session.query(Transaction, TransactionPrediction).outerjoin(
        TransactionPrediction, Transaction.id == TransactionPrediction.transaction_id
    )

    # Apply Search Filter
    if search:
        query = query.filter(Transaction.txn_ref.ilike(f"%{search}%"))

    # Apply Amount Filter
    if min_amount:
        try:
            query = query.filter(Transaction.amount >= float(min_amount))
        except ValueError:
            pass

    # Apply Risk Filter (Now happening in the Database!)
    if risk_filter and risk_filter != "All Risk":
        query = query.filter(TransactionPrediction.risk_category == risk_filter)

    # --- Step 3: Execute Pagination ---
    pagination = query.order_by(Transaction.created_at.desc()).paginate(
        page=page, per_page=10, error_out=False
    )

    # Convert results into a dictionary for your existing template logic
    # pagination.items is a list of tuples: [(Transaction, TransactionPrediction), ...]
    current_txns = [item[0] for item in pagination.items]
    current_preds = {item[0].id: item[1] for item in pagination.items if item[1]}

    # --- Step 4: Quick Stats (Efficient) ---
    high_risk_count = TransactionPrediction.query.filter(
        TransactionPrediction.risk_category.in_(["High", "Critical"])
    ).count()

    return render_template(
        "transaction_monitor.html",
        txns=current_txns,
        preds=current_preds,
        pagination=pagination,
        high_risk_count=high_risk_count,
        search=search,
        risk=risk_filter,
        min_amount=min_amount
    )


@main_bp.route("/transaction/<int:txn_id>")
@login_required
def transaction_view(txn_id):
    txn = Transaction.query.get_or_404(txn_id)
    pred = TransactionPrediction.query.filter_by(transaction_id=txn.id).first()
    return render_template("transaction_view.html", txn=txn, pred=pred)


@main_bp.route("/create_alert_from_transaction/<int:transaction_id>", methods=["POST"])
@login_required
def create_alert_from_transaction(transaction_id):
    txn = Transaction.query.get_or_404(transaction_id)

    alert = Alert(
        customer_id=txn.customer_id,
        transaction_id=txn.id,
        alert_type="Transaction Risk",
        severity="High",
        status="Open"
    )

    db.session.add(alert)
    db.session.commit()
    flash("Alert created from transaction.", "success")
    return redirect(request.referrer or url_for("main.alerts_queue"))


@main_bp.route("/customer/<int:customer_id>")
@login_required
def customer_profile(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    risk = compute_customer_risk(customer)
    messages = Message.query.filter_by(customer_id=customer.id).order_by(Message.created_at.desc()).all()
    txns = Transaction.query.filter_by(customer_id=customer.id).order_by(Transaction.created_at.desc()).all()
    alerts = Alert.query.filter_by(customer_id=customer.id).order_by(Alert.created_at.desc()).all()
    return render_template(
        "customer_profile.html",
        customer=customer,
        risk=risk,
        messages=messages,
        txns=txns,
        alerts=alerts,
        mask_account=mask_account
    )



@main_bp.route("/alerts")
@login_required
def alerts_queue():
    status = request.args.get('status', 'Open')
    page = request.args.get('page', 1, type=int)
    
    # 1. Fetch Paginated Alerts
    pagination = Alert.query.filter_by(status=status)\
                            .order_by(Alert.created_at.desc())\
                            .paginate(page=page, per_page=10, error_out=False)
    
    alerts = pagination.items

    # 2. Build Dictionaries for the current 10 items (Optimizes lookup)
    # This prevents the template from querying the DB inside the loop
    customers = {c.id: c for c in Customer.query.filter(Customer.id.in_([a.customer_id for a in alerts])).all()}
    
    msg_ids = [a.message_id for a in alerts if a.message_id]
    msg_preds = {mp.message_id: mp for mp in MessagePrediction.query.filter(MessagePrediction.message_id.in_(msg_ids)).all()}
    
    tx_ids = [a.transaction_id for a in alerts if a.transaction_id]
    tx_preds = {tp.transaction_id: tp for tp in TransactionPrediction.query.filter(TransactionPrediction.transaction_id.in_(tx_ids)).all()}

    return render_template("alerts.html", 
                           alerts=alerts, 
                           pagination=pagination, 
                           customers=customers,
                           msg_preds=msg_preds,
                           tx_preds=tx_preds,
                           current_status=status)


@main_bp.route("/top-risky")
@login_required
def top_risky():
    items = CustomerRiskScore.query.order_by(CustomerRiskScore.risk_score.desc()).all()
    return render_template("top_users.html", items=items, title="Top Risky Users", mode="risky")


@main_bp.route("/top-compliant")
@login_required
def top_compliant():
    items = CustomerRiskScore.query.order_by(CustomerRiskScore.risk_score.asc()).all()
    return render_template("top_users.html", items=items, title="Top Compliant Users", mode="compliant")


from flask import render_template, request, flash
from ..models import AuditLog, User, ROLE_COMPLIANCE, ROLE_ADMIN
from ..extensions import db

@main_bp.route("/audit/logs")
@login_required
def audit_logs():
    # 🔒 Access Control
    if current_user.role not in [ROLE_COMPLIANCE, ROLE_ADMIN]:
        flash("Audit log access is restricted.", "warning")
        return render_template("access_denied.html")
    
    # 📝 Get Pagination and Filter Params
    page = request.args.get('page', 1, type=int)
    user_id = request.args.get("user")
    action_param = request.args.get("action")
    from_date = request.args.get("from_date")
    to_date = request.args.get("to_date")

    # 🔗 Step 1: Join AuditLog with User (Fetches username + log data together)
    query = db.session.query(AuditLog, User).join(User, AuditLog.user_id == User.id)

    # 🔍 Step 2: Apply Database Filters
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)

    if action_param:
        action_map = {
            "FREEZE": "account_frozen",
            "ESCALATE": "escalated",
            "SAFE": "marked_safe",
            "FRAUD": "fraud_confirmed"
        }
        # Get mapped value or use the raw param
        db_action = action_map.get(action_param, action_param)
        query = query.filter(AuditLog.action == db_action)

    if from_date:
        query = query.filter(AuditLog.created_at >= from_date)
    if to_date:
        query = query.filter(AuditLog.created_at <= to_date)

    # 📏 Step 3: Generic Pagination (15 logs per page)
    pagination = query.order_by(AuditLog.created_at.desc()).paginate(
        page=page, per_page=15, error_out=False
    )

    # Fetch all users for the filter dropdown
    all_users = User.query.order_by(User.username.asc()).all()

    return render_template(
        "audit_logs.html", 
        pagination=pagination,
        users=all_users,
        current_user_filter=user_id,
        current_action=action_param,
        from_date=from_date,
        to_date=to_date
    )


@main_bp.route("/admin/settings", methods=["GET", "POST"])
@login_required
def admin_settings():
    if current_user.role != ROLE_ADMIN:
        flash("Admin access required.", "danger")
        return redirect(url_for("main.dashboard"))
    rules = RuleConfiguration.query.all()
    if request.method == "POST":
        for rule in rules:
            value = request.form.get(rule.rule_name)
            if value is not None:
                rule.rule_value = value
        db.session.commit()
        log_audit("config", 1, "rule_update", reason_code="ADMIN", details="Rule configuration updated")
        flash("Rules updated.", "success")
    return render_template("admin_settings.html", rules=rules)


@main_bp.route("/reports")
@login_required
def reports_page():
    if current_user.role not in [ROLE_COMPLIANCE, ROLE_ADMIN]:
        flash("Report generation is typically used by Compliance and Admin.", "info")
    return render_template("reports.html")


def _action_alert(alert_id, action_name, reason_code, notes=None):
    alert = Alert.query.get_or_404(alert_id)
    alert.last_action = action_name
    if action_name in ["Marked Safe", "Resolved"]:
        alert.status = "Closed"
    elif action_name in ["Escalated"]:
        alert.status = "Escalated"
    db.session.commit()
    log_action(alert_id=alert.id, customer_id=alert.customer_id, action=action_name, reason_code=reason_code, notes=notes)
    log_audit("alert", alert.id, action_name.lower().replace(" ", "_"), reason_code=reason_code, details={"notes": notes})
    return alert


@main_bp.route("/call_customer/<int:alert_id>", methods=["POST"])
@login_required
@require_roles(ROLE_BANKER, ROLE_ANALYST, ROLE_COMPLIANCE, ROLE_ADMIN)
def call_customer(alert_id):
    _action_alert(alert_id, "Called Customer", "CALL")
    flash("Call logged as simulated telephony action.", "info")
    return redirect(request.referrer or url_for("main.alerts_queue"))


@main_bp.route("/send_alert_sms/<int:alert_id>", methods=["POST"])
@login_required
@require_roles(ROLE_BANKER, ROLE_ANALYST, ROLE_COMPLIANCE, ROLE_ADMIN)
def send_alert_sms(alert_id):
    _action_alert(alert_id, "Alert SMS Sent", "SMS")
    flash("Alert SMS simulated and logged.", "info")
    return redirect(request.referrer or url_for("main.alerts_queue"))


@main_bp.route("/freeze_account/<int:alert_id>", methods=["POST"])
@login_required
@require_roles(ROLE_BANKER, ROLE_ANALYST, ROLE_COMPLIANCE, ROLE_ADMIN)
def freeze_account(alert_id):
    alert = _action_alert(alert_id, "Account Frozen", "FREEZE")
    customer = Customer.query.get(alert.customer_id)
    if customer:
        customer.account_status = "Frozen"
        db.session.commit()
    flash("Account frozen.", "warning")
    return redirect(request.referrer or url_for("main.alerts_queue"))


@main_bp.route("/kyc/request_update/<int:alert_id>", methods=["POST"])
@login_required
@require_roles(ROLE_BANKER, ROLE_ANALYST, ROLE_COMPLIANCE, ROLE_ADMIN)
def request_kyc(alert_id):
    _action_alert(alert_id, "KYC Update Requested", "KYC")
    flash("KYC update requested.", "warning")
    return redirect(request.referrer or url_for("main.alerts_queue"))


@main_bp.route("/escalate/<int:alert_id>", methods=["POST"])
@login_required
@require_roles(ROLE_BANKER, ROLE_ANALYST, ROLE_COMPLIANCE, ROLE_ADMIN)
def escalate(alert_id):
    _action_alert(alert_id, "Escalated", "ESCALATE")
    flash("Alert escalated to compliance.", "warning")
    return redirect(request.referrer or url_for("main.alerts_queue"))


@main_bp.route("/mark_safe/<int:alert_id>", methods=["POST"])
@login_required
@require_roles(ROLE_BANKER, ROLE_ANALYST, ROLE_COMPLIANCE, ROLE_ADMIN)
def mark_safe(alert_id):
    _action_alert(alert_id, "Marked Safe", "SAFE")
    flash("Alert marked safe.", "success")
    return redirect(request.referrer or url_for("main.alerts_queue"))


@main_bp.route("/mark_fraud/<int:alert_id>", methods=["POST"])
@login_required
@require_roles(ROLE_BANKER, ROLE_ANALYST, ROLE_COMPLIANCE, ROLE_ADMIN)
def mark_fraud(alert_id):
    _action_alert(alert_id, "Fraud Confirmed", "FRAUD")
    flash("Fraud confirmed and logged.", "danger")
    return redirect(request.referrer or url_for("main.alerts_queue"))


@main_bp.route("/case_note/<int:alert_id>", methods=["POST"])
@login_required
@require_roles(ROLE_BANKER, ROLE_ANALYST, ROLE_COMPLIANCE, ROLE_ADMIN)
def case_note(alert_id):
    note = request.form.get("note")
    if note:
        db.session.add(CaseNote(alert_id=alert_id, user_id=current_user.id, note=note))
        db.session.commit()
        log_audit("case_note", alert_id, "added", reason_code="NOTE", details={"note": note[:100]})
    flash("Case note added.", "success")
    return redirect(request.referrer or url_for("main.alerts_queue"))


@main_bp.route("/predict/message", methods=["POST"])
@login_required
def predict_message_route():
    data = request.get_json(silent=True) or request.form.to_dict()
    body = data.get("body", "")
    sender_name = data.get("sender_name", "")
    sender_id = data.get("sender_id", "")
    phone_or_email = data.get("phone_or_email", "")
    customer_id = data.get("customer_id")

    msg = Message(
        customer_id=customer_id,
        sender_name=sender_name,
        sender_id=sender_id,
        phone_or_email=phone_or_email,
        body=body,
        channel=data.get("channel", "SMS"),
        url_count=body.count("http") + body.count("www."),
        short_link_count=body.lower().count("bit.ly")
    )
    db.session.add(msg)
    db.session.commit()

    pred = analyze_message(msg.id)
    return jsonify({
        "message_id": msg.id,
        "scam_probability": pred.scam_probability,
        "risk_score": pred.risk_score,
        "risk_category": pred.risk_category,
        "reasons": json.loads(pred.reasons_json),
        "keywords": json.loads(pred.keywords_json),
        "action_recommendation": pred.action_recommendation,
    })


@main_bp.route("/predict/transaction", methods=["POST"])
@login_required
def predict_transaction_route():
    data = request.get_json(silent=True) or request.form.to_dict()
    tx = Transaction(
        customer_id=data.get("customer_id"),
        txn_ref=data.get("txn_ref", f"TXN{Transaction.query.count() + 1000}"),
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
    return jsonify({
        "transaction_id": tx.id,
        "fraud_probability": pred.fraud_probability,
        "risk_score": pred.risk_score,
        "risk_category": pred.risk_category,
        "reasons": json.loads(pred.reasons_json),
    })


@main_bp.route("/api/customer/<int:customer_id>")
@login_required
def customer_json(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    risk = compute_customer_risk(customer)
    return jsonify({
        "id": customer.id,
        "name": customer.full_name,
        "risk": risk,
        "account_status": customer.account_status,
        "kyc_status": customer.kyc_status,
    })


@main_bp.route("/api/alerts")
@login_required
def alerts_json():
    time_threshold = datetime.utcnow() - timedelta(hours=24)

    alerts = (
        Alert.query.filter(
            Alert.status.ilike("OPEN"),
            Alert.created_at >= time_threshold
        )
        .order_by(Alert.created_at.desc())
        .limit(10)
        .all()
    )

    return jsonify([
        {
            "id": a.id,
            "alert_type": a.alert_type,
            "severity": a.severity,
            "status": a.status,
            "customer_id": a.customer_id,
            "message_id": a.message_id,
            "transaction_id": a.transaction_id,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in alerts
    ])

@main_bp.route("/create_alert_from_message", methods=["POST"])
@login_required
def create_alert_from_message():
    message_id = request.form.get("message_id")
    msg = Message.query.get_or_404(message_id)

    alert = Alert(
        customer_id=msg.customer_id,
        message_id=msg.id,
        alert_type="Message Risk",
        severity="High",
        status="Open",
    )

    db.session.add(alert)
    db.session.commit()
    flash("🚨 Alert created from message.", "success")
    return redirect(url_for("main.message_verify"))


@main_bp.route("/mark_message_safe", methods=["POST"])
@login_required
def mark_message_safe():
    message_id = request.form.get("message_id")
    msg = Message.query.get_or_404(message_id)

    alert = Alert.query.filter_by(message_id=msg.id).first()
    if alert:
        alert.status = "Closed"
        alert.last_action = "Marked Safe"
        db.session.commit()

    flash("✅ Message marked as safe.", "success")
    return redirect(url_for("main.message_verify"))


@main_bp.route("/export_logs")
@login_required
def export_logs():
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Action", "Entity", "Created At"])

    for log in logs:
        writer.writerow([log.id, log.action, log.entity_type, log.created_at])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_logs.csv"},
    )


@main_bp.route("/export_reports", methods=["POST"])
@login_required
def export_reports():
    report_type = request.form.get("report_type", "messages")
    export_format = request.form.get("export_format", "csv").lower()
    from_date = request.form.get("from_date")
    to_date = request.form.get("to_date")
    risk_level = request.form.get("risk_level")

    files = generate_reports(
        base_dir=os.getcwd(),
        report_type=report_type,
        from_date=from_date,
        to_date=to_date,
        risk_level=risk_level,
    )

    fmt_map = {"csv": "csv", "excel": "xlsx", "xlsx": "xlsx", "pdf": "pdf"}
    chosen = fmt_map.get(export_format, "csv")
    file_path = files.get(chosen) or files.get("csv")

    if not file_path or not os.path.exists(file_path):
        flash("Report could not be generated.", "danger")
        return redirect(url_for("main.reports_page"))

    return send_file(file_path, as_attachment=True, download_name=os.path.basename(file_path))

@main_bp.route("/customer/<int:customer_id>/call", methods=["POST"])
@login_required
def call_customer_profile(customer_id):
    log_action(None, customer_id, "Called Customer", "CALL")
    flash("Customer contacted.", "info")

    return redirect(url_for("main.customer_profile", customer_id=customer_id))





@main_bp.route("/customer/<int:customer_id>/freeze", methods=["POST"])
@login_required
def freeze_account_profile(customer_id):
    customer = Customer.query.get_or_404(customer_id)

    customer.account_status = "Frozen"
    db.session.commit()

    log_action(None, customer.id, "Account Frozen", "FREEZE")
    flash("Account frozen.", "danger")

    return redirect(url_for("main.customer_profile", customer_id=customer_id))




@main_bp.route("/customer/<int:customer_id>/request_kyc", methods=["POST"])
@login_required
def request_kyc_profile(customer_id):
    customer = Customer.query.get_or_404(customer_id)

    customer.kyc_status = "Pending Review"
    db.session.commit()

    log_action(None, customer.id, "KYC Requested", "KYC")
    flash("KYC requested.", "warning")

    return redirect(url_for("main.customer_profile", customer_id=customer_id))