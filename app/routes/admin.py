from flask import Blueprint, render_template, request, abort
from flask_login import login_required, current_user
from ..extensions import db
from ..models import (
    User, Customer, KYCProfile, Message, MessagePrediction,
    Transaction, TransactionPrediction, Alert, CustomerRiskScore,
    ActionLog, AuditLog, CaseNote, RuleConfiguration,
    ROLE_ADMIN
)

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

MODEL_MAP = {
    "user": User,
    "customer": Customer,
    "kyc_profile": KYCProfile,
    "message": Message,
    "message_prediction": MessagePrediction,
    "transaction": Transaction,
    "transaction_prediction": TransactionPrediction,
    "alert": Alert,
    "customer_risk_score": CustomerRiskScore,
    "action_log": ActionLog,
    "audit_log": AuditLog,
    "case_note": CaseNote,
    "rule_configuration": RuleConfiguration,
}

@admin_bp.route("/tables")
@login_required
def list_tables():
    if current_user.role != ROLE_ADMIN:
        abort(403)

    tables = [
        {"name": key, "label": value.__name__}
        for key, value in MODEL_MAP.items()
    ]
    return render_template("admin_tables.html", tables=tables)

@admin_bp.route("/table/<table_name>")
@login_required
def view_table(table_name):
    if current_user.role != ROLE_ADMIN:
        abort(403)

    model = MODEL_MAP.get(table_name)
    if not model:
        abort(404)

    page = request.args.get("page", 1, type=int)
    per_page = 20

    query = model.query

    if hasattr(model, "id"):
        query = query.order_by(model.id.desc())

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    columns = [c.name for c in model.__table__.columns]
    rows = pagination.items

    return render_template(
        "admin_table_view.html",
        table_name=table_name,
        columns=columns,
        rows=rows,
        pagination=pagination
    )