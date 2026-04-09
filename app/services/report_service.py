from pathlib import Path
import csv
import logging
from datetime import datetime, time

from ..models import MessagePrediction, CustomerRiskScore, AuditLog, Alert

logger = logging.getLogger(__name__)


def _parse_date(value, end=False):
    if not value:
        return None
    try:
        d = datetime.strptime(value, "%Y-%m-%d").date()
        return datetime.combine(d, time.max if end else time.min)
    except ValueError:
        return None


def _apply_created_at_filter(query, model, from_date=None, to_date=None):
    if hasattr(model, "created_at"):
        start = _parse_date(from_date, end=False)
        end = _parse_date(to_date, end=True)
        if start is not None:
            query = query.filter(model.created_at >= start)
        if end is not None:
            query = query.filter(model.created_at <= end)
    return query


def _stringify_rows(rows):
    clean_rows = []
    for row in rows:
        clean_rows.append([str(cell) if cell is not None else "" for cell in row])
    return clean_rows


def _build_rows(report_type, from_date=None, to_date=None, risk_level=None):
    report_type = (report_type or "messages").lower()
    risk_level = (risk_level or "").strip().lower()

    if report_type == "messages":
        query = MessagePrediction.query
        query = _apply_created_at_filter(query, MessagePrediction, from_date, to_date)
        if risk_level and risk_level != "all":
            query = query.filter(MessagePrediction.risk_category.ilike(risk_level))
        rows = query.order_by(MessagePrediction.risk_score.desc()).all()
        headers = ["message_id", "scam_probability", "risk_score", "risk_category", "action_recommendation"]
        data = [
            [r.message_id, r.scam_probability, r.risk_score, r.risk_category, r.action_recommendation]
            for r in rows
        ]
        return headers, _stringify_rows(data)

    if report_type == "customers":
        query = CustomerRiskScore.query
        query = _apply_created_at_filter(query, CustomerRiskScore, from_date, to_date)
        if risk_level and risk_level != "all":
            query = query.filter(CustomerRiskScore.risk_classification.ilike(risk_level))
        rows = query.order_by(CustomerRiskScore.risk_score.desc()).all()
        headers = ["customer_id", "risk_score", "risk_classification", "reason_summary"]
        data = [
            [r.customer_id, r.risk_score, r.risk_classification, r.reason_summary]
            for r in rows
        ]
        return headers, _stringify_rows(data)

    if report_type == "alerts":
        query = Alert.query
        query = _apply_created_at_filter(query, Alert, from_date, to_date)
        if risk_level and risk_level != "all":
            query = query.filter(Alert.severity.ilike(risk_level))
        rows = query.order_by(Alert.created_at.desc()).all()
        headers = ["id", "alert_type", "severity", "status", "customer_id", "message_id", "transaction_id"]
        data = [
            [r.id, r.alert_type, r.severity, r.status, r.customer_id, r.message_id, r.transaction_id]
            for r in rows
        ]
        return headers, _stringify_rows(data)

    if report_type == "audit":
        query = AuditLog.query
        query = _apply_created_at_filter(query, AuditLog, from_date, to_date)
        rows = query.order_by(AuditLog.created_at.desc()).all()
        
        # 1. Update Headers to match your UI screenshot
        headers = ["Time", "User", "Entity", "Action", "Reason", "Details"]
        
        # 2. Map the data including the missing 'details' field
        data = [
            [
                r.created_at.strftime("%d-%b %H:%M"), # Formatted Time
                r.user_id,                            # User ID (or join with User.username)
                f"{r.entity_type} #{r.entity_id}",    # Combined Entity info
                r.action,
                r.reason_code,                        # Mapping to 'Reason'
                r.details                             # 👈 THE MISSING DETAILS COLUMN
            ]
            for r in rows
        ]
        return headers, _stringify_rows(data)

    return ["message"], [["No data found"]]


def generate_reports(base_dir=None, report_type="messages", from_date=None, to_date=None, risk_level=None):
    base_dir = Path(base_dir or ".").resolve()
    out_dir = base_dir / "exports"
    out_dir.mkdir(parents=True, exist_ok=True)

    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    report_type = (report_type or "messages").lower()

    report_dir = out_dir / f"{report_type}_{stamp}"
    report_dir.mkdir(parents=True, exist_ok=True)

    headers, rows = _build_rows(
        report_type,
        from_date=from_date,
        to_date=to_date,
        risk_level=risk_level,
    )

    files = {}

    # CSV
    csv_path = report_dir / f"{report_type}_{stamp}.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)
    files["csv"] = str(csv_path)

    # Excel
    try:
        from openpyxl import Workbook

        xlsx_path = report_dir / f"{report_type}_{stamp}.xlsx"
        wb = Workbook()
        ws = wb.active
        ws.title = report_type[:31]
        ws.append(headers)
        for row in rows:
            ws.append(row)
        wb.save(xlsx_path)
        files["xlsx"] = str(xlsx_path)
    except Exception as exc:
        logger.exception("Excel report generation failed: %s", exc)

    # PDF
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle

        pdf_path = report_dir / f"{report_type}_{stamp}.pdf"
        doc = SimpleDocTemplate(str(pdf_path), pagesize=A4)

        table_data = [headers] + rows
        if len(rows) == 0:
            table_data = [headers, ["No data found"] + [""] * (len(headers) - 1)]

        table = Table(table_data, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        doc.build([table])
        files["pdf"] = str(pdf_path)
    except Exception as exc:
        logger.exception("PDF report generation failed: %s", exc)

    files["folder"] = str(report_dir)
    return files