from flask import Blueprint, current_app, jsonify, request
from flask_login import login_required
from ..services.report_service import generate_reports

reports_bp = Blueprint("reports", __name__)

@reports_bp.route("/reports/generate", methods=["POST"])
@login_required
def generate():
    files = generate_reports(current_app.root_path.rsplit("/", 1)[0])
    return jsonify({"status": "ok", "files": files})
