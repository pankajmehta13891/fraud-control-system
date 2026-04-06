import json
from datetime import datetime
from flask_login import current_user
from ..extensions import db
from ..models import AuditLog, ActionLog

def log_audit(entity_type, entity_id, action, reason_code=None, details=None, user_id=None):
    uid = user_id or (current_user.id if getattr(current_user, "is_authenticated", False) else None)
    if uid is None:
        return None
    row = AuditLog(
        user_id=uid,
        entity_type=entity_type,
        entity_id=entity_id,
        action=action,
        reason_code=reason_code,
        details=json.dumps(details or {}, default=str),
        created_at=datetime.utcnow(),
    )
    db.session.add(row)
    db.session.commit()
    return row

def log_action(alert_id, customer_id, action, reason_code=None, notes=None, user_id=None):
    uid = user_id or (current_user.id if getattr(current_user, "is_authenticated", False) else None)
    if uid is None:
        return None
    row = ActionLog(
        alert_id=alert_id,
        customer_id=customer_id,
        user_id=uid,
        action=action,
        reason_code=reason_code,
        notes=notes,
        created_at=datetime.utcnow(),
    )
    db.session.add(row)
    db.session.commit()
    return row
