from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class IncidentRun(db.Model):
    __tablename__ = "incident_run"
    run_id = db.Column(db.String, primary_key=True)
    status = db.Column(db.String, default="waiting")
    request_hash = db.Column(db.String)
    trace_id = db.Column(db.String)
    public_marker = db.Column(db.String)
    diagnosis_root_cause = db.Column(db.String)
    diagnosis_evidence = db.Column(db.JSON)
    chosen_effect = db.Column(db.String, nullable=True)
    suppressed = db.Column(db.JSON, default=list)
    approval_required_for = db.Column(db.JSON, default=list)
    chosen_effect_tool = db.Column(db.String, nullable=True)
    chosen_effect_arguments = db.Column(db.JSON, nullable=True)
    effect_dispatched = db.Column(db.Boolean, default=False)
    model_used = db.Column(db.String, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ActionLogEntry(db.Model):
    __tablename__ = "action_log_entry"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    run_id = db.Column(db.String, db.ForeignKey("incident_run.run_id"))
    action_id = db.Column(db.String)
    call_id = db.Column(db.String)
    phase = db.Column(db.String)  # diagnostic | effect
    tool_name = db.Column(db.String)
    arguments = db.Column(db.JSON)
    evidence = db.Column(db.JSON)
    attempt = db.Column(db.Integer, default=1)
    trace_id = db.Column(db.String)
    span_id = db.Column(db.String)
    status = db.Column(db.String, default="pending")  # pending|succeeded|failed|retried
    result_class = db.Column(db.String, nullable=True)
    approval_id = db.Column(db.String, nullable=True)
    approval_nonce = db.Column(db.String, nullable=True)
    observed_status = db.Column(db.Integer, nullable=True)   # 200 / 503 / 0(timeout) etc
    error_type = db.Column(db.String, nullable=True)         # "503" | "timeout" | None
    receipt_id = db.Column(db.String, nullable=True)         # which receipt delivered this outcome
    receipt_nonce = db.Column(db.String, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ReceiptEntry(db.Model):
    __tablename__ = "receipt_entry"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    run_id = db.Column(db.String)
    receipt_id = db.Column(db.String, unique=True)
    body_hash = db.Column(db.String)
    body_snapshot = db.Column(db.JSON)
    response_snapshot = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ApprovalEntry(db.Model):
    __tablename__ = "approval_entry"
    approval_id = db.Column(db.String, primary_key=True)
    run_id = db.Column(db.String)
    action_id = db.Column(db.String)
    tool_name = db.Column(db.String)
    arguments = db.Column(db.JSON)
    arguments_digest = db.Column(db.String)
    status = db.Column(db.String, default="pending")  # pending|approved
    approval_nonce = db.Column(db.String, nullable=True)
