from flask import Flask, request, jsonify
import os
import hashlib

from models import db, IncidentRun, ActionLogEntry, ReceiptEntry, ApprovalEntry
from ids import new_opaque_id, new_trace_id
from digest import canonical_json, redact
import planner
import otlp as otlp_builder

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///incidents.db")
db.init_app(app)

with app.app_context():
    db.create_all()

SUPPORTED_PROFILE = "ga5-incident-agent/v2"


def error(msg, code):
    return jsonify({"error": msg}), code


@app.route("/v2/incidents", methods=["POST"])
def create_incident():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return error("invalid json body", 400)

    # --- Validate top-level shape ---
    if body.get("profile") != SUPPORTED_PROFILE:
        return error("unsupported profile", 422)

    run_id = body.get("runId")
    if not run_id or not isinstance(run_id, str) or len(run_id) < 8:
        return error("missing or invalid runId", 400)

    incident = body.get("incident")
    if not isinstance(incident, dict) or "transcript" not in incident or "allowedRootCauses" not in incident:
        return error("invalid incident object", 400)

    transcript = incident["transcript"]
    allowed_root_causes = incident["allowedRootCauses"]
    tool_catalog = body.get("toolCatalog", [])
    policy = body.get("policy", {})
    public_marker = body.get("publicMarker", "")
    # sensitive object must NEVER be forwarded to the model or stored in any exported field
    # (we simply never read body["sensitive"] beyond this point)

    content_hash = hashlib.sha256(
        canonical_json({
            "runId": run_id,
            "incident": incident,
            "toolCatalog": tool_catalog,
            "policy": policy,
        }).encode()
    ).hexdigest()

    # --- Idempotency / conflict check ---
    existing = IncidentRun.query.get(run_id)
    if existing:
        if existing.request_hash == content_hash:
            # identical replay -> return stored state, no recompute, no model call
            return jsonify(redact(build_incident_response(existing))), 200
        else:
            return error("runId exists with different content", 409)

    # --- New run: do the real (or stub) diagnosis ---
    incoming_tp = request.headers.get("traceparent")
    trace_id = new_trace_id()  # TODO: continue incoming_tp's trace_id if valid (Step 5)

    diagnosis = planner.diagnose(
        transcript=transcript,
        allowed_root_causes=allowed_root_causes,
        evidence_lines=transcript.splitlines(),
    )

    run = IncidentRun(
        run_id=run_id,
        status="waiting",
        request_hash=content_hash,
        trace_id=trace_id,
        public_marker=public_marker,
        diagnosis_root_cause=diagnosis["rootCause"],
        diagnosis_evidence=diagnosis["evidence"],
    )
    db.session.add(run)
    db.session.commit()

    # TODO Step 5: generate real diagnostic dispatches here instead of []
    return jsonify(redact(build_incident_response(run))), 200


def build_incident_response(run):
    resp = {
        "runId": run.run_id,
        "status": run.status,
        "diagnosis": {
            "rootCause": run.diagnosis_root_cause,
            "evidence": run.diagnosis_evidence,
        },
    }
    if run.status == "waiting":
        resp["dispatches"] = []   # TODO: populate from ActionLogEntry pending rows
        resp["approvals"] = []    # TODO: populate from ApprovalEntry pending rows
    else:
        resp["chosenEffect"] = run.chosen_effect
        resp["suppressed"] = run.suppressed or []
        resp["actionLog"] = []    # TODO Step 9
        resp["receiptLog"] = []   # TODO Step 9
        resp["otlp"] = otlp_builder.build_otlp(run, [], [])  # TODO Step 10
    return resp


@app.route("/v2/incidents/<run_id>", methods=
