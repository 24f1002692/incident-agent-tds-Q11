from flask import Flask, request, jsonify
import os
import hashlib

from models import db, IncidentRun, ActionLogEntry, ReceiptEntry, ApprovalEntry
from ids import new_opaque_id, new_trace_id, new_span_id, build_traceparent, parse_traceparent
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
        pending = ActionLogEntry.query.filter_by(run_id=run.run_id, status="pending").all()
        resp["dispatches"] = [
            {
                "actionId": e.action_id,
                "callId": e.call_id,
                "phase": e.phase,
                "toolName": e.tool_name,
                "arguments": e.arguments,
                "evidence": e.evidence,
                "attempt": e.attempt,
                "traceparent": build_traceparent(e.trace_id, e.span_id),
            }
            for e in pending
        ]
        resp["approvals"] = []  # TODO Step 8
    else:
        resp["chosenEffect"] = run.chosen_effect
        resp["suppressed"] = run.suppressed or []
        resp["actionLog"] = []   # TODO Step 9
        resp["receiptLog"] = []  # TODO Step 9
        resp["otlp"] = otlp_builder.build_otlp(run, [], [])  # TODO Step 10
    return resp


@app.route("/v2/incidents", methods=["POST"])
def create_incident():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return error("invalid json body", 400)

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
    # NOTE: body.get("sensitive") is intentionally never read beyond this point.

    content_hash = hashlib.sha256(
        canonical_json({
            "runId": run_id,
            "incident": incident,
            "toolCatalog": tool_catalog,
            "policy": policy,
        }).encode()
    ).hexdigest()

    existing = IncidentRun.query.get(run_id)
    if existing:
        if existing.request_hash == content_hash:
            return jsonify(redact(build_incident_response(existing))), 200
        else:
            return error("runId exists with different content", 409)

    incoming_tp = request.headers.get("traceparent")
    parsed_incoming = parse_traceparent(incoming_tp) if incoming_tp else None
    trace_id = parsed_incoming[0] if parsed_incoming else new_trace_id()

    # --- Single model call: diagnosis + diagnostic tool selection ---
    diagnosis_plan = planner.plan(
        transcript=transcript,
        allowed_root_causes=allowed_root_causes,
        tool_catalog=tool_catalog,
        max_diagnostics=policy.get("maximumDiagnostics", 3),
    )

    run = IncidentRun(
        run_id=run_id,
        status="waiting",
        request_hash=content_hash,
        trace_id=trace_id,
        public_marker=public_marker,
        diagnosis_root_cause=diagnosis_plan["rootCause"],
        diagnosis_evidence=diagnosis_plan["evidence"],
    )
    db.session.add(run)
    db.session.commit()

    # --- Generate real diagnostic dispatches from the plan ---
    for call in diagnosis_plan["diagnosticCalls"]:
        action_id = new_opaque_id()
        call_id = new_opaque_id()
        span_id = new_span_id()

        entry = ActionLogEntry(
            run_id=run_id,
            action_id=action_id,
            call_id=call_id,
            phase="diagnostic",
            tool_name=call["toolName"],
            arguments=call["arguments"],
            evidence=call["evidence"],
            attempt=1,
            trace_id=trace_id,
            span_id=span_id,
            status="pending",
        )
        db.session.add(entry)

    db.session.commit()

    return jsonify(redact(build_incident_response(run))), 200


@app.route("/v2/incidents/<run_id>", methods=["GET"])
def get_incident(run_id):
    run = IncidentRun.query.get(run_id)
    if not run:
        return error("not found", 404)
    return jsonify(redact(build_incident_response(run))), 200


@app.route("/v2/incidents/<run_id>/receipts", methods=["POST"])
def post_receipt(run_id):
    run = IncidentRun.query.get(run_id)
    if not run:
        return error("not found", 404)

    body = request.get_json(silent=True)
    if not isinstance(body, dict) or "receiptId" not in body:
        return error("invalid receipt", 400)

    receipt_id = body["receiptId"]
    body_hash = hashlib.sha256(canonical_json(body).encode()).hexdigest()

    existing = ReceiptEntry.query.filter_by(receipt_id=receipt_id).first()
    if existing:
        if existing.body_hash == body_hash:
            return jsonify(redact(existing.response_snapshot)), 200
        else:
            return error("receiptId exists with different content", 409)

    # TODO Step 6-8: real state_machine.advance() call here
    response = build_incident_response(run)

    entry = ReceiptEntry(
        run_id=run_id,
        receipt_id=receipt_id,
        body_hash=body_hash,
        response_snapshot=response,
    )
    db.session.add(entry)
    db.session.commit()

    return jsonify(redact(response)), 200


if __name__ == "__main__":
    app.run(debug=True, port=5000)
