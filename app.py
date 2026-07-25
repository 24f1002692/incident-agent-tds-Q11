from flask import Flask, request, jsonify
import os
import hashlib
import json

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

PUBLIC_MARKER = os.environ.get("PUBLIC_MARKER", "ga5-run")


@app.route("/v2/incidents", methods=["POST"])
def create_incident():
    body = request.get_json(silent=True)
    if not body or "transcript" not in body:
        return jsonify({"error": "invalid request"}), 400

    transcript = body["transcript"]
    incoming_tp = request.headers.get("traceparent")

    run_id = new_opaque_id()
    trace_id = new_trace_id()

    # STEP 4 TODO: replace with real planner.diagnose() call
    diagnosis = planner.diagnose(transcript, evidence_lines=transcript.splitlines())

    run = IncidentRun(
        run_id=run_id,
        status="waiting",
        request_hash=hashlib.sha256(canonical_json(body).encode()).hexdigest(),
        trace_id=trace_id,
        public_marker=PUBLIC_MARKER,
        diagnosis_root_cause=diagnosis["rootCause"],
        diagnosis_evidence=diagnosis["evidence"],
    )
    db.session.add(run)
    db.session.commit()

    response = {
        "runId": run_id,
        "status": "waiting",
        "diagnosis": {"rootCause": diagnosis["rootCause"], "evidence": diagnosis["evidence"]},
        "dispatches": [],
        "approvals": [],
    }
    return jsonify(redact(response)), 200


@app.route("/v2/incidents/<run_id>", methods=["GET"])
def get_incident(run_id):
    run = IncidentRun.query.get(run_id)
    if not run:
        return jsonify({"error": "not found"}), 404

    response = {
        "runId": run.run_id,
        "status": run.status,
        "diagnosis": {"rootCause": run.diagnosis_root_cause, "evidence": run.diagnosis_evidence},
    }
    return jsonify(redact(response)), 200


@app.route("/v2/incidents/<run_id>/receipts", methods=["POST"])
def post_receipt(run_id):
    run = IncidentRun.query.get(run_id)
    if not run:
        return jsonify({"error": "not found"}), 404

    body = request.get_json(silent=True)
    if not body or "receiptId" not in body:
        return jsonify({"error": "invalid receipt"}), 400

    receipt_id = body["receiptId"]
    body_hash = hashlib.sha256(canonical_json(body).encode()).hexdigest()

    existing = ReceiptEntry.query.filter_by(receipt_id=receipt_id).first()
    if existing:
        if existing.body_hash == body_hash:
            return jsonify(redact(existing.response_snapshot)), 200
        else:
            return jsonify({"error": "conflict"}), 409

    # TODO Step 6-8: real state_machine.advance() call here
    response = {"runId": run.run_id, "status": run.status}

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
