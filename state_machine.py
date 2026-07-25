from models import db, ActionLogEntry, ApprovalEntry
from ids import new_opaque_id, new_span_id
from digest import arguments_digest


def process_receipt(run, body):
    """Applies grader outcomes/approvals from a receipt body, then advances state."""
    for o in body.get("outcomes", []):
        entry = ActionLogEntry.query.filter_by(
            run_id=run.run_id,
            action_id=o.get("actionId"),
            call_id=o.get("callId"),
            attempt=o.get("attempt"),
            status="pending",
        ).first()
        if not entry:
            continue  # not a pending call — ignore per spec

        status = o.get("status")
        if status == 503 and entry.attempt == 1:
            entry.status = "retried"
            retry_entry = ActionLogEntry(
                run_id=run.run_id,
                action_id=entry.action_id,
                call_id=new_opaque_id(),
                phase=entry.phase,
                tool_name=entry.tool_name,
                arguments=entry.arguments,
                evidence=entry.evidence,
                attempt=2,
                trace_id=entry.trace_id,
                span_id=new_span_id(),
                status="pending",
            )
            db.session.add(retry_entry)
        elif status == 0 and o.get("errorType") == "timeout":
            entry.status = "failed"
        elif status == 200:
            entry.status = "succeeded"
            entry.result_class = o.get("resultClass")
        else:
            entry.status = "failed"

    db.session.commit()

    for a in body.get("approvals", []):
        appr = ApprovalEntry.query.filter_by(
            run_id=run.run_id, approval_id=a.get("approvalId"), status="pending"
        ).first()
        if appr and a.get("decision") == "approved":
            appr.status = "approved"
            appr.approval_nonce = a.get("nonce")

    db.session.commit()
    advance(run)


def advance(run):
    """Pure state-machine step: no model calls, only DB reads/writes."""
    diagnostics = ActionLogEntry.query.filter_by(run_id=run.run_id, phase="diagnostic").all()

    if any(e.status == "pending" for e in diagnostics):
        return  # still waiting on diagnostic outcomes

    if any(e.status == "failed" for e in diagnostics):
        run.status = "failed"
        run.suppressed = [run.chosen_effect_tool] if run.chosen_effect_tool else []
        db.session.commit()
        return

    if not run.chosen_effect_tool:
        run.status = "completed"
        db.session.commit()
        return

    if run.effect_dispatched:
        effect_entries = ActionLogEntry.query.filter_by(run_id=run.run_id, phase="effect").all()
        if any(e.status == "succeeded" for e in effect_entries):
            run.status = "completed"
            run.chosen_effect = run.chosen_effect_tool
            db.session.commit()
        elif any(e.status == "failed" for e in effect_entries):
            run.status = "failed"
            db.session.commit()
        return  # else still waiting on effect outcome

    is_destructive = run.chosen_effect_tool in (run.approval_required_for or [])

    if is_destructive:
        approval = ApprovalEntry.query.filter_by(run_id=run.run_id).first()
        if not approval:
            action_id = new_opaque_id()
            approval_id = new_opaque_id()
            digest = arguments_digest(run.chosen_effect_arguments or {})
            appr = ApprovalEntry(
                approval_id=approval_id,
                run_id=run.run_id,
                action_id=action_id,
                tool_name=run.chosen_effect_tool,
                arguments=run.chosen_effect_arguments,
                arguments_digest=digest,
                status="pending",
            )
            db.session.add(appr)
            db.session.commit()
            return  # wait for approval
        elif approval.status == "approved":
            entry = ActionLogEntry(
                run_id=run.run_id,
                action_id=approval.action_id,
                call_id=new_opaque_id(),
                phase="effect",
                tool_name=run.chosen_effect_tool,
                arguments=run.chosen_effect_arguments,
                evidence=[],
                attempt=1,
                trace_id=run.trace_id,
                span_id=new_span_id(),
                status="pending",
                approval_id=approval.approval_id,
                approval_nonce=approval.approval_nonce,
            )
            db.session.add(entry)
            run.effect_dispatched = True
            db.session.commit()
            return
        else:
            return  # still pending approval
    else:
        entry = ActionLogEntry(
            run_id=run.run_id,
            action_id=new_opaque_id(),
            call_id=new_opaque_id(),
            phase="effect",
            tool_name=run.chosen_effect_tool,
            arguments=run.chosen_effect_arguments,
            evidence=[],
            attempt=1,
            trace_id=run.trace_id,
            span_id=new_span_id(),
            status="pending",
        )
        db.session.add(entry)
        run.effect_dispatched = True
        db.session.commit()
        return
