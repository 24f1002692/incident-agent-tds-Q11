from models import ApprovalEntry
from ids import new_span_id

SPAN_KIND_INTERNAL = 1
SPAN_KIND_SERVER = 2
SPAN_KIND_CLIENT = 3

STATUS_UNSET = 0
STATUS_OK = 1
STATUS_ERROR = 2

_counter = [1000]


def _next_time():
    _counter[0] += 1000
    return _counter[0]


def _attr(key, value):
    if isinstance(value, bool):
        return {"key": key, "value": {"boolValue": value}}
    if isinstance(value, int):
        return {"key": key, "value": {"intValue": str(value)}}
    return {"key": key, "value": {"stringValue": "" if value is None else str(value)}}


def _make_span(trace_id, span_id, parent_span_id, name, kind, attributes: dict,
                status_code=STATUS_UNSET, links=None):
    start = _next_time()
    end = start + 500
    span = {
        "traceId": trace_id,
        "spanId": span_id,
        "name": name,
        "kind": kind,
        "startTimeUnixNano": str(start),
        "endTimeUnixNano": str(end),
        "attributes": [_attr(k, v) for k, v in attributes.items()],
        "status": {"code": status_code},
    }
    if parent_span_id:
        span["parentSpanId"] = parent_span_id
    if links:
        span["links"] = [{"traceId": trace_id, "spanId": sid} for sid in links]
    return span


def build_otlp(run, action_logs, receipts):
    trace_id = run.trace_id
    spans = []

    common = {
        "ga5.run.id": run.run_id,
        "ga5.public.marker": run.public_marker,
    }

    # SERVER root span
    server_span_id = new_span_id()
    spans.append(_make_span(
        trace_id, server_span_id, None, "POST /v2/incidents", SPAN_KIND_SERVER, dict(common)
    ))

    # INTERNAL invoke_agent
    agent_span_id = new_span_id()
    spans.append(_make_span(
        trace_id, agent_span_id, server_span_id, "invoke_agent incident-response",
        SPAN_KIND_INTERNAL, dict(common)
    ))

    # CLIENT chat incident-plan — exactly one
    chat_span_id = new_span_id()
    chat_attrs = dict(common)
    chat_attrs["gen_ai.operation.name"] = "chat"
    chat_attrs["gen_ai.request.model"] = run.model_used or "unknown-model"
    spans.append(_make_span(
        trace_id, chat_span_id, agent_span_id, "chat incident-plan",
        SPAN_KIND_CLIENT, chat_attrs
    ))

    # Group action_logs by action_id (logical action), preserving first-seen order
    logical_actions = {}
    order = []
    for e in action_logs:
        if e.action_id not in logical_actions:
            logical_actions[e.action_id] = []
            order.append(e.action_id)
        logical_actions[e.action_id].append(e)

    diagnostic_execute_span_ids = []

    for action_id in order:
        entries = logical_actions[action_id]
        first = entries[0]
        # the logical call id is the same across attempts (per spec)
        call_id = first.call_id

        exec_span_id = new_span_id()
        exec_attrs = dict(common)
        exec_attrs["ga5.action.id"] = action_id
        exec_attrs["gen_ai.tool.name"] = first.tool_name
        exec_attrs["gen_ai.tool.call.id"] = call_id
        exec_attrs["gen_ai.operation.name"] = "execute_tool"
        spans.append(_make_span(
            trace_id, exec_span_id, agent_span_id, f"execute_tool {first.tool_name}",
            SPAN_KIND_INTERNAL, exec_attrs
        ))

        if first.phase == "diagnostic":
            diagnostic_execute_span_ids.append(exec_span_id)

        for attempt_entry in entries:
            client_attrs = dict(common)
            client_attrs["ga5.action.id"] = action_id
            client_attrs["ga5.attempt"] = attempt_entry.attempt
            if attempt_entry.receipt_id:
                client_attrs["ga5.receipt.id"] = attempt_entry.receipt_id
            if attempt_entry.receipt_nonce:
                client_attrs["ga5.receipt.nonce"] = attempt_entry.receipt_nonce
            client_attrs["http.request.method"] = "POST"
            client_attrs["http.request.resend_count"] = attempt_entry.attempt - 1

            status_code = STATUS_UNSET
            if attempt_entry.error_type == "503":
                status_code = STATUS_ERROR
                client_attrs["error.type"] = "503"
            elif attempt_entry.error_type == "timeout":
                status_code = STATUS_ERROR
                client_attrs["error.type"] = "timeout"
            elif attempt_entry.status == "succeeded":
                status_code = STATUS_UNSET  # UNSET or OK, never ERROR on success
            elif attempt_entry.error_type:
                status_code = STATUS_ERROR
                client_attrs["error.type"] = attempt_entry.error_type

            # Reuse the EXACT span id that was placed in the dispatch's traceparent
            spans.append(_make_span(
                trace_id, attempt_entry.span_id, exec_span_id,
                f"POST tool/{attempt_entry.tool_name}", SPAN_KIND_CLIENT,
                client_attrs, status_code=status_code
            ))

    # incident.join — only when diagnostics fanned out (more than one)
    if len(diagnostic_execute_span_ids) > 1:
        join_span_id = new_span_id()
        spans.append(_make_span(
            trace_id, join_span_id, agent_span_id, "incident.join",
            SPAN_KIND_INTERNAL, dict(common), links=diagnostic_execute_span_ids
        ))

    # approval_gate — only when an approval was required for this run
    approval = ApprovalEntry.query.filter_by(run_id=run.run_id).first()
    if approval:
        gate_span_id = new_span_id()
        gate_attrs = dict(common)
        gate_attrs["ga5.approval.id"] = approval.approval_id
        if approval.approval_nonce:
            gate_attrs["ga5.receipt.nonce"] = approval.approval_nonce
        spans.append(_make_span(
            trace_id, gate_span_id, agent_span_id, "approval_gate",
            SPAN_KIND_INTERNAL, gate_attrs
        ))

    return {
        "resourceSpans": [
            {"scopeSpans": [{"spans": spans}]}
        ]
    }
