import uuid
import secrets

def new_opaque_id() -> str:
    """Stable id, opaque, min 8 chars."""
    return uuid.uuid4().hex

def new_trace_id() -> str:
    """32 lowercase hex chars, nonzero."""
    while True:
        t = secrets.token_hex(16)
        if t != "0" * 32:
            return t

def new_span_id() -> str:
    """16 lowercase hex chars, nonzero."""
    while True:
        s = secrets.token_hex(8)
        if s != "0" * 16:
            return s

def build_traceparent(trace_id: str, span_id: str, flags: str = "01") -> str:
    return f"00-{trace_id}-{span_id}-{flags}"

def parse_traceparent(tp: str):
    """Returns (trace_id, span_id) if valid, else None."""
    if not tp:
        return None
    parts = tp.split("-")
    if len(parts) != 4:
        return None
    version, trace_id, span_id, flags = parts
    if len(trace_id) != 32 or trace_id == "0" * 32:
        return None
    if len(span_id) != 16 or span_id == "0" * 16:
        return None
    return trace_id, span_id
