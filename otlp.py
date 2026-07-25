def build_otlp(run, action_logs, receipts):
    """
    TODO: build OTLP resourceSpans JSON from stored rows only.
    No model calls here.
    """
    return {"resourceSpans": [{"scopeSpans": [{"spans": []}]}]}
