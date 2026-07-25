def diagnose(transcript: str, allowed_root_causes: list, evidence_lines: list) -> dict:
    """
    TODO Step 4 (real): call your model here.
    Prompt should include:
      - the transcript / evidence lines (NOT the sensitive object)
      - the allowedRootCauses list
    Model must return exactly one rootCause from allowedRootCauses
    and 2-4 evidence IDs that exist in the transcript.

    For now this is a stub that picks the first allowed root cause
    and grabs the first 2 evidence-tagged lines it finds.
    """
    root_cause = allowed_root_causes[0] if allowed_root_causes else "unknown"

    evidence = []
    for line in evidence_lines:
        line = line.strip()
        if line.startswith("[") and "]" in line:
            ev_id = line.split("]")[0].strip("[")
            if ev_id and ev_id not in evidence:
                evidence.append(ev_id)
        if len(evidence) == 2:
            break

    return {"rootCause": root_cause, "evidence": evidence}


def choose_diagnostic_calls(diagnosis: dict, transcript: str, tool_catalog: list, max_diagnostics: int = 3) -> list:
    """
    TODO Step 5 (real): choose 1-3 diagnostic tool calls from tool_catalog
    with exact incident-specific arguments, each citing >=1 evidence ID
    from diagnosis['evidence'].

    For now returns an empty list (no dispatches yet) — Step 5 will fill this in.
    Returns: list of dicts like
      {"toolName": "...", "arguments": {...}, "evidence": ["ev_..."]}
    """
    return []
