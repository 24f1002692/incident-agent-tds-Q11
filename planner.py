ALLOWED_ROOT_CAUSES = [
    # TODO: fill from spec / grader docs once you see a real transcript
]

def diagnose(transcript_text: str, evidence_lines: list[str]) -> dict:
    """
    TODO Step 4: call your model here.
    For now returns a stub so the pipeline runs end-to-end.
    """
    return {
        "rootCause": ALLOWED_ROOT_CAUSES[0] if ALLOWED_ROOT_CAUSES else "unknown",
        "evidence": [e.split("]")[0].strip("[") for e in evidence_lines[:2]]
    }

def choose_diagnostic_calls(diagnosis: dict, transcript_text: str) -> list[dict]:
    """
    TODO Step 5: choose 1-3 diagnostic tool calls with exact arguments.
    Returns list of {"toolName": ..., "arguments": {...}, "evidence": [...]}
    """
    return []
