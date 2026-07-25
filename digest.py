import json
import hashlib

def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

def arguments_digest(args: dict) -> str:
    return hashlib.sha256(canonical_json(args).encode("utf-8")).hexdigest()

def redact(obj):
    """Recursively redact sensitive-looking keys before returning in any response."""
    SENSITIVE_KEYS = {"authorization", "token", "password", "secret", "apikey", "api_key"}
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k.lower() in SENSITIVE_KEYS:
                out[k] = "[REDACTED]"
            else:
                out[k] = redact(v)
        return out
    elif isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj
