"""Read-only evidence of the last validated Nginx policy deployment."""
import hashlib
import json

from config import EXPORT_DIR


def _policy_hash(http_file, guard_file):
    a = hashlib.sha256(http_file.read_bytes()).hexdigest()
    b = hashlib.sha256(guard_file.read_bytes()).hexdigest()
    return hashlib.sha256((a + b).encode("ascii")).hexdigest()


def get_policy_deployment_status() -> dict:
    http_file = EXPORT_DIR / "npm-blocklist.conf"
    guard_file = EXPORT_DIR / "npm-server-guard.conf"
    status_file = EXPORT_DIR / "deployment-status.json"
    if not http_file.exists() or not guard_file.exists():
        return {"state": "not_configured", "generated_hash": None, "applied_hash": None}
    generated_hash = _policy_hash(http_file, guard_file)
    try:
        status = json.loads(status_file.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, ValueError):
        status = {}

    applied_hash = status.get("applied_hash")
    confirmed = status.get("status") == "applied" and applied_hash == generated_hash
    return {
        "state": "applied" if confirmed else "pending",
        "generated_hash": generated_hash,
        "applied_hash": applied_hash,
        "applied_at": status.get("applied_at"),
        "container": status.get("container"),
        "verification": "last successful nginx -t and reload" if confirmed else None,
    }
