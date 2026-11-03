"""A compact, grounded overview for the security control center.

The endpoint reports what NPM actually logged separately from security
rules that are only generated or pending application to Nginx.
"""
from fastapi import APIRouter, Depends, Query

from auth_deps import require_admin
from config import (
    AUTO_BAN_DRY_RUN,
    AUTO_BAN_ENABLED,
    THREAT_AUTO_BLOCK_THRESHOLD,
)
from database import get_db
from services.deployment import get_policy_deployment_status

router = APIRouter(tags=["security-control"], dependencies=[Depends(require_admin)])


@router.get("/security-control/overview")
def security_control_overview(
    hours: int = Query(default=24, ge=1, le=168),
):
    window = f"-{hours} hours"
    with get_db() as conn:
        block_types = conn.execute(
            """SELECT type, COUNT(*) AS total
               FROM blocklist
               WHERE expires_at IS NULL OR expires_at > datetime('now')
               GROUP BY type""",
        ).fetchall()
        trusted = conn.execute(
            "SELECT COUNT(*) FROM trusted_entries"
        ).fetchone()[0]
        traffic = conn.execute(
            """SELECT COUNT(*) AS requests,
                      COALESCE(SUM(CASE WHEN blocked=1 THEN 1 ELSE 0 END), 0) AS proxy_blocked,
                      COUNT(DISTINCT ip) AS unique_ips
               FROM access_logs
               WHERE datetime(timestamp) >= datetime('now', ?)""",
            [window],
        ).fetchone()
        incidents = conn.execute(
            """SELECT COUNT(*) AS signals,
                      COUNT(DISTINCT ip) AS suspicious_ips,
                      COALESCE(SUM(CASE WHEN threat_type='brute_force' THEN 1 ELSE 0 END), 0)
                          AS brute_force,
                      COALESCE(SUM(CASE WHEN threat_type='scanner' THEN 1 ELSE 0 END), 0)
                          AS http_scans
               FROM threat_events
               WHERE datetime(created_at) >= datetime('now', ?)""",
            [window],
        ).fetchone()
        latest_actions = [
            dict(row)
            for row in conn.execute(
                """SELECT target, type, action, reason, created_at
                   FROM ban_events ORDER BY id DESC LIMIT 5"""
            ).fetchall()
        ]

    counts = {"ip": 0, "cidr": 0, "country": 0}
    for row in block_types:
        if row["type"] in counts:
            counts[row["type"]] = row["total"]

    enabled = AUTO_BAN_ENABLED or THREAT_AUTO_BLOCK_THRESHOLD > 0
    auto_ban_mode = (
        "off" if not enabled else "simulation" if AUTO_BAN_DRY_RUN else "active"
    )
    return {
        "window_hours": hours,
        "policy": get_policy_deployment_status(),
        "rules": {
            "active_total": sum(counts.values()),
            "by_type": counts,
            "trusted_total": trusted,
        },
        "traffic": dict(traffic),
        "detections": dict(incidents),
        "auto_ban_mode": auto_ban_mode,
        "recent_actions": latest_actions,
    }
