"""A compact, grounded overview for the security control center.

The endpoint reports what NPM actually logged separately from security
rules that are only generated or pending application to Nginx.
"""
import ipaddress

from fastapi import APIRouter, Depends, Query

from auth_deps import require_admin
from config import (
    AUTO_BAN_DRY_RUN,
    AUTO_BAN_ENABLED,
    THREAT_AUTO_BLOCK_THRESHOLD,
)
from database import get_db
from services.deployment import get_policy_deployment_status
from services.policy_preview import evaluate_saved_policy
from services.trust import is_internal_ip

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


def _matching_network_rule(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, rows):
    """Return the most specific matching CIDR or exact IP rule."""
    matches = []
    for row in rows:
        try:
            network = ipaddress.ip_network(row["value"], strict=False)
        except ValueError:
            continue
        if ip in network:
            matches.append((network.prefixlen, dict(row)))
    return max(matches, default=(None, None), key=lambda item: item[0])[1]


@router.get("/security-control/suspects")
def security_control_suspects(
    hours: int = Query(default=24, ge=1, le=168),
    limit: int = Query(default=20, ge=1, le=100),
    min_score: int = Query(default=25, ge=0, le=100),
):
    """Rank suspicious IPs by observed threat signals, without changing policy.

    The returned block state describes rule storage, not actual Nginx
    enforcement. Only explicit IP/CIDR trust is used as a network exemption;
    a spoofable User-Agent is never treated as an IP trust grant.
    """
    with get_db() as conn:
        rows = conn.execute(
            """SELECT te.ip, COUNT(*) AS signals, MAX(te.score) AS max_score,
                      MAX(te.created_at) AS last_seen,
                      SUM(CASE WHEN te.threat_type='brute_force' THEN 1 ELSE 0 END) AS brute_force,
                      SUM(CASE WHEN te.threat_type='scanner' THEN 1 ELSE 0 END) AS scans,
                      MAX(al.host) AS host,
                      MAX(al.country_code) AS country_code
               FROM threat_events te
               LEFT JOIN access_logs al ON al.id=te.access_log_id
               WHERE datetime(te.created_at) >= datetime('now', ?)
                 AND te.score >= ? AND te.ip IS NOT NULL AND te.ip != ''
               GROUP BY te.ip
               ORDER BY max_score DESC, signals DESC, last_seen DESC
               LIMIT ?""",
            [f"-{hours} hours", min_score, limit],
        ).fetchall()
        blocked_rules = conn.execute(
            """SELECT id, type, value FROM blocklist
               WHERE host='' AND type IN ('ip','cidr')
                 AND (expires_at IS NULL OR expires_at > datetime('now'))"""
        ).fetchall()
        trusted_rules = conn.execute(
            """SELECT id, type, value FROM trusted_entries
               WHERE type IN ('ip','cidr')"""
        ).fetchall()

    results = []
    for row in rows:
        try:
            ip = ipaddress.ip_address(row["ip"])
        except ValueError:
            continue
        blocking = _matching_network_rule(ip, blocked_rules)
        trusted = _matching_network_rule(ip, trusted_rules)
        internal = is_internal_ip(str(ip))
        results.append({
            **dict(row),
            "ip": str(ip),
            "internal": internal,
            "trusted": internal or trusted is not None,
            "trust_source": "internal_network" if internal else (trusted["type"] if trusted else None),
            "block_rule": blocking,
            "direct_block_id": blocking["id"] if blocking and blocking["type"] == "ip" else None,
        })
    return {
        "window_hours": hours,
        "min_score": min_score,
        "policy_state": get_policy_deployment_status()["state"],
        "items": results,
    }


@router.get("/security-control/policy/preview")
def security_policy_preview(
    ip: str = Query(..., min_length=3, max_length=45),
    host: str = Query(..., min_length=1, max_length=253),
    country_code: str | None = Query(default=None),
):
    """Explain a saved-policy decision without touching NPM or the blocklist."""
    with get_db() as conn:
        prediction = evaluate_saved_policy(conn, ip, host, country_code)
    prediction["policy"] = get_policy_deployment_status()
    prediction["warning"] = (
        "Simulation des règles enregistrées uniquement. "
        "Le statut Nginx réel dépend du dernier déploiement et de la configuration du proxy."
    )
    return prediction
