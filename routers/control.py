from services.security_rules import active_rules
"""A compact, grounded overview for the security control center.

The endpoint reports what NPM actually logged separately from security
rules that are only generated or pending application to Nginx.
"""
import ipaddress

from fastapi import APIRouter, Depends, HTTPException, Query

from auth_deps import require_admin
from config import (
    AUTO_BAN_DRY_RUN,
    AUTO_BAN_ENABLED,
    THREAT_AUTO_BLOCK_THRESHOLD,
)
from database import get_db
from services.deployment import get_policy_deployment_status
from services.policy_preview import evaluate_saved_policy
from schemas import ObservationIncidentStatusUpdate, PolicyModeUpdate
from services.export import (
    get_blocklist_items, get_trusted_items, get_policy_modes,
    write_blocklist_exports,
)
from services.trust import validate_proxy_host
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


@router.get("/security-control/policy/modes")
def list_policy_modes():
    """List explicit overrides; other hosts inherit the global mode."""
    with get_db() as conn:
        modes = get_policy_modes(conn)
    return {
        "default_mode": modes.get("", "block"),
        "overrides": [
            {"host": host, "mode": mode}
            for host, mode in sorted(modes.items())
            if host
        ],
        "policy": get_policy_deployment_status(),
    }


@router.post("/security-control/policy/modes")
def set_policy_mode(payload: PolicyModeUpdate):
    scope = validate_proxy_host(payload.host)
    try:
        with get_db() as conn:
            conn.execute(
                """INSERT INTO policy_modes (host, mode) VALUES (?, ?)
                   ON CONFLICT(host) DO UPDATE SET
                       mode=excluded.mode, updated_at=datetime('now')""",
                [scope, payload.mode],
            )
            write_blocklist_exports(
                get_blocklist_items(conn), get_trusted_items(conn),
                get_policy_modes(conn), active_rules(conn),
            )
            conn.commit()
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Unable to update policy mode") from exc
    return {
        "host": scope,
        "mode": payload.mode,
        "pending_apply": True,
    }


@router.delete("/security-control/policy/modes")
def reset_policy_mode(host: str = Query(default="", max_length=253)):
    scope = validate_proxy_host(host)
    try:
        with get_db() as conn:
            conn.execute("DELETE FROM policy_modes WHERE host=?", [scope])
            write_blocklist_exports(
                get_blocklist_items(conn), get_trusted_items(conn),
                get_policy_modes(conn), active_rules(conn),
            )
            conn.commit()
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Unable to reset policy mode") from exc
    return {"host": scope, "mode": "inherited", "pending_apply": True}


@router.get("/security-control/observations")
def observation_incident_console(
    hours: int = Query(default=24, ge=1, le=168),
    limit: int = Query(default=50, ge=1, le=100),
    status: str = Query(default="all"),
):
    """Observed Nginx decisions, not inferred from HTTP status or saved rules."""
    if status not in {"all", "open", "acknowledged", "resolved"}:
        raise HTTPException(status_code=422, detail="Invalid incident status")

    window = f"-{hours} hours"
    with get_db() as conn:
        summary = conn.execute(
            """SELECT
                   COUNT(*) AS instrumented_requests,
                   COALESCE(SUM(CASE WHEN policy_mode='observe' AND would_deny=1
                            THEN 1 ELSE 0 END), 0) AS would_deny_requests,
                   COALESCE(SUM(CASE WHEN policy_mode='block' AND would_deny=1
                            THEN 1 ELSE 0 END), 0) AS would_deny_block_mode
               FROM access_logs
               WHERE policy_mode IN ('observe','block')
                 AND would_deny IN (0,1)
                 AND datetime(timestamp) >= datetime('now', ?)""",
            (window,),
        ).fetchone()
        alert_count = conn.execute(
            """SELECT COUNT(*) FROM observation_alerts
               WHERE created_at >= datetime('now', ?)""",
            (window,),
        ).fetchone()[0]
        where = "AND status=?" if status != "all" else ""
        args = [window]
        if status != "all":
            args.append(status)
        args.append(limit)
        items = [
            dict(row) for row in conn.execute(
                f"""SELECT id, host, ip, status, first_seen, last_seen,
                           hits, last_uri, last_country, last_alert_at
                    FROM observation_incidents
                    WHERE last_seen >= datetime('now', ?) {where}
                    ORDER BY last_seen DESC, id DESC LIMIT ?""",
                args,
            ).fetchall()
        ]
    return {
        "window_hours": hours,
        "telemetry_available": summary["instrumented_requests"] > 0,
        "telemetry": dict(summary),
        "alert_count": alert_count,
        "items": items,
        "source": "nginx_observation_fields",
        "warning": (
            "Seuls les logs Nginx contenant npm_security_policy_mode et "
            "npm_security_would_deny alimentent les incidents. "
            "Aucune décision n'est inférée depuis les règles enregistrées."
        ),
    }


@router.get("/security-control/observations/alerts")
def observation_alert_history(
    hours: int = Query(default=24, ge=1, le=168),
    limit: int = Query(default=50, ge=1, le=100),
):
    with get_db() as conn:
        alerts = conn.execute(
            """SELECT a.id, a.incident_id, a.created_at, a.recent_hits,
                      i.host, i.ip, i.status
               FROM observation_alerts a
               JOIN observation_incidents i ON i.id=a.incident_id
               WHERE a.created_at >= datetime('now', ?)
               ORDER BY a.id DESC LIMIT ?""",
            (f"-{hours} hours", limit),
        ).fetchall()
    return [dict(row) for row in alerts]


@router.post("/security-control/observations/{incident_id}/status")
def update_observation_incident(
    incident_id: int,
    payload: ObservationIncidentStatusUpdate,
):
    with get_db() as conn:
        incident = conn.execute(
            "SELECT id FROM observation_incidents WHERE id=?",
            (incident_id,),
        ).fetchone()
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        conn.execute(
            "UPDATE observation_incidents SET status=? WHERE id=?",
            (payload.status, incident_id),
        )
        conn.commit()
    return {"id": incident_id, "status": payload.status}
