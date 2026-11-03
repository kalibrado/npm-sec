import json
from fastapi import APIRouter, Depends

from auth_deps import require_admin
from config import (
    AUTO_BAN_ENABLED,
    AUTO_BAN_SCORE,
    AUTO_BAN_DRY_RUN,
    THREAT_AUTO_BLOCK_THRESHOLD,
    BRUTE_FORCE_WINDOW_MIN,
    BRUTE_FORCE_LOGIN_THRESHOLD,
)
from database import get_db
from services.trust import is_already_blocked, is_trusted_event, validate_ip_or_cidr

router = APIRouter(tags=["threats"])


@router.get("/threats/simulate-autoban", dependencies=[Depends(require_admin)])
def simulate_autoban(limit: int = 100, threshold: int = None):
    effective_threshold = (
        AUTO_BAN_SCORE if threshold is None else min(max(int(threshold), 1), 100)
    )
    limit = min(max(limit, 1), 500)
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT te.ip, MAX(te.score) as max_score, COUNT(*) as events,
                   MAX(te.threat_type) as threat_type,
                   MAX(te.created_at) as last_seen,
                   MAX(al.country_code) as country_code,
                   MAX(al.country_name) as country_name,
                   MAX(al.isp) as isp
            FROM threat_events te
            LEFT JOIN access_logs al ON al.id = te.access_log_id
            WHERE te.score >= ?
            GROUP BY te.ip
            ORDER BY max_score DESC, events DESC
            LIMIT ?
            """,
            [effective_threshold, limit],
        ).fetchall()
        candidates = []
        for r in rows:
            event = dict(r)
            if not event.get("ip"):
                continue
            if is_trusted_event(event, conn) or is_already_blocked(conn, event["ip"]):
                continue
            candidates.append(event)
    return {
        "threshold": effective_threshold,
        "auto_ban_enabled": AUTO_BAN_ENABLED or THREAT_AUTO_BLOCK_THRESHOLD > 0,
        "dry_run": AUTO_BAN_DRY_RUN,
        "would_block": len(candidates),
        "ips": candidates,
    }


@router.get("/threats", dependencies=[Depends(require_admin)])
def threats(limit: int = 50, min_score: int = 0, ip: str = ""):
    limit = min(max(limit, 1), 500)
    min_score = min(max(min_score, 0), 100)
    conditions = ["te.score >= ?"]
    params: list = [min_score]
    if ip:
        ip = validate_ip_or_cidr(ip)
        conditions.append("te.ip = ?")
        params.append(ip)
    where = "WHERE " + " AND ".join(conditions)
    with get_db() as conn:
        rows = conn.execute(
            f"""
            SELECT te.*, al.host, al.uri, al.status, al.country_code, al.country_name
            FROM threat_events te
            LEFT JOIN access_logs al ON al.id = te.access_log_id
            {where}
            ORDER BY te.id DESC
            LIMIT ?
            """,
            params + [limit],
        ).fetchall()
    result = []
    for r in rows:
        item = dict(r)
        try:
            item["reasons"] = json.loads(item.get("reasons") or "[]")
        except Exception:
            item["reasons"] = []
        result.append(item)
    return result


@router.get("/threats/summary", dependencies=[Depends(require_admin)])
def threats_summary():
    with get_db() as conn:
        by_type = conn.execute("""
            SELECT threat_type, COUNT(*) as count, MAX(score) as max_score, ROUND(AVG(score), 1) as avg_score
            FROM threat_events
            WHERE created_at > datetime('now', '-7 days')
            GROUP BY threat_type
            ORDER BY count DESC
            """).fetchall()
        top_ips = conn.execute("""
            SELECT ip, COUNT(*) as count, MAX(score) as max_score, MAX(created_at) as last_seen
            FROM threat_events
            WHERE created_at > datetime('now', '-7 days')
            GROUP BY ip
            ORDER BY max_score DESC, count DESC
            LIMIT 20
            """).fetchall()
    return {
        "by_type": [dict(r) for r in by_type],
        "top_ips": [dict(r) for r in top_ips],
    }


@router.get("/threat-intel/asn-isp", dependencies=[Depends(require_admin)])
def threat_intel_asn_isp(limit: int = 25):
    limit = min(max(limit, 1), 100)
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT COALESCE(al.asn, '') as asn,
                   COALESCE(al.isp, '-') as isp,
                   COUNT(*) as total,
                   SUM(CASE WHEN al.blocked=1 THEN 1 ELSE 0 END) as blocked,
                   COUNT(DISTINCT al.ip) as unique_ips,
                   COUNT(te.id) as threat_events,
                   MAX(te.score) as max_score,
                   MAX(al.timestamp) as last_seen
            FROM access_logs al
            LEFT JOIN threat_events te ON te.access_log_id = al.id
            WHERE al.ip IS NOT NULL AND al.ip != ''
            GROUP BY asn, isp
            HAVING total > 0
            ORDER BY threat_events DESC, blocked DESC, total DESC
            LIMIT ?
            """,
            [limit],
        ).fetchall()
    return [dict(r) for r in rows]


@router.get("/threat-intel/bruteforce", dependencies=[Depends(require_admin)])
def brute_force_by_host(window_min: int = None, threshold: int = None, limit: int = 50):
    window_min = (
        BRUTE_FORCE_WINDOW_MIN
        if window_min is None
        else min(max(int(window_min), 1), 1440)
    )
    threshold = (
        BRUTE_FORCE_LOGIN_THRESHOLD
        if threshold is None
        else min(max(int(threshold), 1), 10000)
    )
    limit = min(max(limit, 1), 200)
    login_patterns = [
        "%login%",
        "%wp-login%",
        "%xmlrpc.php%",
        "%admin%",
        "%signin%",
        "%auth%",
    ]
    params = [f"-{window_min} minutes"] + login_patterns + [threshold, limit]
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT host, ip,
                   COUNT(*) as attempts,
                   SUM(CASE WHEN status IN (401,403,429,444) THEN 1 ELSE 0 END) as denied,
                   COUNT(DISTINCT uri) as unique_uris,
                   MAX(timestamp) as last_seen,
                   MAX(country_code) as country_code,
                   MAX(isp) as isp
            FROM access_logs
            WHERE datetime(timestamp) > datetime('now', ?)
              AND (uri LIKE ? OR uri LIKE ? OR uri LIKE ? OR uri LIKE ? OR uri LIKE ? OR uri LIKE ?)
            GROUP BY host, ip
            HAVING attempts >= ? OR denied >= ?
            ORDER BY denied DESC, attempts DESC
            LIMIT ?
            """,
            params[:-2] + [threshold, threshold, limit],
        ).fetchall()
    return {
        "window_min": window_min,
        "threshold": threshold,
        "items": [dict(r) for r in rows],
    }


@router.get("/threat-tags", dependencies=[Depends(require_admin)])
def threat_tags(limit: int = 100):
    limit = min(max(limit, 1), 500)
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT tag, COUNT(*) as count, MAX(created_at) as last_seen
            FROM threat_tags
            GROUP BY tag
            ORDER BY count DESC
            LIMIT ?
            """,
            [limit],
        ).fetchall()
    return [dict(r) for r in rows]
