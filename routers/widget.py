import json
from fastapi import APIRouter, HTTPException, Depends

from auth_deps import require_viewer

from  config import APP_VERSION
from  database import get_db
from  services.trust import is_trusted_event, validate_ip_or_cidr

router = APIRouter(tags=["widget"], dependencies=[Depends(require_viewer)])


@router.get("/widget")
def homepage_widget():
    """Small JSON payload for Homepage/gethomepage custom widgets."""
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM access_logs").fetchone()[0]
        blocked = conn.execute("SELECT COUNT(*) FROM access_logs WHERE blocked=1").fetchone()[0]
        threats_24h = conn.execute(
            "SELECT COUNT(*) FROM threat_events WHERE created_at > datetime('now','-24 hours') AND score >= 50"
        ).fetchone()[0]
        last_attack = conn.execute(
            "SELECT created_at FROM threat_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        top_error = conn.execute(
            """
            SELECT status, COUNT(*) as count FROM access_logs
            WHERE status >= 500 AND timestamp > datetime('now','-24 hours')
            GROUP BY status ORDER BY count DESC LIMIT 1
            """
        ).fetchone()
    block_rate = (blocked / total * 100) if total else 0
    score = max(0, round(100 - min(30, block_rate * 5) - min(30, threats_24h * 2)))
    return {
        "name": "NPM Security Dashboard",
        "version": APP_VERSION,
        "security_score": score,
        "logs_total": total,
        "blocked_total": blocked,
        "block_rate": round(block_rate, 2),
        "threats_24h": threats_24h,
        "last_attack": last_attack["created_at"] if last_attack else None,
        "top_error_24h": dict(top_error) if top_error else None,
    }


@router.get("/security-activity")
def security_activity(limit: int = 30):
    """Unified recent security activity feed for the mobile home screen."""
    limit = min(max(limit, 1), 100)
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT 'threat' as source, te.id, te.created_at, te.ip as target, te.threat_type as action,
                   te.score as score, te.reasons as details, al.host, al.uri
            FROM threat_events te
            LEFT JOIN access_logs al ON al.id = te.access_log_id
            UNION ALL
            SELECT 'ban' as source, id, created_at, target, action, NULL as score, reason as details,
                   NULL as host, NULL as uri
            FROM ban_events
            ORDER BY created_at DESC
            LIMIT ?
            """,
            [limit],
        ).fetchall()
    result = []
    for r in rows:
        item = dict(r)
        if item.get("source") == "threat":
            try:
                item["details"] = json.loads(item.get("details") or "[]")
            except Exception:
                item["details"] = []
        result.append(item)
    return result


@router.get("/ip/{ip}/profile")
def ip_profile(ip: str):
    ip = validate_ip_or_cidr(ip)
    with get_db() as conn:
        summary = conn.execute(
            """
            SELECT ip, COUNT(*) as total, COALESCE(SUM(blocked),0) as blocked,
                   MAX(timestamp) as last_seen, MIN(timestamp) as first_seen,
                   MAX(country_code) as country_code, MAX(country_name) as country_name,
                   MAX(city) as city, MAX(isp) as isp, MAX(asn) as asn
            FROM access_logs WHERE ip = ? GROUP BY ip
            """,
            [ip],
        ).fetchone()
        if not summary:
            raise HTTPException(status_code=404, detail="IP not found")
        statuses = conn.execute(
            "SELECT status, COUNT(*) as count FROM access_logs WHERE ip=? GROUP BY status ORDER BY count DESC LIMIT 10",
            [ip],
        ).fetchall()
        hosts = conn.execute(
            "SELECT host, COUNT(*) as count FROM access_logs WHERE ip=? GROUP BY host ORDER BY count DESC LIMIT 10",
            [ip],
        ).fetchall()
        threats = conn.execute(
            "SELECT * FROM threat_events WHERE ip=? ORDER BY id DESC LIMIT 20",
            [ip],
        ).fetchall()
        logs = conn.execute(
            "SELECT id,timestamp,host,method,uri,status,blocked,threat FROM access_logs WHERE ip=? ORDER BY id DESC LIMIT 30",
            [ip],
        ).fetchall()
        is_blocked = conn.execute(
            """SELECT 1 FROM blocklist
               WHERE type='ip' AND value=? AND host=''
                 AND (expires_at IS NULL OR expires_at > datetime('now'))
               LIMIT 1""", [ip]
        ).fetchone() is not None
        is_trusted = is_trusted_event({"ip": ip, "country_code": summary["country_code"] or "", "ua": ""}, conn)
    threat_list = []
    for t in threats:
        d = dict(t)
        try:
            d["reasons"] = json.loads(d.get("reasons") or "[]")
        except Exception:
            d["reasons"] = []
        threat_list.append(d)
    return {
        "summary": dict(summary),
        "is_blocked": is_blocked,
        "is_trusted": is_trusted,
        "statuses": [dict(r) for r in statuses],
        "hosts": [dict(r) for r in hosts],
        "threats": threat_list,
        "logs": [dict(r) for r in logs],
    }
