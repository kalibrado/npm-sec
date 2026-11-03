import json
import time
import urllib.request
from datetime import datetime, timedelta

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from config import WHOIS_CACHE_TTL_DAYS
from database import get_db
from services.log_parser import sse_generator
from services.stats_cache import get_stats_cache, STATS_CACHE_TTL
from services.trust import validate_ip_or_cidr

router = APIRouter(tags=["logs"])
stats_cache = get_stats_cache()


@router.get("/events")
async def events():
    return StreamingResponse(
        sse_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/history")
async def history(
    limit: int = 100,
    cursor: int = None,  # cursor-based (id < cursor) – replaces OFFSET
    offset: int = 0,  # kept for backward compat when cursor absent
    blocked_only: bool = False,
    allowed_only: bool = False,
    search: str = "",
):
    limit = min(limit, 5000)
    if blocked_only and allowed_only:
        return {"logs": [], "total": 0, "next_cursor": None}

    allowed_fields = {
        "ip": "ip",
        "host": "host",
        "method": "method",
        "status": "status",
        "uri": "uri",
        "country": "country_name",
        "country_code": "country_code",
        "isp": "isp",
    }

    with get_db() as conn:
        conditions, params = [], []

        if blocked_only:
            conditions.append("blocked = 1")
        if allowed_only:
            conditions.append("blocked = 0")

        if search:
            for token in search.split():
                if ":" in token:
                    field, value = token.split(":", 1)
                    if field.lower() in allowed_fields and value:
                        like = value if "%" in value else f"{value}%"
                        conditions.append(f"{allowed_fields[field.lower()]} LIKE ?")
                        params.append(like)
                    else:
                        like = f"%{token}%"
                        conditions.append(
                            "(ip LIKE ? OR host LIKE ? OR uri LIKE ? OR country_name LIKE ? OR isp LIKE ? OR status LIKE ?)"
                        )
                        params.extend([like] * 6)
                else:
                    like = f"%{token}%"
                    conditions.append(
                        "(ip LIKE ? OR host LIKE ? OR uri LIKE ? OR country_name LIKE ? OR country_code LIKE ? OR isp LIKE ?)"
                    )
                    params.extend([like] * 6)

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        total = conn.execute(
            f"SELECT COUNT(*) FROM access_logs {where}", params
        ).fetchone()[0]

        # Cursor-based: efficient for large tables
        if cursor is not None:
            cursor_clause = f"{'AND' if where else 'WHERE'} id < ?"
            rows = conn.execute(
                f"SELECT * FROM access_logs {where} {cursor_clause} ORDER BY id DESC LIMIT ?",
                params + [cursor, limit],
            ).fetchall()
        else:
            rows = conn.execute(
                f"SELECT * FROM access_logs {where} ORDER BY id DESC LIMIT ? OFFSET ?",
                params + [limit, offset],
            ).fetchall()

    log_list = [dict(r) for r in rows]
    next_cursor = min((r["id"] for r in rows), default=None) if rows else None
    return {"logs": log_list, "total": total, "next_cursor": next_cursor}


@router.get("/stats")
async def stats():
    now = time.time()
    if stats_cache["data"] and (now - stats_cache["ts"]) < STATS_CACHE_TTL:
        return stats_cache["data"]

    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM access_logs").fetchone()[0]
        blocked = conn.execute(
            "SELECT COUNT(*) FROM access_logs WHERE blocked=1"
        ).fetchone()[0]

        top_countries = conn.execute("""
            SELECT country_code, country_name, COUNT(*) as count, SUM(blocked) as blocked_count
            FROM access_logs GROUP BY country_code ORDER BY count DESC LIMIT 10
        """).fetchall()

        top_ips = conn.execute("""
            SELECT ip, COUNT(*) as count, MAX(timestamp) as last_seen,
                   MAX(isp) as isp, MAX(country_code) as country_code
            FROM access_logs WHERE blocked=1
            GROUP BY ip ORDER BY count DESC LIMIT 10
        """).fetchall()

        status_dist = conn.execute("""
            SELECT status, COUNT(*) as count FROM access_logs
            GROUP BY status ORDER BY count DESC
        """).fetchall()

        top_uris = conn.execute("""
            SELECT uri, COUNT(*) as count FROM access_logs WHERE blocked=1
            GROUP BY uri ORDER BY count DESC LIMIT 10
        """).fetchall()

    result = {
        "total": total,
        "blocked": blocked,
        "allowed": total - blocked,
        "block_rate": round(blocked / total * 100, 1) if total else 0,
        "top_countries": [dict(r) for r in top_countries],
        "top_attackers": [dict(r) for r in top_ips],
        "top_uris": [dict(r) for r in top_uris],
        "status_dist": [dict(r) for r in status_dist],
    }
    stats_cache.update({"data": result, "ts": now})
    return result


@router.get("/timeline")
def timeline():
    with get_db() as conn:
        rows = conn.execute("""
            SELECT strftime('%Y-%m-%d %H:%M', timestamp) as t,
                   COUNT(*) as total, SUM(blocked) as blocked
            FROM access_logs GROUP BY t ORDER BY t DESC LIMIT 60
        """).fetchall()
    return [dict(r) for r in rows]


@router.get("/heatmap")
def heatmap():
    """Returns a 7-day × 24-hour attack heatmap matrix."""
    with get_db() as conn:
        rows = conn.execute("""
            SELECT
                CAST(strftime('%w', timestamp, 'localtime') AS INTEGER) as dow,
                CAST(strftime('%H', timestamp, 'localtime') AS INTEGER) as hour,
                COUNT(*) as total,
                SUM(blocked) as blocked
            FROM access_logs
            WHERE timestamp > datetime('now', '-7 days')
            GROUP BY dow, hour
        """).fetchall()

    matrix = [[{"total": 0, "blocked": 0} for _ in range(24)] for _ in range(7)]
    for r in rows:
        matrix[r["dow"]][r["hour"]] = {
            "total": r["total"],
            "blocked": int(r["blocked"] or 0),
        }
    return {"matrix": matrix}


@router.get("/sparklines")
def sparklines(ips: str = ""):
    """Returns per-IP 5-min-bucket hit counts for the last 60 min."""
    ip_list = [i.strip() for i in ips.split(",") if i.strip()][:20]
    if not ip_list:
        return {}
    result = {}
    with get_db() as conn:
        for ip in ip_list:
            rows = conn.execute(
                """
                SELECT
                    CAST(strftime('%H', timestamp, 'localtime') AS INTEGER)*12 +
                    CAST(strftime('%M', timestamp, 'localtime') AS INTEGER)/5 AS bucket,
                    COUNT(*) as count
                FROM access_logs
                WHERE ip = ? AND timestamp > datetime('now', '-1 hour')
                GROUP BY bucket ORDER BY bucket
            """,
                [ip],
            ).fetchall()
            result[ip] = [r["count"] for r in rows] or [0]
    return result


@router.get("/whois/{ip}")
def whois(ip: str, refresh: bool = False):
    """Cached proxy to ipinfo.io to avoid CORS, rate limits and needless drama."""
    ip = validate_ip_or_cidr(ip)
    ttl_expr = f"-{WHOIS_CACHE_TTL_DAYS} days"

    if not refresh:
        with get_db() as conn:
            row = conn.execute(
                "SELECT payload, updated_at FROM whois_cache WHERE ip=? AND updated_at > datetime('now', ?)",
                [ip, ttl_expr],
            ).fetchone()
            if row:
                payload = json.loads(row["payload"])
                payload["_cached"] = True
                payload["_cached_at"] = row["updated_at"]
                return payload

    try:
        url = f"https://ipinfo.io/{ip}/json"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as r:
            payload = json.loads(r.read())
        with get_db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO whois_cache (ip, payload, updated_at) VALUES (?, ?, datetime('now'))",
                [ip, json.dumps(payload)],
            )
            conn.commit()
        payload["_cached"] = False
        return payload
    except Exception as e:
        return {"error": str(e)}
