import csv
import io
import shutil
from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import FileResponse, Response

from  auth_deps import require_admin
from  config import BACKUP_DIR, CSV_EXPORT_LIMIT, DB_FILE, DB_RETENTION_DAYS, DISCORD_WEBHOOK_URL, PROMETHEUS_METRICS_ENABLED
from  database import get_db, invalidate_stats_cache
from  report_generator import send_discord_with_attachment
from  services.reports import generate_report_file

router = APIRouter(tags=["admin"])


def _metric_line(name: str, value, labels: dict | None = None) -> str:
    if labels:
        label_txt = ",".join(f'{k}="{str(v).replace(chr(34), "_")}"' for k, v in labels.items())
        return f"{name}{{{label_txt}}} {value}"
    return f"{name} {value}"


@router.get("/metrics", dependencies=[Depends(require_admin)])
def prometheus_metrics():
    if not PROMETHEUS_METRICS_ENABLED:
        raise HTTPException(status_code=404, detail="Metrics disabled")
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM access_logs").fetchone()[0]
        blocked = conn.execute("SELECT COUNT(*) FROM access_logs WHERE blocked=1").fetchone()[0]
        threats_total = conn.execute("SELECT COUNT(*) FROM threat_events").fetchone()[0]
        block_entries = conn.execute("SELECT COUNT(*) FROM blocklist").fetchone()[0]
        trusted_entries = conn.execute("SELECT COUNT(*) FROM trusted_entries").fetchone()[0]
        autoban = conn.execute("SELECT COUNT(*) FROM ban_events WHERE action IN ('AUTO_BLOCK','AUTO_BLOCK_DRY_RUN')").fetchone()[0]
        status_rows = conn.execute("SELECT status, COUNT(*) as count FROM access_logs GROUP BY status").fetchall()
        threat_rows = conn.execute("SELECT threat_type, COUNT(*) as count FROM threat_events GROUP BY threat_type").fetchall()
        tag_rows = conn.execute("SELECT tag, COUNT(*) as count FROM threat_tags GROUP BY tag ORDER BY count DESC LIMIT 50").fetchall()
    lines = [
        "# HELP npm_security_logs_total Total parsed access logs",
        "# TYPE npm_security_logs_total counter",
        _metric_line("npm_security_logs_total", total),
        "# HELP npm_security_blocked_total Total blocked access logs",
        "# TYPE npm_security_blocked_total counter",
        _metric_line("npm_security_blocked_total", blocked),
        "# HELP npm_security_threat_events_total Total threat events",
        "# TYPE npm_security_threat_events_total counter",
        _metric_line("npm_security_threat_events_total", threats_total),
        _metric_line("npm_security_blocklist_entries", block_entries),
        _metric_line("npm_security_trusted_entries", trusted_entries),
        _metric_line("npm_security_autoban_total", autoban),
    ]
    for r in status_rows:
        lines.append(_metric_line("npm_security_http_status_total", r["count"], {"status": r["status"]}))
    for r in threat_rows:
        lines.append(_metric_line("npm_security_threat_type_total", r["count"], {"type": r["threat_type"]}))
    for r in tag_rows:
        lines.append(_metric_line("npm_security_threat_tag_total", r["count"], {"tag": r["tag"]}))
    return Response("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")


@router.get("/export/csv", dependencies=[Depends(require_admin)])
def export_csv(kind: str = "logs", limit: int = 10000, min_score: int = 0):
    limit = min(max(limit, 1), CSV_EXPORT_LIMIT)
    output = io.StringIO()
    writer = csv.writer(output)
    with get_db() as conn:
        if kind == "threats":
            rows = conn.execute(
                """
                SELECT te.id, te.created_at, te.ip, te.threat_type, te.score, te.reasons,
                       al.host, al.uri, al.status, al.country_code, al.isp, al.asn
                FROM threat_events te
                LEFT JOIN access_logs al ON al.id = te.access_log_id
                WHERE te.score >= ?
                ORDER BY te.id DESC LIMIT ?
                """,
                [min_score, limit],
            ).fetchall()
        elif kind == "ban-events":
            rows = conn.execute("SELECT * FROM ban_events ORDER BY id DESC LIMIT ?", [limit]).fetchall()
        elif kind == "blocklist":
            rows = conn.execute("SELECT * FROM blocklist ORDER BY id DESC LIMIT ?", [limit]).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, timestamp, ip, country_code, country_name, host, method, uri,
                       status, blocked, threat, isp, asn, request_time
                FROM access_logs ORDER BY id DESC LIMIT ?
                """,
                [limit],
            ).fetchall()
    if rows:
        writer.writerow(rows[0].keys())
        for row in rows:
            writer.writerow([row[k] for k in row.keys()])
    else:
        writer.writerow(["empty"])
    filename = f"npm-security-{kind}-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
    return Response(
        output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/db/backup", dependencies=[Depends(require_admin)])
def backup_database():
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    if not DB_FILE.exists():
        raise HTTPException(status_code=404, detail="Database file not found")
    backup_path = BACKUP_DIR / f"logs-{datetime.now().strftime('%Y%m%d-%H%M%S')}.db"
    with get_db() as conn:
        conn.execute("PRAGMA wal_checkpoint(FULL)")
    shutil.copy2(DB_FILE, backup_path)
    return {"status": "ok", "path": str(backup_path), "size_bytes": backup_path.stat().st_size}


@router.get("/db/backups", dependencies=[Depends(require_admin)])
def list_db_backups():
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    items = []
    for path in sorted(BACKUP_DIR.glob("*.db"), key=lambda p: p.stat().st_mtime, reverse=True):
        st = path.stat()
        items.append({"name": path.name, "path": str(path), "size_bytes": st.st_size, "mtime": datetime.fromtimestamp(st.st_mtime).isoformat()})
    return items[:100]


@router.post("/db/compact", dependencies=[Depends(require_admin)])
def compact_database():
    before = DB_FILE.stat().st_size if DB_FILE.exists() else 0
    with get_db() as conn:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.execute("VACUUM")
        conn.execute("ANALYZE")
    after = DB_FILE.stat().st_size if DB_FILE.exists() else 0
    return {"status": "ok", "before_bytes": before, "after_bytes": after, "saved_bytes": max(before - after, 0)}


@router.post("/db/cleanup", dependencies=[Depends(require_admin)])
def cleanup_database(days: int = None):
    days = DB_RETENTION_DAYS if days is None else min(max(int(days), 1), 3650)
    with get_db() as conn:
        cur = conn.execute("DELETE FROM access_logs WHERE timestamp < datetime('now', ?)", [f"-{days} days"])
        deleted = cur.rowcount
        conn.commit()
    return {"status": "ok", "retention_days": days, "deleted_rows": deleted}


@router.post("/db/purge-logs", dependencies=[Depends(require_admin)])
def purge_saved_logs(
    payload: dict,
    confirmation: str = Header(default="", alias="X-Purge-Confirmation"),
    user: dict = Depends(require_admin),
):
    """Erase stored traffic and derived findings, not NPM's source log file.

    The explicit custom header provides an additional check against cookie
    session CSRF, while the confirmation phrase protects against accidental
    UI clicks. The ingestion cursor is deliberately preserved: historical
    lines must not be replayed after the purge.
    """
    expected = "PURGER"
    if payload.get("confirmation") != expected or confirmation != expected:
        raise HTTPException(
            status_code=422, detail="Saisissez PURGER pour confirmer la suppression",
        )

    tables = (
        "threat_tags",
        "threat_events",
        "observation_alerts",
        "observation_incidents",
        "access_logs",
    )
    deleted = {}
    with get_db() as conn:
        try:
            conn.execute("BEGIN IMMEDIATE")
            for table in tables:
                deleted[table] = conn.execute(f"DELETE FROM {table}").rowcount
            conn.execute(
                """INSERT INTO ban_events(target, type, action, reason)
                   VALUES ('access_logs', 'system', 'PURGE_LOGS', ?)""",
                (
                    f"Admin {user.get('username', 'unknown')}: "
                    f"{deleted['access_logs']} logs, "
                    f"{deleted['threat_events']} detections, "
                    f"{deleted['observation_incidents']} incidents purged",
                ),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    invalidate_stats_cache()
    return {
        "status": "ok",
        "deleted": deleted,
        "preserved": [
            "blocklist", "trusted_entries", "policy_modes", "ban_events",
            "users", "sessions", "ingestion_state",
        ],
        "message": (
            "Historique local supprimé. Les logs Nginx sur disque ne sont "
            "pas touchés et la collecte des nouvelles requêtes continue."
        ),
    }


@router.get("/generate-report", dependencies=[Depends(require_admin)])
async def manual_generate_report():
    try:
        pdf_bytes, stats_dict, report_path = generate_report_file(period_days=30)
        send_discord_with_attachment(DISCORD_WEBHOOK_URL, pdf_bytes, stats_dict)
        return {"status": "ok", "path": str(report_path)}
    except Exception as e:
        return {"error": str(e)}
