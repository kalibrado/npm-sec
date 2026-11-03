import os
from pathlib import Path

from fastapi import APIRouter, Depends

from auth_deps import require_admin
from config import (
    APP_VERSION,
    DB_FILE,
    LOG_FILE,
    EXPORT_DIR,
    BACKUP_DIR,
    DISCORD_WEBHOOK_URL,
    ALERT_THRESHOLD,
    AUTO_BAN_ENABLED,
    AUTO_BAN_SCORE,
    AUTO_BAN_DRY_RUN,
    AUTO_BAN_EXPORT_APPLY,
    AUTO_BAN_RELOAD,
    DISCORD_THREAT_ALERTS_ENABLED,
    WHOIS_CACHE_TTL_DAYS,
    PROMETHEUS_METRICS_ENABLED,
    DB_RETENTION_DAYS,
    CSV_EXPORT_LIMIT,
    BRUTE_FORCE_WINDOW_MIN,
    BRUTE_FORCE_LOGIN_THRESHOLD,
    NGINX_RELOAD_CMD,
    NGINX_RELOAD_ENABLED,
    THREAT_AUTO_BLOCK_THRESHOLD,
    ALLOWED_ORIGINS,
)
from database import get_db
from scheduler import scheduler

router = APIRouter(tags=["health"])
SCHEDULER = scheduler


def _path_writable(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".write-test"
        probe.write_text("ok")
        probe.unlink(missing_ok=True)
        return True
    except Exception:
        return False


def _health_details():
    db_ok = False
    db_size = 0
    try:
        with get_db() as conn:
            conn.execute("SELECT 1").fetchone()
        db_ok = True
        db_size = DB_FILE.stat().st_size if DB_FILE.exists() else 0
    except Exception:
        db_ok = False

    log_file_exists = LOG_FILE.exists()
    log_file_readable = os.access(LOG_FILE, os.R_OK) if log_file_exists else False
    export_dir_writable = _path_writable(EXPORT_DIR)
    backup_dir_writable = _path_writable(BACKUP_DIR)
    scheduler_running = bool(getattr(SCHEDULER, "running", False))
    status = (
        "ok"
        if all([db_ok, log_file_exists, log_file_readable, export_dir_writable])
        else "degraded"
    )

    return {
        "status": status,
        "version": APP_VERSION,
        "db_ok": db_ok,
        "db_file": str(DB_FILE),
        "db_size_bytes": db_size,
        "log_file": str(LOG_FILE),
        "log_file_exists": log_file_exists,
        "log_file_readable": log_file_readable,
        "export_dir": str(EXPORT_DIR),
        "export_dir_writable": export_dir_writable,
        "backup_dir": str(BACKUP_DIR),
        "backup_dir_writable": backup_dir_writable,
        "scheduler_running": scheduler_running,
        "admin_enabled": True,
        "auth_mode": "session",
        "discord_configured": bool(DISCORD_WEBHOOK_URL),
    }


@router.get("/health")
def health():
    details = _health_details()
    return {"status": details["status"], "version": APP_VERSION}


@router.get("/health/details", dependencies=[Depends(require_admin)])
def health_details():
    return _health_details()


@router.get("/version")
def version():
    return {
        "name": "NPM Security Dashboard",
        "version": APP_VERSION,
        "auto_ban_enabled": AUTO_BAN_ENABLED or THREAT_AUTO_BLOCK_THRESHOLD > 0,
        "auto_ban_score": AUTO_BAN_SCORE,
        "auto_ban_dry_run": AUTO_BAN_DRY_RUN,
        "whois_cache_ttl_days": WHOIS_CACHE_TTL_DAYS,
        "prometheus_metrics_enabled": PROMETHEUS_METRICS_ENABLED,
        "db_retention_days": DB_RETENTION_DAYS,
        "auth_mode": "session",
    }


@router.get("/config", dependencies=[Depends(require_admin)])
def runtime_config():
    return {
        "version": APP_VERSION,
        "db_file": str(DB_FILE),
        "log_file": str(LOG_FILE),
        "export_dir": str(EXPORT_DIR),
        "allowed_origins": ALLOWED_ORIGINS,
        "admin_enabled": True,
        "auth_mode": "session",
        "discord_configured": bool(DISCORD_WEBHOOK_URL),
        "discord_threat_alerts_enabled": DISCORD_THREAT_ALERTS_ENABLED,
        "alert_threshold": ALERT_THRESHOLD,
        "auto_ban_enabled": AUTO_BAN_ENABLED or THREAT_AUTO_BLOCK_THRESHOLD > 0,
        "auto_ban_score": AUTO_BAN_SCORE,
        "auto_ban_dry_run": AUTO_BAN_DRY_RUN,
        "auto_ban_export_apply": AUTO_BAN_EXPORT_APPLY,
        "auto_ban_reload": AUTO_BAN_RELOAD,
        "nginx_reload_enabled": NGINX_RELOAD_ENABLED,
        "nginx_reload_configured": bool(NGINX_RELOAD_CMD),
        "whois_cache_ttl_days": WHOIS_CACHE_TTL_DAYS,
        "prometheus_metrics_enabled": PROMETHEUS_METRICS_ENABLED,
        "backup_dir": str(BACKUP_DIR),
        "db_retention_days": DB_RETENTION_DAYS,
        "csv_export_limit": CSV_EXPORT_LIMIT,
        "brute_force_window_min": BRUTE_FORCE_WINDOW_MIN,
        "brute_force_login_threshold": BRUTE_FORCE_LOGIN_THRESHOLD,
    }


@router.get("/npm-health", dependencies=[Depends(require_admin)])
def npm_health(limit: int = 10):
    limit = min(max(limit, 1), 50)
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM access_logs").fetchone()[0]
        errors = conn.execute(
            "SELECT COUNT(*) FROM access_logs WHERE status >= 500"
        ).fetchone()[0]
        top_status = conn.execute(
            """
            SELECT status, COUNT(*) as count
            FROM access_logs
            WHERE status >= 400
            GROUP BY status
            ORDER BY count DESC
            LIMIT ?
            """,
            [limit],
        ).fetchall()
        errors_by_host = conn.execute(
            """
            SELECT host, COUNT(*) as total,
                   SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END) as server_errors,
                   SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) as http_errors,
                   MAX(timestamp) as last_seen
            FROM access_logs
            WHERE host IS NOT NULL AND host != ''
            GROUP BY host
            HAVING http_errors > 0
            ORDER BY server_errors DESC, http_errors DESC
            LIMIT ?
            """,
            [limit],
        ).fetchall()
        errors_by_uri = conn.execute(
            """
            SELECT uri, host, status, COUNT(*) as count, MAX(timestamp) as last_seen
            FROM access_logs
            WHERE status >= 500 AND uri IS NOT NULL AND uri != ''
            GROUP BY host, uri, status
            ORDER BY count DESC
            LIMIT ?
            """,
            [limit],
        ).fetchall()
    return {
        "total": total,
        "server_errors": errors,
        "server_error_rate": round((errors / total) * 100, 2) if total else 0,
        "top_error_statuses": [dict(r) for r in top_status],
        "errors_by_host": [dict(r) for r in errors_by_host],
        "errors_by_uri": [dict(r) for r in errors_by_uri],
    }
