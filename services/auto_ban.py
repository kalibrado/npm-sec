import sqlite3

from  config import AUTO_BAN_DRY_RUN, AUTO_BAN_ENABLED, AUTO_BAN_SCORE, AUTO_BAN_DURATION_MINUTES, DISCORD_THREAT_ALERTS_ENABLED, THREAT_AUTO_BLOCK_THRESHOLD
from  services.discord import send_threat_discord_alert
from  services.export import get_blocklist_items, write_blocklist_exports
from  services.nginx import reload_nginx_if_enabled
from  services.trust import is_already_blocked, is_trusted_event


def record_ban_event(conn: sqlite3.Connection, target: str, entry_type: str, action: str, reason: str = ""):
    conn.execute(
        "INSERT INTO ban_events (target, type, action, reason) VALUES (?, ?, ?, ?)",
        [target, entry_type, action.upper(), (reason or "")[:255]],
    )


def maybe_auto_ban(event: dict, conn: sqlite3.Connection) -> bool:
    legacy_enabled = THREAT_AUTO_BLOCK_THRESHOLD > 0
    enabled = AUTO_BAN_ENABLED or legacy_enabled
    threshold = THREAT_AUTO_BLOCK_THRESHOLD if legacy_enabled and not AUTO_BAN_ENABLED else AUTO_BAN_SCORE

    if not enabled:
        return False
    if int(event.get("threat_score") or 0) < threshold:
        return False
    ip = event.get("ip")
    if not ip or is_trusted_event(event, conn) or is_already_blocked(conn, ip):
        return False

    reason = f"Auto-ban: score {event.get('threat_score')} / {event.get('threat')}"
    if AUTO_BAN_DRY_RUN:
        record_ban_event(conn, ip, "ip", "auto-block-dry-run", reason)
        event["auto_block_dry_run"] = True
        send_threat_discord_alert(event, "auto-block-dry-run")
        return False

    conn.execute(
        """INSERT INTO blocklist (type, value, reason, expires_at)
           VALUES ('ip', ?, ?, datetime('now', ?))
           ON CONFLICT(type, value) DO UPDATE SET
             reason=excluded.reason,
             expires_at=excluded.expires_at,
             created_at=datetime('now')""",
        [ip, reason, f"+{AUTO_BAN_DURATION_MINUTES} minutes"],
    )
    record_ban_event(conn, ip, "ip", "auto-block", reason)
    event["auto_blocked"] = True
    send_threat_discord_alert(event, "auto-blocked")
    return True
