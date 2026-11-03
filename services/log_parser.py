import asyncio
import json
import time
from datetime import datetime, timezone

from  config import ALERT_THRESHOLD, AUTO_BAN_EXPORT_APPLY, AUTO_BAN_RELOAD, DB_RETENTION_DAYS, LOG_FILE
from  database import get_db, invalidate_stats_cache
from  services.auto_ban import maybe_auto_ban
from  services.discord import send_discord_alert
from  services.export import get_blocklist_items, write_blocklist_exports
from  services.nginx import reload_nginx_if_enabled
from  services.threat_engine import analyze_threat, classify_threat, threat_tags_for_event

last_alert_time = 0.0


def parse_line(line: str) -> dict | None:
    try:
        data = json.loads(line.strip())
        ip = data.get("remote_addr", "")
        # if is_internal_ip(ip):
        #     return None
        return {
            "timestamp": data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "ip": ip,
            "country_code": data.get("country_code", "XX"),
            "country_name": data.get("country_name", "Inconnu"),
            "city": data.get("city", "-"),
            "host": data.get("host", "-"),
            "method": data.get("method", "-"),
            "referer": data.get("http_referer", ""),
            "user_agent": data.get("http_user_agent", ""),
            "isp": data.get("isp", "-"),
            "asn": str(data.get("asn", "")),
            "uri": data.get("uri", data.get("request_uri", "")),
            "status": int(data.get("status", 0)),
            "blocked": 1 if data.get("allowed", "yes") == "no" else 0,
            "ua": data.get("http_user_agent", ""),
            "latitude": float(data.get("latitude", 0) or 0),
            "longitude": float(data.get("longitude", 0) or 0),
            "request_time": float(data.get("request_time", 0) or 0),
            "threat": classify_threat(data.get("uri"), data.get("http_user_agent")),
        }
    except (json.JSONDecodeError, ValueError):
        return None


def insert_log(event: dict) -> dict:
    with get_db() as conn:
        threat = analyze_threat(event, conn)
        event.update(threat)
        cur = conn.execute(
            """
            INSERT INTO access_logs
                (timestamp, ip, country_code, country_name, city, isp, asn, method, referer,
                 host, user_agent, uri, status, blocked, ua, latitude, longitude, request_time, threat)
            VALUES
                (:timestamp, :ip, :country_code, :country_name, :city, :isp, :asn, :method,
                 :referer, :host, :user_agent, :uri, :status, :blocked, :ua,
                 :latitude, :longitude, :request_time, :threat)
        """,
            event,
        )
        access_log_id = cur.lastrowid
        event["id"] = access_log_id

        if event.get("threat_score", 0) > 0:
            cur_threat = conn.execute(
                """
                INSERT INTO threat_events (access_log_id, ip, threat_type, score, reasons)
                VALUES (?, ?, ?, ?, ?)
                """,
                [
                    access_log_id,
                    event.get("ip"),
                    event.get("threat"),
                    int(event.get("threat_score") or 0),
                    json.dumps(event.get("threat_reasons") or []),
                ],
            )
            threat_event_id = cur_threat.lastrowid
            for tag in threat_tags_for_event(event):
                conn.execute(
                    "INSERT INTO threat_tags (threat_event_id, tag) VALUES (?, ?)",
                    [threat_event_id, tag],
                )

        auto_banned = maybe_auto_ban(event, conn)
        conn.commit()

        if auto_banned and AUTO_BAN_EXPORT_APPLY:
            # Export after commit so the generated files see the new blocklist row.
            items = get_blocklist_items(conn)
            write_blocklist_exports(items)
            if AUTO_BAN_RELOAD:
                reload_nginx_if_enabled()
    invalidate_stats_cache()
    return event


def import_existing_logs():
    with get_db() as conn:
        count = conn.execute("SELECT COUNT(*) FROM access_logs").fetchone()[0]
    if count > 0:
        print(f"✅ DB existante : {count} entrées")
        return
    if not LOG_FILE.exists():
        return
    print(f"🔄 Import initial depuis {LOG_FILE}…")
    imported = 0
    with open(LOG_FILE, "r") as f, get_db() as conn:
        for line in f:
            event = parse_line(line)
            if not event:
                continue
            conn.execute(
                """
                INSERT INTO access_logs
                    (timestamp, ip, country_code, country_name, city, isp, asn, method, referer,
                     host, user_agent, uri, status, blocked, ua, latitude, longitude, request_time, threat)
                VALUES
                    (:timestamp, :ip, :country_code, :country_name, :city, :isp, :asn, :method,
                     :referer, :host, :user_agent, :uri, :status, :blocked, :ua,
                     :latitude, :longitude, :request_time, :threat)
            """,
                event,
            )
            imported += 1
        conn.commit()
    print(f"✅ {imported} logs importés")


def check_alerts():
    global last_alert_time
    now = time.time()
    if now - last_alert_time < 30:
        return
    with get_db() as conn:
        count = conn.execute(
            """
            SELECT COUNT(*) FROM access_logs
            WHERE blocked=1 AND timestamp > datetime('now','-1 minute')
        """
        ).fetchone()[0]
    if count > ALERT_THRESHOLD:
        last_alert_time = now
        msg = f"🚨 **ALERT NPM Security** : {count} requêtes bloquées en 1 min (seuil : {ALERT_THRESHOLD})"
        print(msg)
        send_discord_alert(msg)


async def cleanup_task():
    while True:
        await asyncio.sleep(3600)
        with get_db() as conn:
            conn.execute(
                "DELETE FROM access_logs WHERE timestamp < datetime('now', ?)",
                [f"-{DB_RETENTION_DAYS} days"],
            )
            conn.commit()
        print("🧹 Cleanup done")


async def tail_log():
    """Follow LOG_FILE and survive logrotate/truncate."""
    last_inode = None
    f = None
    try:
        while True:
            try:
                stat = LOG_FILE.stat()
                if f is None or stat.st_ino != last_inode:
                    if f:
                        f.close()
                    f = open(LOG_FILE, "r")
                    f.seek(0, 2)
                    last_inode = stat.st_ino

                line = f.readline()
                if line:
                    yield line
                else:
                    await asyncio.sleep(0.2)
            except FileNotFoundError:
                if f:
                    f.close()
                    f = None
                    last_inode = None
                await asyncio.sleep(1)
    finally:
        if f:
            f.close()


async def sse_generator():
    async for line in tail_log():
        event = parse_line(line)
        if not event:
            continue
        event = insert_log(event)
        check_alerts()
        yield f"data: {json.dumps(event)}\n\n"
