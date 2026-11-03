from fastapi import APIRouter, Depends, HTTPException, Query
from datetime import datetime, timedelta, timezone
from fastapi.responses import HTMLResponse

from  auth_deps import require_admin
from  database import get_db
from services.deployment import get_policy_deployment_status
from  schemas import BlockEntry, TrustedEntry
from  services.auto_ban import record_ban_event
from  services.export import get_blocklist_items, get_trusted_items, render_blocklist_json, render_nginx_blocklist, write_blocklist_exports
from  services.nginx import reload_nginx_if_enabled
from  services.trust import assert_safe_manual_block, validate_country_code, validate_ip_or_cidr, validate_trusted_type

router = APIRouter(tags=["blocklist"])


def _expires_at(duration_minutes: int | None) -> str | None:
    if duration_minutes is None:
        return None
    if not 1 <= duration_minutes <= 43200:
        raise HTTPException(status_code=422, detail="duration_minutes must be 1..43200")
    return (datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)).strftime("%Y-%m-%d %H:%M:%S")



def _sync_exports(conn):
    items = get_blocklist_items(conn)
    trusted_items = get_trusted_items(conn)
    return write_blocklist_exports(items, trusted_items)


@router.get("/trusted", dependencies=[Depends(require_admin)])
def list_trusted():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM trusted_entries ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]


@router.post("/trusted", dependencies=[Depends(require_admin)])
def add_trusted(entry: TrustedEntry):
    entry_type, value = validate_trusted_type(entry.type, entry.value)
    with get_db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO trusted_entries (type, value, reason) VALUES (?, ?, ?)",
            [entry_type, value, (entry.reason or "")[:255]],
        )
        record_ban_event(conn, value, entry_type, "trust", entry.reason or "Manual trust entry")
        export_info = _sync_exports(conn)
        conn.commit()
    return {"status": "trusted", "type": entry_type, "value": value}


@router.delete("/trusted/{entry_id}", dependencies=[Depends(require_admin)])
def remove_trusted(entry_id: int):
    with get_db() as conn:
        row = conn.execute("SELECT type, value FROM trusted_entries WHERE id = ?", [entry_id]).fetchone()
        conn.execute("DELETE FROM trusted_entries WHERE id = ?", [entry_id])
        if row:
            record_ban_event(conn, row["value"], row["type"], "untrust", "Manual trusted entry removal")
        export_info = _sync_exports(conn)
        conn.commit()
    return {"status": "deleted", "id": entry_id, "pending_apply": True}


@router.get("/blocklist/deployment", dependencies=[Depends(require_admin)])
def blocklist_deployment():
    return get_policy_deployment_status()


@router.get("/blocklist", dependencies=[Depends(require_admin)])
def list_blocklist():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM blocklist WHERE expires_at IS NULL OR expires_at > datetime('now') ORDER BY created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


@router.post("/blocklist", dependencies=[Depends(require_admin)])
def add_to_blocklist(entry: BlockEntry):
    entry_type = (entry.type or "").strip().lower()
    if entry_type == "country":
        value = validate_country_code(entry.value)
    elif entry_type == "cidr":
        value = validate_ip_or_cidr(entry.value, allow_cidr=True)
    elif entry_type == "ip":
        value = validate_ip_or_cidr(entry.value)
    else:
        raise HTTPException(status_code=400, detail="Invalid blocklist type")

    expiration = _expires_at(entry.duration_minutes)
    try:
        with get_db() as conn:
            assert_safe_manual_block(entry_type, value, conn)
            conn.execute(
                """INSERT INTO blocklist (type, value, reason, expires_at)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(type, value) DO UPDATE SET
                     reason=excluded.reason, expires_at=excluded.expires_at,
                     created_at=datetime('now')""",
                [entry_type, value, (entry.reason or "")[:255], expiration],
            )
            record_ban_event(conn, value, entry_type, "block", entry.reason or "Manual blocklist add")
            export_info = _sync_exports(conn)
            conn.commit()
        return {"status": "ok", "type": entry_type, "value": value, "pending_apply": True}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Unable to update blocklist") from exc


@router.delete("/blocklist/{entry_id}", dependencies=[Depends(require_admin)])
def remove_from_blocklist(entry_id: int):
    with get_db() as conn:
        row = conn.execute("SELECT type, value FROM blocklist WHERE id = ?", [entry_id]).fetchone()
        conn.execute("DELETE FROM blocklist WHERE id = ?", [entry_id])
        if row:
            record_ban_event(conn, row["value"], row["type"], "unblock", "Manual remove via dashboard")
        export_info = _sync_exports(conn)
        conn.commit()
    return {"status": "deleted", "id": entry_id, "pending_apply": True}


@router.post("/block_ip/{ip}", dependencies=[Depends(require_admin)])
def block_ip(ip: str, duration_minutes: int | None = Query(default=None, ge=1, le=43200)):
    ip = validate_ip_or_cidr(ip)
    expiration = _expires_at(duration_minutes)
    try:
        with get_db() as conn:
            assert_safe_manual_block("ip", ip, conn)
            reason = "Manual block via dashboard"
            conn.execute(
                """INSERT INTO blocklist (type, value, reason, expires_at)
                   VALUES ('ip', ?, ?, ?)
                   ON CONFLICT(type, value) DO UPDATE SET
                     reason=excluded.reason, expires_at=excluded.expires_at,
                     created_at=datetime('now')""",
                [ip, reason, expiration],
            )
            record_ban_event(conn, ip, "ip", "block", reason)
            export_info = _sync_exports(conn)
            conn.commit()
        return {"status": "blocked", "ip": ip, "pending_apply": True}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Unable to update blocklist") from exc


@router.post("/block_country/{cc}", dependencies=[Depends(require_admin)])
def block_country(cc: str, duration_minutes: int | None = Query(default=None, ge=1, le=43200)):
    cc = validate_country_code(cc)
    expiration = _expires_at(duration_minutes)
    try:
        with get_db() as conn:
            reason = "Mass block via dashboard"
            conn.execute(
                """INSERT INTO blocklist (type, value, reason, expires_at)
                   VALUES ('country', ?, ?, ?)
                   ON CONFLICT(type, value) DO UPDATE SET
                     reason=excluded.reason, expires_at=excluded.expires_at,
                     created_at=datetime('now')""",
                [cc, reason, expiration],
            )
            record_ban_event(conn, cc, "country", "block", reason)
            export_info = _sync_exports(conn)
            conn.commit()
        # Optionally trigger nginx reload here via subprocess
        return {"status": "blocked", "country": cc, "pending_apply": True}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Unable to update blocklist") from exc


@router.get("/ban-events", dependencies=[Depends(require_admin)])
def ban_events(limit: int = 100):
    limit = min(max(limit, 1), 500)
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM ban_events ORDER BY id DESC LIMIT ?",
            [limit],
        ).fetchall()
    return [dict(r) for r in rows]


@router.get("/blocklist/export/json", dependencies=[Depends(require_admin)])
def export_blocklist_json():
    with get_db() as conn:
        items = get_blocklist_items(conn)
        trusted_items = get_trusted_items(conn)
    return render_blocklist_json(items, trusted_items)


@router.get("/blocklist/export/nginx", dependencies=[Depends(require_admin)])
def export_blocklist_nginx():
    with get_db() as conn:
        items = get_blocklist_items(conn)
        trusted_items = get_trusted_items(conn)
    return HTMLResponse(render_nginx_blocklist(items, trusted_items), media_type="text/plain")


@router.post("/blocklist/export/apply", dependencies=[Depends(require_admin)])
def apply_blocklist_export(reload: bool = False):
    with get_db() as conn:
        items = get_blocklist_items(conn)
        trusted_items = get_trusted_items(conn)
        export_info = write_blocklist_exports(items, trusted_items)
        record_ban_event(conn, "blocklist", "system", "export", f"Exported {len(items)} entries")
        conn.commit()

    reload_info = {"requested": reload, "executed": False, "message": "reload not requested"}
    if reload:
        reload_info = reload_nginx_if_enabled()

    return {
        "status": "ok",
        "export": export_info,
        "reload": reload_info,
    }
