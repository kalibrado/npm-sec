"""Expire temporary bans and refresh exported Nginx policy."""
from database import get_db
from services.auto_ban import record_ban_event
from services.export import (
    get_blocklist_items,
    get_trusted_items,
    write_blocklist_exports,
)


def expire_block_rules() -> int:
    with get_db() as conn:
        expired = conn.execute(
            """SELECT id, type, value FROM blocklist
               WHERE expires_at IS NOT NULL AND expires_at <= datetime('now')"""
        ).fetchall()
        if not expired:
            return 0
        for row in expired:
            conn.execute("DELETE FROM blocklist WHERE id=?", [row["id"]])
            record_ban_event(
                conn, row["value"], row["type"], "expire", "Temporary block expired"
            )
        # Generate from the updated transaction. Failure rolls back the rows,
        # allowing the next scheduler tick to retry rather than leave stale state.
        write_blocklist_exports(get_blocklist_items(conn), get_trusted_items(conn))
        conn.commit()
        return len(expired)
