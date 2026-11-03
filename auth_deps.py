import hmac
from datetime import datetime, timezone
from typing import Optional
from fastapi import Cookie, Depends, Header, HTTPException

from  config import ADMIN_TOKEN, SESSION_COOKIE_NAME
from  database import get_db
from  security import hash_session_token, utcnow


def _safe_user(row) -> dict:
    return {
        "id": row["id"],
        "username": row["username"],
        "role": row["role"],
        "created_at": row["created_at"],
        "last_login": row["last_login"],
        "enabled": bool(row["enabled"]),
    }


def get_current_user(
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
    x_admin_token: str = Header(default=""),
):
    # Legacy API token remains accepted for curl/automation during migration.
    if ADMIN_TOKEN and x_admin_token and hmac.compare_digest(x_admin_token, ADMIN_TOKEN):
        return {"id": 0, "username": "admin-token", "role": "admin", "legacy_token": True}

    if not session_token:
        raise HTTPException(status_code=401, detail="Authentication required")

    token_hash = hash_session_token(session_token)
    with get_db() as conn:
        row = conn.execute(
            """
            SELECT u.id, u.username, u.role, u.created_at, u.last_login, u.enabled, s.expires_at
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ? AND u.enabled = 1
            LIMIT 1
            """,
            [token_hash],
        ).fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="Invalid session")
        try:
            expires = datetime.fromisoformat(row["expires_at"])
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if expires < utcnow():
                conn.execute("DELETE FROM sessions WHERE token_hash = ?", [token_hash])
                conn.commit()
                raise HTTPException(status_code=401, detail="Session expired")
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid session")
        return _safe_user(row)


def require_admin(user: dict = Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return user


def require_viewer(user: dict = Depends(get_current_user)):
    return user
