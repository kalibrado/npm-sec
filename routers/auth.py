import secrets
import sqlite3
from datetime import timedelta
from typing import Optional

from fastapi import APIRouter, Cookie, Depends, HTTPException, Response

from  auth_deps import get_current_user, require_admin, _safe_user
from  config import SESSION_COOKIE_NAME, SESSION_COOKIE_SECURE, SESSION_TTL_SECONDS
from  database import get_db
from  schemas import LoginRequest, UserCreate, UserPasswordUpdate
from  security import hash_session_token, pbkdf2_password, utcnow, verify_password

router = APIRouter(tags=["auth"])


@router.post("/auth/login")
def auth_login(payload: LoginRequest, response: Response):
    username = (payload.username or "").strip()
    password = payload.password or ""
    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")

    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ? AND enabled = 1", [username]).fetchone()
        if not row or not verify_password(password, row["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        token = secrets.token_urlsafe(32)
        expires = utcnow() + timedelta(seconds=SESSION_TTL_SECONDS)
        conn.execute(
            "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
            [row["id"], hash_session_token(token), expires.isoformat()],
        )
        conn.execute("UPDATE users SET last_login = ? WHERE id = ?", [utcnow().isoformat(), row["id"]])
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", [utcnow().isoformat()])
        conn.commit()

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=SESSION_COOKIE_SECURE,
        samesite="lax",
        path="/",
    )
    return {"status": "ok", "user": _safe_user(row)}


@router.post("/auth/logout")
def auth_logout(response: Response, session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME)):
    if session_token:
        with get_db() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", [hash_session_token(session_token)])
            conn.commit()
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return {"status": "logged_out"}


@router.get("/auth/me")
def auth_me(user: dict = Depends(get_current_user)):
    return {"authenticated": True, "user": user}


@router.get("/users", dependencies=[Depends(require_admin)])
def list_users():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, username, role, enabled, created_at, last_login FROM users ORDER BY username"
        ).fetchall()
    return [_safe_user(r) for r in rows]


@router.post("/users", dependencies=[Depends(require_admin)])
def create_user(payload: UserCreate):
    username = (payload.username or "").strip()
    role = (payload.role or "viewer").strip().lower()
    if role not in {"admin", "viewer"}:
        raise HTTPException(status_code=400, detail="Invalid role")
    if not username or len(username) > 64 or len(payload.password or "") < 8:
        raise HTTPException(status_code=400, detail="Invalid username or password too short")
    with get_db() as conn:
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                [username, pbkdf2_password(payload.password), role],
            )
            conn.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="User already exists")
    return {"status": "created", "username": username, "role": role}


@router.post("/users/{user_id}/password", dependencies=[Depends(require_admin)])
def update_user_password(user_id: int, payload: UserPasswordUpdate):
    if len(payload.password or "") < 8:
        raise HTTPException(status_code=400, detail="Password too short")
    with get_db() as conn:
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", [pbkdf2_password(payload.password), user_id])
        conn.execute("DELETE FROM sessions WHERE user_id = ?", [user_id])
        conn.commit()
    return {"status": "updated", "id": user_id}




@router.post("/users/{user_id}/enable", dependencies=[Depends(require_admin)])
def enable_user(user_id: int):
    with get_db() as conn:
        row = conn.execute("SELECT id FROM users WHERE id = ?", [user_id]).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        conn.execute("UPDATE users SET enabled = 1 WHERE id = ?", [user_id])
        conn.commit()
    return {"status": "enabled", "id": user_id}


@router.delete("/users/{user_id}/hard")
def hard_delete_user(user_id: int, user: dict = Depends(require_admin)):
    if user_id == user.get("id"):
        raise HTTPException(status_code=400, detail="Cannot delete current user")
    with get_db() as conn:
        row = conn.execute("SELECT id FROM users WHERE id = ?", [user_id]).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        conn.execute("DELETE FROM sessions WHERE user_id = ?", [user_id])
        conn.execute("DELETE FROM users WHERE id = ?", [user_id])
        conn.commit()
    return {"status": "deleted", "id": user_id}

@router.delete("/users/{user_id}")
def delete_user(user_id: int, user: dict = Depends(require_admin)):
    if user_id == user.get("id"):
        raise HTTPException(status_code=400, detail="Cannot delete current user")
    with get_db() as conn:
        conn.execute("UPDATE users SET enabled = 0 WHERE id = ?", [user_id])
        conn.execute("DELETE FROM sessions WHERE user_id = ?", [user_id])
        conn.commit()
    return {"status": "disabled", "id": user_id}
