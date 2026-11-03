"""Admin-editable, versioned path/UA/method rules with audit and TTL."""
import json
import sqlite3
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from typing import Literal

from auth_deps import require_admin, require_viewer
from database import get_db
from services.security_rules import canonical, expiration


router = APIRouter(prefix="/security-rules", tags=["security-rules"])


class RuleInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["path", "ua", "method"]
    value: str = Field(min_length=1, max_length=200, strict=True)
    host: str = Field(default="", max_length=253, strict=True)
    priority: int = Field(default=100, ge=1, le=1000, strict=True)
    enabled: bool = Field(default=True, strict=True)
    duration_minutes: int | None = Field(default=None, ge=0, le=43200, strict=True)
    reason: str = Field(min_length=5, max_length=255, strict=True)


class RuleUpdate(RuleInput):
    expected_version: int = Field(ge=1, strict=True)


def _prepare(payload: RuleInput):
    kind, value, host = canonical(payload.kind, payload.value, payload.host)
    reason = payload.reason.strip()
    if not 5 <= len(reason) <= 255:
        raise HTTPException(status_code=422, detail="Motif explicite obligatoire (5 à 255 caractères)")
    return kind, value, host, reason


def _record(conn, actor, action, rule_id, before=None, after=None):
    conn.execute(
        """INSERT INTO security_rule_audit
           (rule_id,action,actor,before_json,after_json)
           VALUES (?,?,?,?,?)""",
        (
            rule_id, action, actor,
            json.dumps(before, ensure_ascii=False) if before is not None else None,
            json.dumps(after, ensure_ascii=False) if after is not None else None,
        ),
    )


@router.get("", dependencies=[Depends(require_viewer)])
def list_rules():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM security_rules ORDER BY enabled DESC,priority DESC,id ASC"
        ).fetchall()
    return [dict(row) for row in rows]


@router.get("/audit", dependencies=[Depends(require_admin)])
def rule_audit():
    with get_db() as conn:
        rows = conn.execute(
            """SELECT id,rule_id,action,actor,before_json,after_json,created_at
               FROM security_rule_audit ORDER BY id DESC LIMIT 100"""
        ).fetchall()
    return [dict(row) for row in rows]


@router.post("", dependencies=[Depends(require_admin)])
def create_rule(payload: RuleInput, user: dict = Depends(require_admin)):
    kind, value, host, reason = _prepare(payload)
    expiry = expiration(payload.duration_minutes)
    with get_db() as conn:
        existing = conn.execute("SELECT COUNT(*) FROM security_rules").fetchone()[0]
        if existing >= 500:
            raise HTTPException(status_code=422, detail="Limite de 500 règles atteinte")
        try:
            cur = conn.execute(
                """INSERT INTO security_rules
                   (kind,value,host,priority,enabled,reason,expires_at,created_by)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (kind, value, host, payload.priority, int(payload.enabled),
                 reason, expiry, user["username"]),
            )
            row = conn.execute("SELECT * FROM security_rules WHERE id=?", (cur.lastrowid,)).fetchone()
            _record(conn, user["username"], "create", row["id"], after=dict(row))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.rollback()
            raise HTTPException(status_code=409, detail="Règle déjà existante pour cette portée")
    return {**dict(row), "pending_apply": True}


@router.put("/{rule_id}", dependencies=[Depends(require_admin)])
def edit_rule(rule_id: int, payload: RuleUpdate, user: dict = Depends(require_admin)):
    kind, value, host, reason = _prepare(payload)
    with get_db() as conn:
        old = conn.execute("SELECT * FROM security_rules WHERE id=?", (rule_id,)).fetchone()
        if not old:
            raise HTTPException(status_code=404, detail="Règle inexistante")
        if old["version"] != payload.expected_version:
            raise HTTPException(status_code=409, detail="La règle a été modifiée : actualiser la liste")
        expiry = (
            expiration(payload.duration_minutes)
            if "duration_minutes" in payload.model_fields_set and payload.duration_minutes is not None
            else old["expires_at"]
        )
        semantic_change = (
            (kind, value, host) !=
            (old["kind"], old["value"], old["host"])
        )
        hits = 0 if semantic_change else old["match_count"]
        try:
            conn.execute(
                """UPDATE security_rules
                   SET kind=?,value=?,host=?,priority=?,enabled=?,reason=?,
                       expires_at=?,match_count=?,version=version+1,
                       updated_at=datetime('now')
                   WHERE id=? AND version=?""",
                (
                    kind, value, host, payload.priority, int(payload.enabled),
                    reason, expiry, hits, rule_id, payload.expected_version,
                ),
            )
            row = conn.execute("SELECT * FROM security_rules WHERE id=?", (rule_id,)).fetchone()
            _record(conn, user["username"], "update", rule_id, dict(old), dict(row))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.rollback()
            raise HTTPException(status_code=409, detail="Conflit avec une autre règle")
    return {**dict(row), "pending_apply": True}


@router.delete("/{rule_id}", dependencies=[Depends(require_admin)])
def delete_rule(rule_id: int, user: dict = Depends(require_admin)):
    with get_db() as conn:
        old = conn.execute("SELECT * FROM security_rules WHERE id=?", (rule_id,)).fetchone()
        if not old:
            raise HTTPException(status_code=404, detail="Règle inexistante")
        conn.execute("DELETE FROM security_rules WHERE id=?", (rule_id,))
        _record(conn, user["username"], "delete", rule_id, dict(old))
        conn.commit()
    return {"status": "deleted", "id": rule_id, "pending_apply": True}
