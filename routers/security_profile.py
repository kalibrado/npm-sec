"""Authenticated admin API for NSD's editable, versioned security settings.

Writes only immutable revisions in SQLite. There is deliberately no Nginx
reload or Docker operation in this router.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from auth_deps import require_admin
from services.security_profiles import (
    DEFAULTS,
    FIELDS,
    history,
    load_active,
    normalize_settings,
    preview_settings,
    rollback_settings,
    save_settings,
)


router = APIRouter(prefix="/security-profile", tags=["security-profile"])


class PreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    settings: dict


class SaveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    settings: dict
    expected_revision: int = Field(ge=0)
    note: str = Field(default="", max_length=240)


class RollbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_revision: int = Field(ge=0)


@router.get("", dependencies=[Depends(require_admin)])
def get_profile():
    revision, values = load_active()
    return {
        "revision": revision,
        "settings": values,
        "schema": FIELDS,
        "defaults": DEFAULTS,
        "history": history(20),
        "deployment": {
            "state": "not_applied_by_agent",
            "message": (
                "Modifications enregistrées en base. L'agent de validation "
                "et d'application n'est pas encore activé : NPM reste inchangé."
            ),
        },
    }


@router.post("/preview", dependencies=[Depends(require_admin)])
def preview_profile(payload: PreviewRequest):
    values = normalize_settings(payload.settings)
    return preview_settings(values)


@router.post("/revisions")
def save_profile(payload: SaveRequest, admin: dict = Depends(require_admin)):
    return save_settings(
        payload.settings, payload.expected_revision, admin.get("username", "admin"),
        payload.note,
    )


@router.get("/revisions", dependencies=[Depends(require_admin)])
def list_revisions():
    return history(100)


@router.get("/revisions/{revision}", dependencies=[Depends(require_admin)])
def read_revision(revision: int):
    if revision <= 0:
        raise HTTPException(status_code=404, detail="Révision inexistante")
    from database import get_db
    import json
    with get_db() as conn:
        row = conn.execute(
            """SELECT id, payload, hash, created_by, note, parent_revision, created_at
               FROM security_profile_revisions WHERE id=?""",
            (revision,),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Révision inexistante")
    return {
        **{key: row[key] for key in row.keys() if key != "payload"},
        "settings": json.loads(row["payload"]),
    }


@router.post("/revisions/{revision}/restore")
def restore_profile(
    revision: int, payload: RollbackRequest,
    admin: dict = Depends(require_admin),
):
    if revision <= 0:
        raise HTTPException(status_code=404, detail="Révision inexistante")
    return rollback_settings(
        revision, payload.expected_revision, admin.get("username", "admin"),
    )
