"""Authenticated HTTP boundary for verified typed Nginx settings drafts.

This router cannot render, publish or reload Nginx configurations.
"""
from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from auth_deps import require_admin, require_viewer
from database import get_db
from services.nginx_settings_diff import (
    RevisionIntegrityError, RevisionNotFound, compare_settings_revisions,
)
from services.nginx_settings_history import list_settings_revisions
from services.nginx_settings_revisions import (
    RevisionConflict, create_settings_revision, latest_settings_revision,
)

router = APIRouter(prefix="/api/nginx-settings", tags=["nginx-settings"])


@router.get("/latest", dependencies=[Depends(require_viewer)])
def latest_draft():
    with get_db() as conn:
        try:
            return {"draft": latest_settings_revision(conn)}
        except RevisionIntegrityError:
            raise HTTPException(status_code=409, detail="Stored settings revision failed integrity checks")


@router.get("/history", dependencies=[Depends(require_viewer)])
def draft_history(
    limit: int = Query(default=50, ge=1, le=100),
    before_revision: int | None = Query(default=None, ge=1),
):
    with get_db() as conn:
        try:
            return {"revisions": list_settings_revisions(
                conn, limit=limit, before_revision=before_revision
            )}
        except (RevisionIntegrityError, ValueError):
            raise HTTPException(status_code=409, detail="Stored settings revision failed integrity checks")


@router.get("/diff", dependencies=[Depends(require_viewer)])
def draft_diff(
    before_revision: int = Query(ge=1),
    after_revision: int = Query(ge=1),
):
    with get_db() as conn:
        try:
            return compare_settings_revisions(conn, before_revision, after_revision)
        except RevisionNotFound:
            raise HTTPException(status_code=404, detail="Settings revision not found")
        except (RevisionIntegrityError, ValueError):
            raise HTTPException(status_code=409, detail="Stored settings revision failed integrity checks")


class DraftWriteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    settings: dict
    expected_revision: int = Field(ge=0)
    reason: str = Field(min_length=1, max_length=1024)


@router.post("/revisions", status_code=201)
def write_draft(
    payload: DraftWriteRequest,
    admin: dict = Depends(require_admin),
    x_nsd_intent: str | None = Header(default=None),
):
    # A required non-safelisted header forces cross-origin browser requests
    # through CORS preflight. Do not allow this header in cross-origin CORS.
    if x_nsd_intent != "save-settings":
        raise HTTPException(status_code=403, detail="Missing write intent header")
    try:
        with get_db() as conn:
            return {"draft": create_settings_revision(
                conn, payload.settings, expected_revision=payload.expected_revision,
                author=admin["username"], reason=payload.reason,
            )}
    except RevisionConflict:
        raise HTTPException(status_code=409, detail="Settings revision conflict")
    except RevisionIntegrityError:
        raise HTTPException(status_code=409, detail="Stored settings revision failed integrity checks")
    except (ValueError, TypeError):
        raise HTTPException(status_code=422, detail="Invalid settings payload")
