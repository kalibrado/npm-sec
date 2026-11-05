"""Read-only HTTP boundary for verified typed Nginx settings drafts.

This router cannot render, publish or reload Nginx configurations.
"""
from fastapi import APIRouter, Depends, HTTPException, Query

from auth_deps import require_viewer
from database import get_db
from services.nginx_settings_diff import (
    RevisionIntegrityError, RevisionNotFound, compare_settings_revisions,
)
from services.nginx_settings_history import list_settings_revisions
from services.nginx_settings_revisions import latest_settings_revision

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
