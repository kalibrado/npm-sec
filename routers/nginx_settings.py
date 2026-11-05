"""Authenticated HTTP boundary for verified typed Nginx settings drafts.

This router cannot render, publish or reload Nginx configurations.
"""
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from auth_deps import require_admin, require_viewer
from database import get_db
from services.nginx_settings_schema import settings_schema_metadata
from services.nginx_settings_diff import (
    RevisionIntegrityError, RevisionNotFound, compare_settings_revisions,
)
from services.nginx_settings_history import list_settings_revisions
from services.nginx_settings_schema import import_legacy_defaults
from services.nginx_settings_revisions import (
    RevisionConflict, create_settings_revision, latest_settings_revision,
    restore_settings_revision,
)

router = APIRouter(prefix="/api/nginx-settings", tags=["nginx-settings"])


@router.get("/schema", dependencies=[Depends(require_viewer)])
def draft_schema():
    return settings_schema_metadata()


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


class InitialImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    settings: dict
    source_sha256: str = Field(min_length=64, max_length=64)
    reason: str = Field(min_length=1, max_length=1024)
    source_description: str = Field(min_length=1, max_length=512)
    verified_against_source: bool


def _require_same_origin_write(request: Request, intent: str | None, expected_intent: str) -> None:
    if intent != expected_intent:
        raise HTTPException(status_code=403, detail="Missing write intent header")
    fetch_site = request.headers.get("sec-fetch-site", "").lower()
    if fetch_site and fetch_site not in {"same-origin", "none"}:
        raise HTTPException(status_code=403, detail="Cross-origin settings writes forbidden")
    origin = request.headers.get("origin")
    if origin is not None:
        parsed = urlsplit(origin)
        host = request.headers.get("host", "")
        if (parsed.scheme not in {"http", "https"}
                or not parsed.netloc
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path not in {"", "/"}
                or parsed.query or parsed.fragment
                or parsed.netloc.lower() != host.lower()):
            raise HTTPException(status_code=403, detail="Cross-origin settings writes forbidden")


@router.post("/import-initial", status_code=201)
def import_initial_draft(
    payload: InitialImportRequest,
    request: Request,
    admin: dict = Depends(require_admin),
    x_nsd_intent: str | None = Header(default=None),
):
    _require_same_origin_write(request, x_nsd_intent, "import-settings")
    if payload.verified_against_source is not True or not payload.source_description.strip():
        raise HTTPException(status_code=422, detail="Explicit source verification required")
    try:
        imported = import_legacy_defaults(payload.settings, source_sha256=payload.source_sha256)
        with get_db() as conn:
            return {"draft": create_settings_revision(
                conn, imported["settings"], expected_revision=0,
                author=admin["username"],
                reason=f"Initial import from {payload.source_description.strip()}: {payload.reason.strip()}",
                source_sha256=imported["source_sha256"],
            )}
    except RevisionConflict:
        raise HTTPException(status_code=409, detail="Initial revision already exists")
    except RevisionIntegrityError:
        raise HTTPException(status_code=409, detail="Stored settings revision failed integrity checks")
    except (ValueError, TypeError):
        raise HTTPException(status_code=422, detail="Invalid imported settings")


class DraftWriteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    settings: dict
    expected_revision: int = Field(ge=0)
    reason: str = Field(min_length=1, max_length=1024)


@router.post("/revisions", status_code=201)
def write_draft(
    payload: DraftWriteRequest,
    request: Request,
    admin: dict = Depends(require_admin),
    x_nsd_intent: str | None = Header(default=None),
):
    _require_same_origin_write(request, x_nsd_intent, "save-settings")
    if payload.expected_revision == 0:
        raise HTTPException(status_code=409, detail="Initial revision requires verified source import")
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


class DraftRestoreRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_revision: int = Field(ge=1)
    expected_revision: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=1024)


@router.post("/restore", status_code=201)
def restore_draft(
    payload: DraftRestoreRequest,
    request: Request,
    admin: dict = Depends(require_admin),
    x_nsd_intent: str | None = Header(default=None),
):
    _require_same_origin_write(request, x_nsd_intent, "restore-settings")
    if not payload.reason.strip():
        raise HTTPException(status_code=422, detail="Restore reason required")
    try:
        with get_db() as conn:
            return {"draft": restore_settings_revision(
                conn, target_revision=payload.target_revision,
                expected_revision=payload.expected_revision,
                author=admin["username"], reason=payload.reason.strip(),
            )}
    except RevisionNotFound:
        raise HTTPException(status_code=404, detail="Settings revision not found")
    except RevisionConflict:
        raise HTTPException(status_code=409, detail="Settings revision conflict")
    except RevisionIntegrityError:
        raise HTTPException(status_code=409, detail="Stored settings revision failed integrity checks")
    except (ValueError, TypeError):
        raise HTTPException(status_code=422, detail="Invalid restore request")
