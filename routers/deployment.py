"""Explicit, audited Nginx deployment jobs for an out-of-process host agent.

The Web UI never runs Docker or executes nginx. The agent gets a fixed,
deterministically generated four-file bundle and reports verified results.
"""
import hmac
import json
import os
import re

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from auth_deps import require_admin
from database import get_db
from services.export import (
    get_blocklist_items, get_trusted_items, get_policy_modes,
    render_nginx_blocklist, render_nginx_server_guard,
)
from services.security_profiles import bundle_hash, load_active, render_profile


router = APIRouter(tags=["deployment"])
SHA256 = re.compile(r"^[a-f0-9]{64}$")


class RequestDeployment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_revision: int = Field(ge=0)
    confirmation: str


class FinishDeployment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str
    bundle_sha256: str
    message: str = Field(default="", max_length=400)


def agent_auth(x_nsd_agent_token: str = Header(default="")):
    # This credential is not exposed to browser users, /config, or /health.
    # Empty/misconfigured token means the agent is disabled by default.
    configured = os.environ.get("NSD_AGENT_TOKEN", "")
    if len(configured) < 32:
        raise HTTPException(status_code=503, detail="Agent désactivé sur NSD")
    if not x_nsd_agent_token or not hmac.compare_digest(
        x_nsd_agent_token, configured
    ):
        raise HTTPException(status_code=401, detail="Identifiants agent invalides")
    return True


def _bundle(conn, settings):
    files = render_profile(settings)
    files["npm-blocklist.conf"] = render_nginx_blocklist(
        get_blocklist_items(conn), get_trusted_items(conn),
        get_policy_modes(conn),
    )
    files["npm-server-guard.conf"] = render_nginx_server_guard()
    return files


@router.post("/security-profile/deployments/request")
def request_deployment(payload: RequestDeployment, user: dict = Depends(require_admin)):
    if payload.confirmation != "APPLIQUER":
        raise HTTPException(status_code=422, detail="Confirmation APPLIQUER requise")
    with get_db() as conn:
        try:
            conn.execute("BEGIN IMMEDIATE")
            revision, values = load_active(conn)
            if payload.expected_revision != revision:
                raise HTTPException(
                    status_code=409,
                    detail="Une nouvelle révision existe : recharger avant de demander l'application",
                )
            pending = conn.execute(
                """SELECT id FROM nsd_deployment_jobs
                   WHERE status IN ('pending','claimed') LIMIT 1"""
            ).fetchone()
            if pending:
                raise HTTPException(
                    status_code=409,
                    detail=f"Une application est déjà en attente (#{pending['id']})",
                )
            files = _bundle(conn, values)
            digest = bundle_hash(files)
            row = conn.execute(
                """INSERT INTO nsd_deployment_jobs
                   (revision,requested_by,bundle_sha256,bundle_json)
                   VALUES (?,?,?,?)""",
                (revision, user["username"], digest,
                 json.dumps(files, sort_keys=True)),
            )
            conn.commit()
            return {
                "status": "pending",
                "id": row.lastrowid,
                "revision": revision,
                "bundle_sha256": digest,
                "message": "Demande enregistrée. Aucune modification NPM exécutée par NSD.",
            }
        except Exception:
            conn.rollback()
            raise


@router.get("/security-profile/deployments", dependencies=[Depends(require_admin)])
def deployment_history():
    with get_db() as conn:
        rows = conn.execute(
            """SELECT id,revision,requested_by,bundle_sha256,status,
                      requested_at,claimed_at,completed_at,reported_hash,result_message
               FROM nsd_deployment_jobs ORDER BY id DESC LIMIT 50"""
        ).fetchall()
    return [dict(r) for r in rows]


@router.post("/agent/deployments/claim", dependencies=[Depends(agent_auth)])
def claim_deployment():
    with get_db() as conn:
        try:
            conn.execute("BEGIN IMMEDIATE")
            # One host-side process owns the token. If it crashed, restarting
            # its local rollback journal comes before the same job is returned.
            row = conn.execute(
                """SELECT * FROM nsd_deployment_jobs
                   WHERE status IN ('claimed','pending')
                   ORDER BY CASE WHEN status='claimed' THEN 0 ELSE 1 END, id
                   LIMIT 1"""
            ).fetchone()
            if not row:
                conn.rollback()
                return {"job": None}
            if row["status"] == "pending":
                conn.execute(
                    """UPDATE nsd_deployment_jobs SET status='claimed',
                       claimed_at=datetime('now') WHERE id=?""",
                    (row["id"],),
                )
            conn.commit()
            return {
                "job": {
                    "id": row["id"],
                    "revision": row["revision"],
                    "bundle_sha256": row["bundle_sha256"],
                    "files": json.loads(row["bundle_json"]),
                }
            }
        except Exception:
            conn.rollback()
            raise


@router.post("/agent/deployments/{job_id}/complete", dependencies=[Depends(agent_auth)])
def finish_deployment(job_id: int, payload: FinishDeployment):
    if payload.status not in {"applied", "failed", "rolled_back"}:
        raise HTTPException(status_code=422, detail="Statut agent non autorisé")
    if not SHA256.fullmatch(payload.bundle_sha256):
        raise HTTPException(status_code=422, detail="Empreinte invalide")
    with get_db() as conn:
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT status,bundle_sha256 FROM nsd_deployment_jobs WHERE id=?",
                (job_id,),
            ).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Demande absente")
            if row["bundle_sha256"] != payload.bundle_sha256:
                raise HTTPException(status_code=409, detail="Empreinte non concordante")
            if row["status"] != "claimed":
                raise HTTPException(status_code=409, detail="Demande non attribuée à l'agent")
            conn.execute(
                """UPDATE nsd_deployment_jobs
                   SET status=?,completed_at=datetime('now'),
                       reported_hash=?,result_message=? WHERE id=?""",
                (payload.status, payload.bundle_sha256 if payload.status == "applied" else None,
                 payload.message.strip(), job_id),
            )
            conn.commit()
            return {"status": payload.status, "id": job_id}
        except Exception:
            conn.rollback()
            raise
