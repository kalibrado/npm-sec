"""Read-only diagnostics for the single-process, single-writer NPM log collector.

No raw access-log lines, IPs, URIs, cookies or Nginx configuration are
returned. Runtime counters describe this process only; the SQLite cursor
remains authoritative across restarts and log rotations.
"""
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from config import LOG_FILE
from database import get_db


_lock = threading.Lock()
_runtime = {
    "source_path": None,
    "last_poll_at": None,
    "last_success_at": None,
    "last_error_at": None,
    "last_error_type": None,
    "last_poll_monotonic": None,
    "last_success_monotonic": None,
    "last_error_monotonic": None,
    "polls": 0,
    "lines_read": 0,
    "lines_inserted": 0,
    "lines_invalid": 0,
    "lines_duplicate": 0,
    "last_batch_invalid": 0,
    "missing_file_polls": 0,
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _source_path(path) -> str:
    return str(Path(path).resolve())


def _ensure_source(path: str) -> None:
    if _runtime["source_path"] == path:
        return
    for key in ("last_poll_at", "last_success_at", "last_error_at",
                "last_error_type", "last_poll_monotonic",
                "last_success_monotonic", "last_error_monotonic"):
        _runtime[key] = None
    for key in ("polls", "lines_read", "lines_inserted", "lines_invalid",
                "lines_duplicate", "last_batch_invalid", "missing_file_polls"):
        _runtime[key] = 0
    _runtime["source_path"] = path


def record_cycle(
    log_file,
    *,
    read: int = 0,
    inserted: int = 0,
    invalid: int = 0,
    duplicate: int = 0,
    missing: bool = False,
) -> None:
    path = _source_path(log_file)
    with _lock:
        _ensure_source(path)
        _runtime["polls"] += 1
        _runtime["last_poll_at"] = _now()
        _runtime["last_poll_monotonic"] = time.monotonic()
        _runtime["lines_read"] += read
        _runtime["lines_inserted"] += inserted
        _runtime["lines_invalid"] += invalid
        _runtime["lines_duplicate"] += duplicate
        _runtime["last_batch_invalid"] = invalid
        if missing:
            _runtime["missing_file_polls"] += 1
        else:
            _runtime["last_success_at"] = _now()
            _runtime["last_success_monotonic"] = time.monotonic()
            _runtime["last_error_at"] = None
            _runtime["last_error_type"] = None
            _runtime["last_error_monotonic"] = None


def record_failure(log_file, error: Exception) -> None:
    path = _source_path(log_file)
    with _lock:
        _ensure_source(path)
        _runtime["polls"] += 1
        _runtime["last_poll_at"] = _now()
        _runtime["last_poll_monotonic"] = time.monotonic()
        _runtime["last_error_at"] = _now()
        _runtime["last_error_monotonic"] = time.monotonic()
        # Never expose exception strings: they may contain sensitive paths
        # or request content. Operator can consult container stderr.
        _runtime["last_error_type"] = type(error).__name__


def get_runtime_snapshot(log_file=None) -> dict:
    path = _source_path(log_file or LOG_FILE)
    with _lock:
        if _runtime["source_path"] != path:
            return {
                "polls": 0,
                "lines_read": 0,
                "lines_inserted": 0,
                "lines_invalid": 0,
                "lines_duplicate": 0,
                "last_batch_invalid": 0,
                "missing_file_polls": 0,
                "last_poll_at": None,
                "last_success_at": None,
                "last_error_at": None,
                "last_error_type": None,
                "seconds_since_poll": None,
            }
        snapshot = dict(_runtime)
    elapsed = (
        max(0, round(time.monotonic() - snapshot["last_poll_monotonic"], 1))
        if snapshot["last_poll_monotonic"] is not None else None
    )
    for key in list(snapshot):
        if key.endswith("_monotonic") or key == "source_path":
            del snapshot[key]
    snapshot["seconds_since_poll"] = elapsed
    return snapshot


def get_ingestion_diagnostics(log_file=None) -> dict:
    """Inspect mount, durable cursor and collector counters without writes."""
    path = Path(log_file or LOG_FILE)
    key = _source_path(path)
    stat = None
    file_error = None
    try:
        stat = path.stat()
    except OSError as exc:
        file_error = type(exc).__name__
    exists = stat is not None and path.is_file()
    readable = bool(exists and os.access(path, os.R_OK))
    file_size = stat.st_size if exists else None
    last_write = (
        datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
        if exists else None
    )
    file_age = (
        max(0, round(time.time() - stat.st_mtime, 1))
        if exists else None
    )

    with get_db() as conn:
        row = conn.execute(
            "SELECT physical_id, generation, byte_offset, updated_at "
            "FROM ingestion_state WHERE path=?", (key,),
        ).fetchone()
        total = conn.execute("SELECT COUNT(*) FROM access_logs").fetchone()[0]
        latest = conn.execute(
            "SELECT timestamp FROM access_logs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        sample = conn.execute(
            """SELECT
                   COUNT(*) AS sampled,
                   SUM(CASE WHEN policy_mode IN ('observe','block') AND
                                 would_deny IN (0,1) THEN 1 ELSE 0 END)
                     AS instrumented
               FROM (SELECT policy_mode, would_deny FROM access_logs
                     ORDER BY id DESC LIMIT 200)"""
        ).fetchone()

    cursor = dict(row) if row else None
    runtime = get_runtime_snapshot(path)
    identity = f"{stat.st_dev}:{stat.st_ino}" if exists else None
    rotated = bool(cursor and exists and cursor["physical_id"] != identity)
    truncated = bool(cursor and exists and not rotated and
                     file_size < cursor["byte_offset"])
    backlog = (
        max(file_size - cursor["byte_offset"], 0)
        if cursor and exists and not rotated and not truncated else None
    )
    last_poll_age = runtime["seconds_since_poll"]
    last_error = runtime["last_error_type"]

    if not exists:
        code, level = "file_missing", "error"
        advice = "Vérifier LOG_FILE et le montage Docker du fichier de logs NPM."
    elif not readable:
        code, level = "file_unreadable", "error"
        advice = "Vérifier les permissions de lecture du fichier monté."
    elif last_error:
        code, level = "collector_error", "error"
        advice = "Le collecteur a rencontré une erreur. Consulter les logs du dashboard."
    elif last_poll_age is None:
        code, level = "collector_not_observed", "warning"
        advice = "Aucun cycle observé dans ce processus. Vérifier que la tâche de collecte a démarré."
    elif last_poll_age > 30:
        code, level = "collector_stalled", "error"
        advice = "Aucun cycle récent. Vérifier la tâche de fond et les logs du dashboard."
    elif rotated or truncated:
        code, level = "rotation_pending", "warning"
        advice = "Rotation ou troncature détectée. Le collecteur doit recalculer son curseur au prochain cycle."
    elif runtime["last_batch_invalid"] > 0:
        code, level = "invalid_log_lines", "warning"
        advice = "Des lignes récentes ne sont pas au format JSON NPM attendu. Vérifier log_format et LOG_FILE."
    elif backlog and backlog > 0:
        code, level = "backlog", "warning"
        advice = "Des octets attendent la collecte, éventuellement une ligne JSON partielle."
    elif file_size == 0:
        code, level = "empty_file", "warning"
        advice = "Le collecteur fonctionne, mais le fichier ne contient aucune requête."
    else:
        code, level = "up_to_date", "ok"
        advice = "Fichier accessible et curseur à jour. Zéro trafic récent ne prouve pas une panne."

    return {
        "status": level,
        "code": code,
        "advice": advice,
        "log_file": key,
        "file": {
            "exists": exists,
            "readable": readable,
            "size_bytes": file_size,
            "last_write_at": last_write,
            "seconds_since_write": file_age,
            "stat_error_type": file_error,
        },
        "cursor": {
            "present": cursor is not None,
            "offset_bytes": cursor["byte_offset"] if cursor else None,
            "generation": cursor["generation"] if cursor else None,
            "last_checkpoint_at": cursor["updated_at"] if cursor else None,
            "rotation_pending": rotated,
            "truncation_pending": truncated,
            "backlog_bytes": backlog,
        },
        "runtime": runtime,
        "stored": {
            "total_logs": total,
            "latest_log_timestamp": latest["timestamp"] if latest else None,
            "recent_sample_size": sample["sampled"],
            "instrumented_sample": sample["instrumented"] or 0,
        },
        "scope": "runtime_metrics_since_process_start",
        "note": (
            "Compteurs runtime depuis le démarrage uniquement. "
            "Le curseur SQLite survit aux redémarrages et aux purges. "
            "Aucune ligne de log brute n'est exposée."
        ),
    }
