"""Versioned, validated NSD security settings and deterministic Nginx previews.

The database is authoritative for editable settings. Preview rendering never
touches an active Nginx configuration; deployment requires a separate agent.
"""
import difflib
import hashlib
import ipaddress
import json
import re
from pathlib import Path

from fastapi import HTTPException

from database import get_db

ROOT = Path(__file__).resolve().parents[1]
PROFILE_DIR = ROOT / "config" / "nginx-managed"

FIELDS = {
    "rate_limit_rps": {
        "type": "integer", "default": 100, "min": 1, "max": 1000,
        "label": "Requêtes par seconde et par IP",
        "description": "Quota partagé, défini au niveau HTTP. Défaut historique 100 req/s.",
    },
    "rate_limit_burst": {
        "type": "integer", "default": 70, "min": 1, "max": 300,
        "label": "Burst de requêtes",
        "description": "Tolérance des rafales avant réponse 429. Défaut historique 70.",
    },
    "allowed_countries": {
        "type": "countries", "default": ["FR"],
        "label": "Pays autorisés par le filtre historique",
        "description": "Codes ISO alpha-2 séparés par virgules (par défaut FR).",
    },
    "local_allowed_networks": {
        "type": "cidrs", "default": ["127.0.0.1/32", "192.168.1.0/24"],
        "label": "Réseaux autorisés en dérogation géographique",
        "description": "Boucle locale et LAN; conserver un accès d'administration local.",
    },
    "scanner_user_agents": {
        "type": "tokens",
        "default": [
            "masscan", "zgrab", "nikto", "sqlmap", "nmap", "libredtail",
            "nuclei", "dirbuster", "gobuster",
        ],
        "label": "Signatures User-Agent à refuser",
        "description": "Mots simples (sans expressions régulières), séparés par virgules.",
    },
    "legacy_country_filter_enabled": {
        "type": "boolean", "default": True,
        "label": "Activer le filtre géographique historique",
        "description": "Refus des pays non autorisés, sauf réseaux locaux de confiance.",
    },
    "block_empty_user_agent": {
        "type": "boolean", "default": True,
        "label": "Refuser les User-Agents vides",
        "description": "Préserve l'ancienne protection contre les UA absents.",
    },
    "legacy_refusal_status": {
        "type": "choice", "default": "444", "choices": ["444", "403"],
        "label": "Code de refus des filtres historiques",
        "description": "444 ferme la connexion sans réponse; 403 est un refus HTTP standard.",
    },
}
DEFAULTS = {key: field["default"] for key, field in FIELDS.items()}


def normalize_settings(raw: dict) -> dict:
    if not isinstance(raw, dict) or set(raw) != set(FIELDS):
        raise HTTPException(status_code=422, detail="Tous les champs connus sont requis, sans champs supplémentaires")
    normalized = {}
    for name, spec in FIELDS.items():
        value = raw[name]
        kind = spec["type"]
        if kind == "integer":
            if type(value) is not int or not spec["min"] <= value <= spec["max"]:
                raise HTTPException(status_code=422, detail=f"{name}: entier entre {spec['min']} et {spec['max']}")
        elif kind == "boolean":
            if type(value) is not bool:
                raise HTTPException(status_code=422, detail=f"{name}: booléen attendu")
        elif kind == "choice":
            if value not in spec["choices"] or type(value) is not str:
                raise HTTPException(status_code=422, detail=f"{name}: choix non autorisé")
        else:
            if not isinstance(value, list) or len(value) > 40 or any(not isinstance(x, str) for x in value):
                raise HTTPException(status_code=422, detail=f"{name}: tableau de chaînes limité à 40")
            if len(set(value)) != len(value):
                raise HTTPException(status_code=422, detail=f"{name}: doublon interdit")
            clean = []
            for item in value:
                if not item or len(item) > 65:
                    raise HTTPException(status_code=422, detail=f"{name}: valeur vide ou trop longue")
                if kind == "countries":
                    item = item.upper()
                    if not re.fullmatch(r"[A-Z]{2}", item):
                        raise HTTPException(status_code=422, detail=f"{name}: code pays ISO alpha-2 invalide")
                elif kind == "cidrs":
                    try:
                        network = ipaddress.ip_network(item, strict=False)
                    except ValueError:
                        raise HTTPException(status_code=422, detail=f"{name}: CIDR invalide")
                    if network.prefixlen == 0:
                        raise HTTPException(status_code=422, detail=f"{name}: réseau universel interdit")
                    item = str(network)
                elif kind == "tokens":
                    if not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", item):
                        raise HTTPException(status_code=422, detail=f"{name}: signature simple attendue")
                clean.append(item)
            if len(clean) != len(set(clean)):
                raise HTTPException(status_code=422, detail=f"{name}: doublons après normalisation")
            value = clean
        normalized[name] = value

    networks = [ipaddress.ip_network(item) for item in normalized["local_allowed_networks"]]
    for address in ("127.0.0.1", "192.168.1.5"):
        if not any(ipaddress.ip_address(address) in network for network in networks):
            raise HTTPException(
                status_code=422,
                detail=f"Accès de secours {address} obligatoire dans local_allowed_networks",
            )
    return normalized


def render_profile(settings: dict) -> dict[str, str]:
    s = normalize_settings(settings)
    http = (PROFILE_DIR / "http-security.conf").read_text(encoding="utf-8")
    server = (PROFILE_DIR / "server-security.conf").read_text(encoding="utf-8")

    def swap(text, start, end, replacement):
        a = text.find(start)
        b = text.find(end, a + len(start))
        if a == -1 or b == -1 or b <= a:
            raise RuntimeError(f"Profil Nginx inattendu: section {start}")
        return text[:a] + replacement + "\n" + text[b:]

    http = http.replace("rate=100r/s;", f"rate={s['rate_limit_rps']}r/s;")
    server = server.replace("burst=70 nodelay;", f"burst={s['rate_limit_burst']} nodelay;")
    server = server.replace("return 444;", f"return {s['legacy_refusal_status']};")

    networks = "\n".join(f"    {network} yes;" for network in s["local_allowed_networks"])
    http = swap(
        http, "geo $allowed_ip {", "map $geoip2_data_country_code $allowed_country {",
        "geo $allowed_ip {\n    default no;\n" + networks + "\n}",
    )
    country_entries = "\n".join(f"    {country} yes;" for country in s["allowed_countries"])
    if s["legacy_country_filter_enabled"]:
        map_body = "    default $allowed_ip;" + ("\n" + country_entries if country_entries else "")
    else:
        map_body = "    default yes;"
    http = swap(
        http, "map $geoip2_data_country_code $allowed_country {",
        "map $http_user_agent $blocked_agent {",
        "map $geoip2_data_country_code $allowed_country {\n" + map_body + "\n}",
    )
    agents = "\n".join(f"    ~*{token} 1;" for token in s["scanner_user_agents"])
    http = swap(
        http, "map $http_user_agent $blocked_agent {",
        "map $http_user_agent $npm_security_empty_ua {",
        "map $http_user_agent $blocked_agent {\n    default 0;" +
        ("\n" + agents if agents else "") + "\n}",
    )
    http = swap(
        http, "map $http_user_agent $npm_security_empty_ua {",
        "# Preserve existing trust boundaries",
        "map $http_user_agent $npm_security_empty_ua {\n    default 0;\n" +
        ('    "" 1;\n' if s["block_empty_user_agent"] else "") + "}",
    )
    return {
        "http-security.conf": http,
        "server-security.conf": server,
    }


def bundle_hash(files: dict[str, str]) -> str:
    h = hashlib.sha256()
    for name in sorted(files):
        h.update(name.encode("utf-8"))
        h.update(b"\0")
        h.update(files[name].encode("utf-8"))
    return h.hexdigest()


def preview_settings(values: dict) -> dict:
    candidate = render_profile(values)
    current = render_profile(load_active()[1])
    return {
        "candidate_sha256": bundle_hash(candidate),
        "changed_files": [
            name for name in candidate if candidate[name] != current[name]
        ],
        "diff": {
            name: "".join(difflib.unified_diff(
                current[name].splitlines(keepends=True),
                candidate[name].splitlines(keepends=True),
                fromfile=f"enregistré/{name}", tofile=f"candidat/{name}",
            ))[:18000]
            for name in candidate
        },
        "validation": "schéma_et_rendu_uniquement",
        "deployment": "non_appliqué",
        "warning": "Ce preview ne lance PAS nginx -t et ne recharge PAS NPM.",
    }


def load_active(conn=None):
    if conn is not None:
        row = conn.execute(
            "SELECT id, payload FROM security_profile_revisions ORDER BY id DESC LIMIT 1"
        ).fetchone()
    else:
        with get_db() as db:
            row = db.execute(
                "SELECT id, payload FROM security_profile_revisions ORDER BY id DESC LIMIT 1"
            ).fetchone()
    if not row:
        return 0, normalize_settings(DEFAULTS)
    return row["id"], json.loads(row["payload"])


def history(limit=20):
    with get_db() as conn:
        rows = conn.execute(
            """SELECT id, created_by, note, created_at, parent_revision, hash
               FROM security_profile_revisions ORDER BY id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def save_settings(raw, expected_revision: int, author: str, note: str, restore_from=None):
    values = normalize_settings(raw)
    if type(expected_revision) is not int or expected_revision < 0:
        raise HTTPException(status_code=422, detail="expected_revision invalide")
    if not isinstance(note, str) or not 5 <= len(note.strip()) <= 240:
        raise HTTPException(status_code=422, detail="Motif d'au moins 5 caractères requis (240 max)")
    with get_db() as conn:
        try:
            conn.execute("BEGIN IMMEDIATE")
            current_id, current = load_active(conn)
            if current_id != expected_revision:
                raise HTTPException(
                    status_code=409,
                    detail="La configuration a changé. Recharger la page avant d'enregistrer.",
                )
            if values == current:
                raise HTTPException(status_code=409, detail="Aucun changement à enregistrer")
            payload = json.dumps(values, sort_keys=True, ensure_ascii=False)
            digest = bundle_hash(render_profile(values))
            cur = conn.execute(
                """INSERT INTO security_profile_revisions
                   (payload, hash, created_by, note, parent_revision)
                   VALUES (?, ?, ?, ?, ?)""",
                (payload, digest, author[:80], note.strip(), restore_from or current_id),
            )
            conn.commit()
            return {"revision": cur.lastrowid, "hash": digest, "status": "draft_pending"}
        except Exception:
            conn.rollback()
            raise


def rollback_settings(target: int, expected_revision: int, author: str):
    with get_db() as conn:
        row = conn.execute(
            "SELECT payload FROM security_profile_revisions WHERE id=?",
            (target,),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Révision inexistante")
    return save_settings(
        json.loads(row["payload"]), expected_revision, author,
        f"Restauration de la révision {target}", restore_from=target,
    )
