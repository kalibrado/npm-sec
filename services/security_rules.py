"""Validated HTTP path/UA/method security rules.

Rules are compiled to maps rather than accepting arbitrary Nginx snippets.
Their priority applies inside each rule type; multiple types can match the
same request and are logged independently.
"""
import re
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from services.trust import validate_proxy_host

METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"}
KINDS = {"path", "ua", "method"}


def canonical(kind: str, value: str, host: str | None) -> tuple[str, str, str]:
    if kind not in KINDS or not isinstance(value, str):
        raise HTTPException(status_code=422, detail="Type de règle ou valeur invalide")
    value = value.strip()
    host = validate_proxy_host(host)
    if kind == "path":
        if (
            not re.fullmatch(r"/[A-Za-z0-9._/-]{1,160}", value)
            or "//" in value
            or any(segment in (".", "..") for segment in value.split("/"))
        ):
            raise HTTPException(
                status_code=422,
                detail="Préfixe de chemin invalide : utiliser /dossier, sans .., espaces ou paramètres",
            )
    elif kind == "ua":
        value = value.lower()
        if not re.fullmatch(r"[a-z0-9_.-]{2,64}", value):
            raise HTTPException(
                status_code=422,
                detail="Signature UA littérale invalide (2 à 64 caractères)",
            )
    else:
        value = value.upper()
        if value not in METHODS:
            raise HTTPException(status_code=422, detail="Méthode HTTP non autorisée")
    return kind, value, host


def expiration(duration_minutes: int | None) -> str | None:
    if duration_minutes is None or duration_minutes == 0:
        return None
    if type(duration_minutes) is not int or not 1 <= duration_minutes <= 43200:
        raise HTTPException(status_code=422, detail="Durée de règle invalide")
    return (datetime.now(timezone.utc) +
            timedelta(minutes=duration_minutes)).strftime("%Y-%m-%d %H:%M:%S")


def active_rules(conn):
    rows = conn.execute(
        """SELECT id,kind,value,host,priority FROM security_rules
           WHERE enabled=1 AND (expires_at IS NULL OR expires_at > datetime('now'))
           ORDER BY priority DESC,id ASC"""
    ).fetchall()
    return [dict(row) for row in rows]


def _matcher(rule: dict) -> str:
    scope = re.escape(rule["host"]) if rule.get("host") else r"[^:]+"
    value = re.escape(rule["value"])
    if rule["kind"] == "path":
        tail = "" if rule["value"].endswith("/") else r"(?:/|$)"
        return f"~^{scope}:{value}{tail}"
    if rule["kind"] == "ua":
        return f"~*^{scope}:.*{value}"
    return f"~^{scope}:{value}$"


def render_nginx_rule_maps(rules: list[dict]) -> str:
    """Return safe http-context maps for path, UA and method rules.

    Regex matching order follows descending priority and scoped before global
    for ties. Each map returns one rule ID, so different types can report
    matches without forcing any block when NPM SEC is in observe mode.
    """
    sources = {
        "path": ('$host:$uri', 'nsd_rule_path_id'),
        "ua": ('$host:$http_user_agent', 'nsd_rule_ua_id'),
        "method": ('$host:$request_method', 'nsd_rule_method_id'),
    }
    lines = ["# NSD advanced rules, generated from validated database entries."]
    for kind, (source, dest) in sources.items():
        lines.extend([f'map "{source}" ${dest} {{', "    default 0;"])
        relevant = sorted(
            (rule for rule in rules if rule["kind"] == kind),
            key=lambda rule: (-int(rule["priority"]), 0 if rule.get("host") else 1,
                              int(rule["id"])),
        )
        for rule in relevant:
            # Validate even data provided by a call outside the admin API.
            _, normalized, host = canonical(kind, rule["value"], rule.get("host"))
            if normalized != rule["value"] or host != (rule.get("host") or ""):
                raise ValueError("Règle non normalisée")
            number = rule["id"]
            if type(number) is not int or number < 1:
                raise ValueError("ID de règle invalide")
            priority = rule["priority"]
            if type(priority) is not int or not 1 <= priority <= 1000:
                raise ValueError("Priorité de règle invalide")
            lines.append(f"    {_matcher(rule)} {number};")
        lines.append("}")
    lines.extend([
        'map "$nsd_rule_path_id:$nsd_rule_ua_id:$nsd_rule_method_id" $nsd_extra_blocked {',
        "    default 0;",
        "    ~[1-9] 1;",
        "}",
        "",
    ])
    return "\n".join(lines)
