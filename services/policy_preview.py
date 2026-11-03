"""Non-destructive evaluation of saved NPM Security policy.

This evaluates only the currently stored rules. It neither changes SQLite,
nor writes exports, nor asserts that the policy is live in the NPM process.
"""
import ipaddress
import sqlite3

from config import INTERNAL_NETWORKS
from services.trust import validate_country_code, validate_ip_or_cidr, validate_proxy_host


def evaluate_saved_policy(
    conn: sqlite3.Connection,
    ip: str,
    host: str,
    country_code: str | None = None,
) -> dict:
    ip = validate_ip_or_cidr(ip)
    scope = validate_proxy_host(host)
    if not scope:
        from fastapi import HTTPException
        raise HTTPException(status_code=422, detail="host is required for policy preview")

    country = validate_country_code(country_code) if country_code else None
    address = ipaddress.ip_address(ip)

    trusted_matches = []
    for network in INTERNAL_NETWORKS:
        if address in network:
            trusted_matches.append({
                "type": "internal_network", "value": str(network),
            })
    for row in conn.execute(
        "SELECT type, value FROM trusted_entries WHERE type IN ('ip', 'cidr')"
    ).fetchall():
        try:
            network = ipaddress.ip_network(row["value"], strict=False)
        except ValueError:
            continue
        if address in network:
            trusted_matches.append({"type": row["type"], "value": row["value"]})

    candidate_rules = conn.execute(
        """SELECT id, type, value, host, reason, expires_at
           FROM blocklist
           WHERE host IN ('', ?)
             AND (expires_at IS NULL OR expires_at > datetime('now'))
           ORDER BY CASE WHEN host = '' THEN 0 ELSE 1 END, id""",
        [scope],
    ).fetchall()

    matches = []
    country_rules_unresolved = False
    for rule in candidate_rules:
        data = dict(rule)
        if rule["type"] in ("ip", "cidr"):
            try:
                net = ipaddress.ip_network(rule["value"], strict=False)
            except ValueError:
                continue
            if address in net:
                matches.append(data)
        elif rule["type"] == "country":
            if country is None:
                country_rules_unresolved = True
            elif rule["value"].upper() == country:
                matches.append(data)

    trusted = bool(trusted_matches)
    if trusted:
        predicted = "allow"
    elif matches:
        predicted = "deny"
    elif country_rules_unresolved:
        predicted = "unknown"
    else:
        predicted = "allow"

    return {
        "ip": ip,
        "host": scope,
        "country_code": country,
        "predicted_decision": predicted,
        "trusted": trusted,
        "trusted_matches": trusted_matches,
        "matching_block_rules": matches,
        "requires_country": country_rules_unresolved and not trusted and not matches,
        "source": "stored_rules_only",
    }
