"""Typed, non-executable settings boundary for future Nginx profile revisions.

This module deliberately does not generate or apply Nginx configuration.
Legacy defaults must be imported from verified historical configuration, not guessed.
"""
from __future__ import annotations

from ipaddress import ip_network
from typing import Any

SCHEMA_VERSION = 1
MAX_RULES = 512
MAX_CIDRS = 256

# The initial scope is deliberately narrow. New settings require explicit
# validators; unknown keys must never silently become Nginx directives.
_FIELDS = {
    "auto_ban_enabled": bool,
    "country_block_enabled": bool,
    "blocked_countries": list,
    "trusted_proxy_cidrs": list,
    "rate_limit_rps": int,
    "rate_limit_burst": int,
}


class SettingsValidationError(ValueError):
    pass


def _unique_strings(value: list[Any], field: str, limit: int) -> list[str]:
    if len(value) > limit:
        raise SettingsValidationError(f"{field}: too many entries")
    if any(not isinstance(item, str) for item in value):
        raise SettingsValidationError(f"{field}: expected strings")
    if len(set(value)) != len(value):
        raise SettingsValidationError(f"{field}: duplicate entries")
    return value


def validate_settings(settings: Any) -> dict[str, Any]:
    """Return canonical JSON-compatible settings, without modifying input."""
    if not isinstance(settings, dict):
        raise SettingsValidationError("settings: expected object")
    unknown = set(settings) - set(_FIELDS)
    if unknown:
        raise SettingsValidationError("unknown settings: " + ", ".join(sorted(map(str, unknown))))
    missing = set(_FIELDS) - set(settings)
    if missing:
        raise SettingsValidationError("missing settings: " + ", ".join(sorted(missing)))
    for key, expected in _FIELDS.items():
        value = settings[key]
        if type(value) is not expected:
            raise SettingsValidationError(f"{key}: expected {expected.__name__}")

    countries = _unique_strings(settings["blocked_countries"], "blocked_countries", MAX_RULES)
    if any(len(code) != 2 or not code.isascii() or not code.isalpha() or code != code.upper() for code in countries):
        raise SettingsValidationError("blocked_countries: expected ISO alpha-2 uppercase codes")

    cidrs = _unique_strings(settings["trusted_proxy_cidrs"], "trusted_proxy_cidrs", MAX_CIDRS)
    normalized = []
    for cidr in cidrs:
        try:
            network = ip_network(cidr, strict=True)
        except ValueError as exc:
            raise SettingsValidationError("trusted_proxy_cidrs: invalid CIDR") from exc
        if network.prefixlen == 0:
            raise SettingsValidationError("trusted_proxy_cidrs: trusting all addresses is forbidden")
        if str(network) != cidr:
            raise SettingsValidationError("trusted_proxy_cidrs: noncanonical CIDR")
        normalized.append(str(network))
    if len(set(normalized)) != len(normalized):
        raise SettingsValidationError("trusted_proxy_cidrs: duplicate CIDR")

    rate = settings["rate_limit_rps"]
    burst = settings["rate_limit_burst"]
    if not 1 <= rate <= 100000:
        raise SettingsValidationError("rate_limit_rps: out of range")
    if not 0 <= burst <= 100000:
        raise SettingsValidationError("rate_limit_burst: out of range")
    return {**settings, "blocked_countries": list(countries), "trusted_proxy_cidrs": normalized}


def import_legacy_defaults(values: Any, *, source_sha256: str) -> dict[str, Any]:
    """Validate explicit imported values and preserve provenance.

    No historical values are synthesized. Caller must extract them from
    verified http_top.conf/server_proxy.conf before persisting a revision.
    """
    if not isinstance(source_sha256, str) or len(source_sha256) != 64 or any(c not in "0123456789abcdef" for c in source_sha256):
        raise SettingsValidationError("source_sha256: expected lowercase SHA-256")
    return {"schema_version": SCHEMA_VERSION, "source_sha256": source_sha256, "settings": validate_settings(values)}


# Public metadata for the draft editor. Defaults intentionally remain unset
# until verified legacy http_top.conf/server_proxy.conf values are imported.
_FIELD_METADATA = {
    "auto_ban_enabled": ("boolean", "Activer les bans automatiques", "Désactivé tant que la politique n'est pas validée."),
    "country_block_enabled": ("boolean", "Blocage par pays", "Active la politique de pays configurée."),
    "blocked_countries": ("countries", "Pays bloqués", "Codes ISO 3166-1 alpha-2 majuscules, sans doublons."),
    "trusted_proxy_cidrs": ("cidrs", "Proxys de confiance", "Réseaux CIDR canoniques autorisés pour real IP."),
    "rate_limit_rps": ("integer", "Limite de requêtes par seconde", "Entier entre 1 et 100000."),
    "rate_limit_burst": ("integer", "Rafale autorisée", "Entier entre 0 et 100000."),
}


def settings_schema_metadata() -> dict[str, Any]:
    """Describe editable fields without fabricating historical defaults."""
    return {
        "schema_version": SCHEMA_VERSION,
        "legacy_defaults_imported": False,
        "fields": {
            key: {
                "type": _FIELD_METADATA[key][0],
                "label": _FIELD_METADATA[key][1],
                "description": _FIELD_METADATA[key][2],
                "required": True,
                **({"min": 1, "max": 100000} if key == "rate_limit_rps" else {}),
                **({"min": 0, "max": 100000} if key == "rate_limit_burst" else {}),
                **({"max_items": MAX_RULES} if key == "blocked_countries" else {}),
                **({"max_items": MAX_CIDRS} if key == "trusted_proxy_cidrs" else {}),
            }
            for key in _FIELDS
        },
    }
