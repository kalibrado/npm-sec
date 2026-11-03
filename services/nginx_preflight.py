"""Read-only checks for a generated NPM Security Nginx configuration dump.

No Nginx process, Docker container, configuration file or database is
modified here. The output is intentionally limited to derived checks:
never echo Nginx's entire configuration or customer request logs.
"""
import re


def _is_present(config: str, expression: str) -> bool:
    return bool(re.search(expression, config, re.IGNORECASE | re.MULTILINE))


def _log_formats(config: str) -> dict[str, str]:
    return {
        match.group(1): match.group(2)
        for match in re.finditer(
            r"\blog_format\s+([a-zA-Z0-9_-]+)\s+([^;]*);",
            config,
            re.MULTILINE | re.DOTALL,
        )
    }


def _active_log_formats(config: str) -> set[str]:
    active = set()
    for match in re.finditer(r"\baccess_log\s+([^;\n]+);", config):
        tokens = match.group(1).split()
        if len(tokens) >= 2 and tokens[0] != "off":
            active.add(tokens[1])
    return active


def analyze_nginx_dump(config_dump: str, *, geoip_db_readable: bool | None = None) -> dict:
    """Assess NPM Security's effective *configuration*, not runtime traffic.

    A successful `nginx -T` proves the configuration can be parsed, but
    this inspection cannot prove that a valid country lookup or request
    reaches the intended NPM server. Both require live recipe tests.
    """
    # Drop full-line comments (including nginx -T file headers).
    config = re.sub(r"(?m)^\s*#.*$", "", config_dump)
    checks = []

    def add(key: str, ok: bool | None, description: str, *, required=True):
        checks.append({
            "id": key,
            "status": "pass" if ok is True else "fail" if ok is False else "warning",
            "required": required,
            "description": description,
        })

    policy_include = _is_present(
        config,
        r"\binclude\s+\S*/npm-security/npm-blocklist\.conf\s*;",
    )
    guard_include = _is_present(
        config,
        r"\binclude\s+\S*/npm-security/npm-server-guard\.conf\s*;",
    )
    add("http_policy_include", policy_include, "Include HTTP de la politique NPM Security")
    add("server_guard_include", guard_include, "Include de garde dans les serveurs proxy")
    add(
        "policy_variables",
        _is_present(config, r"\$npm_security_would_deny\b")
        and _is_present(config, r"\$npm_security_policy_mode\b")
        and _is_present(config, r"\$npm_security_deny\b"),
        "Variables de décision NPM Security présentes dans Nginx",
    )

    formats = _log_formats(config)
    active_names = _active_log_formats(config)
    needed = (
        '"timestamp"', '"remote_addr"', '"host"',
        '"npm_security_policy_mode"', '"npm_security_would_deny"',
    )
    valid_formats = {
        name for name, body in formats.items()
        if "escape=json" in body
        and all(field in body for field in needed)
        and "$npm_security_policy_mode" in body
        and "$npm_security_would_deny" in body
    }
    active_instrumented = bool(valid_formats & active_names)
    add(
        "instrumented_access_log",
        active_instrumented,
        "Un access_log actif utilise un format JSON avec IP, domaine, horodatage et variables Observe",
    )

    country_policy = _is_present(config, r"\bmap\s+\$geoip2_data_country_code\b")
    country_source = re.search(
        r"\bgeoip2\s+(\S+\.mmdb)\s*\{[^}]*\$geoip2_data_country_code\b",
        config, re.MULTILINE | re.DOTALL,
    )
    if country_policy:
        add(
            "geoip2_country_variable",
            country_source is not None,
            "GeoIP2 fournit bien la variable ISO du pays utilisée par les politiques",
        )
        add(
            "geoip2_database",
            geoip_db_readable,
            "Base GeoIP2 Country lisible depuis le conteneur NPM",
        )
    else:
        add(
            "geoip2_country_variable",
            None,
            "Aucune règle pays détectée dans la configuration chargée, GeoIP2 non exigé",
            required=False,
        )

    realip_configured = _is_present(config, r"\breal_ip_header\s+\S+\s*;")
    trusted_proxies = _is_present(config, r"\bset_real_ip_from\s+\S+\s*;")
    add(
        "real_client_ip_review",
        None,
        (
            "Vérifier manuellement l'IP cliente et les proxies de confiance : "
            + ("directives real_ip présentes" if realip_configured and trusted_proxies
               else "directives real_ip absentes ou partielles, selon topologie")
        ),
        required=False,
    )
    ready = all(item["status"] == "pass" for item in checks if item["required"])
    return {
        "ready_for_log_integration": (
            policy_include and guard_include and active_instrumented
        ),
        "ready_for_country_policy": not country_policy or (
            country_source is not None and geoip_db_readable is True
        ),
        "required_checks_pass": ready,
        "country_rules_detected": country_policy,
        "source": "nginx_configuration_dump_only",
        "checks": checks,
        "limits": (
            "Diagnostic en lecture seule. Ne prouve pas la geolocalisation réelle, "
            "la réception des logs par le dashboard, l'identité IP derrière un CDN "
            "ni le comportement des requêtes. Aucun nginx reload."
        ),
    }
