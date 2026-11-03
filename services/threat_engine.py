import sqlite3

from  services.trust import is_internal_ip


THREAT_PATTERNS = [
    ("scanner", 20, ["wp-login", "xmlrpc.php", "phpmyadmin", "adminer.php", ".git/", ".svn/"]),
    ("secret_discovery", 35, [".env", "config.php", "backup.sql", "dump.sql", "id_rsa", ".aws/credentials"]),
    ("path_traversal", 35, ["../", "..%2f", "%2e%2e", "/etc/passwd", "\\..\\"]),
    ("sql_injection", 40, ["union select", "information_schema", "' or '1'='1", " or 1=1", "sleep(", "benchmark("]),
    ("rce_probe", 45, ["/cgi-bin/", "cmd=", "wget%20", "curl%20", "powershell", "bash -c"]),
]

SCRIPT_USER_AGENTS = ["curl", "python", "go-http-client", "httpclient", "masscan", "nmap", "nikto", "sqlmap", "zgrab"]


def analyze_threat(event: dict, conn: sqlite3.Connection | None = None) -> dict:
    """Calcule un score de menace simple et explicable.

    Score non destructif par défaut : l'auto-block n'est actif que si
    THREAT_AUTO_BLOCK_THRESHOLD > 0. Oui, on évite de bannir la moitié
    d'Internet par enthousiasme algorithmique.
    """
    uri = (event.get("uri") or "").lower()
    ua = (event.get("ua") or event.get("user_agent") or "").lower()
    ip = event.get("ip") or ""
    score = 0
    reasons: list[str] = []
    threat_type = "normal"

    for kind, weight, patterns in THREAT_PATTERNS:
        if any(p in uri for p in patterns):
            score += weight
            threat_type = kind
            reasons.append(kind)

    if not ua or ua in ["-", "_"]:
        score += 5
        reasons.append("empty_user_agent")
    elif any(x in ua for x in SCRIPT_USER_AGENTS):
        score += 15
        reasons.append("script_user_agent")
        if threat_type == "normal":
            threat_type = "script"
    elif "bot" in ua or "crawler" in ua or "spider" in ua:
        score += 3
        reasons.append("bot_user_agent")
        if threat_type == "normal":
            threat_type = "bot"

    status = int(event.get("status") or 0)
    if status in (401, 403, 404, 429, 444):
        score += 5
        reasons.append(f"http_{status}")
    elif status >= 500:
        score += 2
        reasons.append("http_5xx")

    if conn is not None and ip and not is_internal_ip(ip):
        recent = conn.execute(
            """
            SELECT COUNT(*) FROM access_logs
            WHERE ip = ? AND timestamp > datetime('now', '-1 minute')
            """,
            [ip],
        ).fetchone()[0]
        if recent >= 100:
            score += 25
            reasons.append("rate_100_per_min")
            if threat_type == "normal":
                threat_type = "rate_limit"
        elif recent >= 50:
            score += 15
            reasons.append("rate_50_per_min")
            if threat_type == "normal":
                threat_type = "rate_limit"

    return {
        "threat": threat_type if score > 0 else "normal",
        "threat_score": min(score, 100),
        "threat_reasons": reasons,
    }


def classify_threat(uri, ua):
    return analyze_threat({"uri": uri, "ua": ua})["threat"]


def threat_tags_for_event(event: dict) -> list[str]:
    """Tags normalisés pour filtrage UI / Prometheus / rapports."""
    tags = set()
    threat = event.get("threat") or "normal"
    if threat and threat != "normal":
        tags.add(threat)
    for reason in event.get("threat_reasons") or []:
        reason = str(reason).strip().lower().replace(" ", "_")
        if reason:
            tags.add(reason)
    status = int(event.get("status") or 0)
    if status:
        tags.add(f"http_{status}")
        if 400 <= status < 500:
            tags.add("http_4xx")
        if status >= 500:
            tags.add("http_5xx")
    return sorted(tags)[:20]
