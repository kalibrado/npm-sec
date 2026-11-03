import sqlite3

from config import BRUTE_FORCE_WINDOW_MIN, BRUTE_FORCE_LOGIN_THRESHOLD

from  services.trust import is_internal_ip


THREAT_PATTERNS = [
    ("scanner", 20, ["wp-login", "xmlrpc.php", "phpmyadmin", "adminer.php", ".git/", ".svn/"]),
    ("secret_discovery", 35, [".env", "config.php", "backup.sql", "dump.sql", "id_rsa", ".aws/credentials"]),
    ("path_traversal", 35, ["../", "..%2f", "%2e%2e", "/etc/passwd", "\\..\\"]),
    ("sql_injection", 40, ["union select", "information_schema", "' or '1'='1", " or 1=1", "sleep(", "benchmark("]),
    ("rce_probe", 45, ["/cgi-bin/", "cmd=", "wget%20", "curl%20", "powershell", "bash -c"]),
]

SCRIPT_USER_AGENTS = ["curl", "python", "go-http-client", "httpclient", "masscan", "nmap", "nikto", "sqlmap", "zgrab"]

LOGIN_URI_MARKERS = ("/login", "/signin", "/auth/", "wp-login", "/session", "/oauth/token")
SCAN_WINDOW_MIN = 2
SCAN_UNIQUE_URI_THRESHOLD = 12
SCAN_DENIED_THRESHOLD = 10


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
        host = event.get("host") or ""
        recent = conn.execute(
            """SELECT COUNT(*) FROM access_logs
               WHERE ip=? AND host=? AND datetime(timestamp) > datetime('now','-1 minute')""",
            [ip, host],
        ).fetchone()[0]
        if recent >= 100:
            score += 25
            reasons.append("rate_100_per_min")
            if threat_type in {"normal", "bot", "script"}:
                threat_type = "rate_limit"
        elif recent >= 50:
            score += 15
            reasons.append("rate_50_per_min")
            if threat_type in {"normal", "bot", "script"}:
                threat_type = "rate_limit"

        # Repeated failed authentication against the same protected host.
        # Cross-host traffic is not merged: one IP may serve many NAT users.
        if status in (401, 403, 429) and any(x in uri for x in LOGIN_URI_MARKERS):
            failed = conn.execute(
                """SELECT COUNT(*) FROM access_logs
                   WHERE ip=? AND host=? AND status IN (401,403,429)
                     AND datetime(timestamp) > datetime('now', ?)
                     AND (lower(uri) LIKE '%login%' OR lower(uri) LIKE '%signin%'
                          OR lower(uri) LIKE '%auth/%' OR lower(uri) LIKE '%session%'
                          OR lower(uri) LIKE '%oauth/token%')""",
                [ip, host, f"-{BRUTE_FORCE_WINDOW_MIN} minutes"],
            ).fetchone()[0]
            if failed + 1 >= BRUTE_FORCE_LOGIN_THRESHOLD:
                score += 60
                reasons.append("brute_force_login_failures")
                threat_type = "brute_force"

        # Only classify an HTTP path scan when both path diversity and denied
        # responses are high. Scanning TCP/UDP ports is out of scope for NPM logs.
        if status in (403, 404) and threat_type != "brute_force":
            summary = conn.execute(
                """SELECT COUNT(DISTINCT uri) AS unique_paths,
                          SUM(CASE WHEN status IN (403,404) THEN 1 ELSE 0 END) AS denied
                   FROM (
                       SELECT uri, status FROM access_logs
                       WHERE ip=? AND host=? AND datetime(timestamp) > datetime('now', ?)
                       UNION ALL SELECT ? AS uri, ? AS status
                   )""",
                [ip, host, f"-{SCAN_WINDOW_MIN} minutes", uri, status],
            ).fetchone()
            distinct_paths = summary["unique_paths"] or 0
            denied = summary["denied"] or 0
            if distinct_paths >= SCAN_UNIQUE_URI_THRESHOLD and denied >= SCAN_DENIED_THRESHOLD:
                score += 55
                reasons.append("http_path_enumeration")
                if threat_type in {"normal", "bot", "script", "rate_limit", "scanner"}:
                    threat_type = "scanner"

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
