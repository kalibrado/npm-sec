import os
import ipaddress
import secrets
from pathlib import Path
import dotenv

dotenv.load_dotenv(Path(__file__).resolve().parent / ".env")

APP_VERSION = os.getenv("APP_VERSION", "0.5.10.1-dev")
LOG_FILE = Path(os.getenv("LOG_FILE", "/var/log/docker-app/nginx-proxy-manager/access-geo-detailed.log"))
DB_FILE = Path(os.getenv("DB_FILE", "./logs.db"))
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")
ALERT_THRESHOLD = int(os.getenv("ALERT_THRESHOLD", "50"))

# Legacy compatibility: THREAT_AUTO_BLOCK_THRESHOLD still works if AUTO_BAN_* is not set.
THREAT_AUTO_BLOCK_THRESHOLD = int(os.getenv("THREAT_AUTO_BLOCK_THRESHOLD", "0"))
AUTO_BAN_ENABLED = os.getenv("AUTO_BAN_ENABLED", "false").lower() in {"1", "true", "yes", "on"}
AUTO_BAN_SCORE = int(os.getenv("AUTO_BAN_SCORE", str(THREAT_AUTO_BLOCK_THRESHOLD or 75)))
AUTO_BAN_EXPORT_APPLY = os.getenv("AUTO_BAN_EXPORT_APPLY", "true").lower() in {"1", "true", "yes", "on"}
AUTO_BAN_RELOAD = os.getenv("AUTO_BAN_RELOAD", "false").lower() in {"1", "true", "yes", "on"}
AUTO_BAN_DRY_RUN = os.getenv("AUTO_BAN_DRY_RUN", "false").lower() in {"1", "true", "yes", "on"}
DISCORD_THREAT_ALERTS_ENABLED = os.getenv("DISCORD_THREAT_ALERTS_ENABLED", "true").lower() in {"1", "true", "yes", "on"}
WHOIS_CACHE_TTL_DAYS = int(os.getenv("WHOIS_CACHE_TTL_DAYS", "7"))

ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "http://localhost:8000").split(",") if o.strip()]
EXPORT_DIR = Path(os.getenv("EXPORT_DIR", "/data/exports"))
NGINX_RELOAD_CMD = os.getenv("NGINX_RELOAD_CMD", "").strip()
NGINX_RELOAD_ENABLED = os.getenv("NGINX_RELOAD_ENABLED", "false").lower() in {"1", "true", "yes", "on"}

PROMETHEUS_METRICS_ENABLED = os.getenv("PROMETHEUS_METRICS_ENABLED", "true").lower() in {"1", "true", "yes", "on"}
BACKUP_DIR = Path(os.getenv("BACKUP_DIR", "/data/backups"))
DB_RETENTION_DAYS = int(os.getenv("DB_RETENTION_DAYS", "90"))
CSV_EXPORT_LIMIT = int(os.getenv("CSV_EXPORT_LIMIT", "50000"))
BRUTE_FORCE_WINDOW_MIN = int(os.getenv("BRUTE_FORCE_WINDOW_MIN", "10"))
BRUTE_FORCE_LOGIN_THRESHOLD = int(os.getenv("BRUTE_FORCE_LOGIN_THRESHOLD", "10"))

# Web auth / sessions
SESSION_SECRET = os.getenv("SESSION_SECRET", ADMIN_TOKEN or secrets.token_urlsafe(32))
SESSION_COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "npm_sec_session")
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", str(60 * 60 * 12)))
SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "false").lower() in {"1", "true", "yes", "on"}
DEFAULT_ADMIN_USERNAME = os.getenv("DEFAULT_ADMIN_USERNAME", "admin")
DEFAULT_ADMIN_PASSWORD = os.getenv("DEFAULT_ADMIN_PASSWORD", "")

_INTERNAL_NETWORKS_RAW = os.getenv("INTERNAL_NETWORKS", "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
INTERNAL_NETWORKS = []
for item in _INTERNAL_NETWORKS_RAW.split(','):
    item = item.strip()
    if not item:
        continue
    try:
        INTERNAL_NETWORKS.append(ipaddress.ip_network(item, strict=False))
    except ValueError:
        print(f"⚠️ Ignoring invalid INTERNAL_NETWORKS entry: {item}")