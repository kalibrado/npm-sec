
ARG APP_VERSION=1.0.0
FROM python:3.12-slim

ARG APP_VERSION=1.0.0

WORKDIR /app

ENV APP_VERSION=${APP_VERSION} \
  PYTHONUNBUFFERED=1\
  DB_FILE=/data/logs.db\
  LOG_FILE=/logs/access-geo-detailed.log\
  DISCORD_WEBHOOK_URL=""\
  ADMIN_TOKEN=""\
  DEFAULT_ADMIN_USERNAME="admin"\
  DEFAULT_ADMIN_PASSWORD=""\
  SESSION_SECRET=""\
  SESSION_TTL_SECONDS="43200"\
  SESSION_COOKIE_SECURE="false"\
  ALLOWED_ORIGINS="http://localhost:8000"\
  INTERNAL_NETWORKS="127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"\
  EXPORT_DIR="/data/exports"\
  NGINX_RELOAD_ENABLED="false"\
  NGINX_RELOAD_CMD=""\
  AUTO_BAN_ENABLED="false"\
  AUTO_BAN_SCORE="75"\
  AUTO_BAN_EXPORT_APPLY="true"\
  AUTO_BAN_RELOAD="false"\
  DISCORD_THREAT_ALERTS_ENABLED="true"\
  WHOIS_CACHE_TTL_DAYS="7"\
  AUTO_BAN_DRY_RUN="true"\
  PROMETHEUS_METRICS_ENABLED="true"\
  BACKUP_DIR="/data/backups"\
  DB_RETENTION_DAYS="90"\
  CSV_EXPORT_LIMIT="50000"\
  BRUTE_FORCE_WINDOW_MIN="10"\
  BRUTE_FORCE_LOGIN_THRESHOLD="10"

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt\
  && useradd --system --uid 10001 --gid 0 --home-dir /app appuser\
  && mkdir -p /data /data/exports /data/backups /app/reports\
  && chown -R appuser:0 /app /data\
  && chmod -R g=u /app /data

COPY --chown=appuser:0 . .


USER appuser

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
