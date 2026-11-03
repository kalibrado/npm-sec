# Nginx Proxy Manager - Reverse proxy

## Proxy Host

Dans NPM, crée un Proxy Host :

```text
Domain Names        : npm-security.example.com
Scheme              : http
Forward Hostname/IP : IP_DU_SERVEUR_DOCKER
Forward Port        : 8000
Websockets Support  : ON
Block Common Exploits : ON
```

## SSL

Active Let's Encrypt et force SSL si le domaine est public.

Dans `.env` côté dashboard :

```env
ALLOWED_ORIGINS=https://npm-security.example.com
SESSION_COOKIE_SECURE=true
```

## Headers utiles

NPM transmet déjà les headers classiques. Le Dockerfile lance Uvicorn avec :

```text
--proxy-headers --forwarded-allow-ips *
```

Donc l'application tient compte des headers proxy transmis par NPM.

## Logs NPM

Le dashboard attend par défaut :

```text
/logs/access-geo-detailed.log
```

Ce chemin correspond au montage Compose :

```yaml
- ${NPM_LOGS_PATH}:/logs:ro
```

Adapte `NPM_LOGS_PATH` dans `.env` au chemin host réel.
