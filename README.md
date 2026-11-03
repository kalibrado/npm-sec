# NPM Security Dashboard

Dashboard FastAPI pour surveiller les logs de Nginx Proxy Manager, détecter les comportements suspects, gérer une blocklist/trusted list, exporter une configuration Nginx et envoyer des alertes Discord.

Version pack prod : `0.6.0-prod`.

## Installation rapide Docker Compose

```bash
cp .env.example .env
make secrets
nano .env
make init
make build
make up
make logs
```

Ouvre ensuite :

```text
http://IP_DU_SERVEUR:8000
```

L'utilisateur admin initial est créé avec :

```env
DEFAULT_ADMIN_USERNAME=admin
DEFAULT_ADMIN_PASSWORD=...
```

Ne laisse pas les valeurs `CHANGE_ME_*`, sinon l'application refuse de démarrer en mode production.

## Variables importantes

| Variable | Rôle |
|---|---|
| `NPM_LOGS_PATH` | Chemin host du dossier logs NPM monté en lecture seule |
| `LOG_FILE` | Chemin du fichier log dans le conteneur, par défaut `/logs/access-geo-detailed.log` |
| `DB_FILE` | Base SQLite, par défaut `/data/logs.db` |
| `EXPORT_DIR` | Exports `blocklist.json` et `npm-blocklist.conf` |
| `BACKUP_DIR` | Backups SQLite |
| `ALLOWED_ORIGINS` | URL autorisées par CORS |
| `SESSION_COOKIE_SECURE` | `true` derrière HTTPS |
| `AUTO_BAN_DRY_RUN` | `true` conseillé au début |

## Volumes

```yaml
./data:/data
${NPM_LOGS_PATH}:/logs:ro
```

Le dossier `/data` contient :

```text
data/
├── logs.db
├── backups/
├── reports/
└── exports/
    ├── blocklist.json
    └── npm-blocklist.conf
```

## Commandes utiles

```bash
make ps
make logs
make smoke
make backup
make restore BACKUP=./data/backups/logs-YYYYmmdd-HHMMSS.db
make down
```

## Smoke test

```bash
BASE_URL=http://localhost:8000 ADMIN_TOKEN=<token> ./scripts/smoke-test.sh
```

Le `ADMIN_TOKEN` reste accepté pour les scripts/API, même si l'UI utilise les sessions web.

## Reverse proxy NPM

Configuration recommandée dans Nginx Proxy Manager :

```text
Forward Hostname/IP : IP_DU_SERVEUR_DOCKER
Forward Port        : 8000
Websockets Support  : activé
Block Common Exploits : activé
SSL : Let's Encrypt
```

Dans `.env` :

```env
ALLOWED_ORIGINS=https://npm-security.example.com
SESSION_COOKIE_SECURE=true
```

Voir aussi `docs/NPM_REVERSE_PROXY.md`.

## Exports de blocage

Le dashboard écrit :

```text
/data/exports/blocklist.json
/data/exports/npm-blocklist.conf
```

Par défaut, le reload Nginx est désactivé :

```env
NGINX_RELOAD_ENABLED=false
NGINX_RELOAD_CMD=
```

C'est volontaire : exécuter des commandes reload depuis un dashboard web doit rester une action explicitement contrôlée.

## Sécurité production

Le conteneur est lancé avec :

- utilisateur non-root `10001`
- filesystem read-only
- `cap_drop: ALL`
- `no-new-privileges`
- logs Docker avec rotation
- healthcheck Docker
- validation des secrets au startup

Checklist :

```text
[ ] DEFAULT_ADMIN_PASSWORD changé
[ ] SESSION_SECRET généré avec openssl rand -hex 32
[ ] ADMIN_TOKEN généré avec openssl rand -hex 32
[ ] ALLOWED_ORIGINS fixé à ton domaine
[ ] SESSION_COOKIE_SECURE=true si HTTPS
[ ] AUTO_BAN_DRY_RUN=true pour la première phase
[ ] NPM_LOGS_PATH correct
[ ] make smoke OK
```

## Dev local

```bash
cp .env.dev.example .env
./start-dev.sh
```

Le port dev par défaut est `8010`.
