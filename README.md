# NPM Security Dashboard

Dashboard FastAPI pour surveiller les logs de Nginx Proxy Manager, détecter les comportements suspects, gérer une blocklist/trusted list, exporter une configuration Nginx et envoyer des alertes Discord.

Version pack prod : `0.6.0-prod`.

## Installation rapide Docker Compose

```bash
cp .env.example .env
make secrets
nano .env
make init
# Si make init indique un problème de permissions :
# sudo chown -R 10001:0 data
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

## Investigation des IP suspectes

L'onglet « Listes de sécurité » présente désormais un classement des IP
suspectes avec filtres de période (1 h, 24 h, 7 j) et de score minimal.
L'API authentifiée `GET /security-control/suspects` expose le nombre de
signaux, le score maximum, les détections de brute force/scans HTTP et le
contexte de confiance ou de blocage **enregistré**.

Depuis le tableau, un administrateur peut ouvrir une fiche IP, enregistrer
un bannissement temporaire d'une heure, ajouter une IP de confiance ou
retirer un blocage direct. Les actions exigent confirmation et sont
journalisées via les API existantes. Une IP couverte uniquement par un CIDR
doit être gérée dans la liste des règles ; supprimer un blocage direct ne
supprime pas une interdiction CIDR plus large.

**Important :** aucun score ne prouve à lui seul une attaque et
l'enregistrement d'un bannissement ne signifie pas qu'il est déjà appliqué
par Nginx Proxy Manager. Les réseaux internes et les IP explicitement
de confiance ne proposent pas d'action de blocage depuis cette vue.

## Centre de contrôle de sécurité

La page **Listes de sécurité** présente un aperçu vérifiable des dernières
24 heures via l'API authentifiée `GET /security-control/overview?hours=24`.
Le périmètre peut être adapté de 1 à 168 heures avec le paramètre `hours`.

- Règles IP/CIDR/pays **enregistrées** et non expirées, séparées des exceptions.
- Requêtes réellement déclarées `blocked` dans les logs NPM.
- Événements de menace classifiés `brute_force` et `scanner`.
- Mode du bannissement automatique : désactivé / simulation / actif.
- État de politique `not_configured`, `pending`, `applied` fondé sur
  la **dernière** validation et recharge de l'outil d'application NPM.

Une politique `applied` ne signifie **pas** une surveillance continue de
l'instance NPM si quelqu'un modifie le proxy en dehors du script. De même,
une règle enregistrée en base n'est pas automatiquement un blocage effectif.

## Ingestion continue des logs (branche dev)

La collecte ne dépend plus d'un navigateur ouvert : un ingesteur serveur unique lit le fichier NPM, mémorise sa position en SQLite et tolère les rotations/troncatures observées. Le SSE (`/events`) est désormais un flux **lecture seule** avec reprise par `since_id`. Les insertions portent une clé d'origine unique pour éviter les doublons après crash.

**Important :** l'application doit rester sur **un seul worker Uvicorn** avec cette architecture. Un cluster nécessite un verrou d'ingestion distribué ou un worker distinct. Lors d'une migration depuis une base existante sans curseur, l'ingesteur démarre à la fin du fichier courant, pour éviter de doubler les données historiques ; ce choix peut laisser des événements anciens non importés.

## Authentification des API

Les endpoints contenant des logs, des profils IP, des statistiques détaillées, des règles et des métriques exigent désormais une session authentifiée ou le header `X-Admin-Token`. Cela inclut `/events`, `/stats`, `/history`, `/widget` et `/metrics`. Un widget Homepage ou Prometheus doit donc être configuré avec un accès de service approprié ; les accès publics anonymes ne fonctionnent plus.

`/health` renvoie seulement `status` et `version` pour le healthcheck. Les détails internes sont sous `/health/details` (admin).

Avec `APP_ENV=production`, un `SESSION_SECRET` robuste (32 caractères minimum) est obligatoire. L'initialisation d'un premier admin exige `DEFAULT_ADMIN_PASSWORD`, sans mot de passe de repli. Les variables de `.env.example` sont alignées sur les volumes Docker : `/data` et `/logs`.

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

## Modes de protection : Observation et Blocage

Le centre de contrôle expose désormais le mode **Blocage** (historique et
par défaut) ou **Observation** pour une portée globale ou pour un domaine
précis. Une configuration spécifique de domaine remplace le mode global
**pour ce domaine seulement** ; les règles IP/CIDR/pays restent identiques.

Les API admin `GET/POST/DELETE /security-control/policy/modes` permettent
de consulter, définir et réinitialiser les modes. Le simulateur indique
distinctement la décision des règles (`rule_decision`) et la décision qui
serait appliquée avec le mode choisi (`predicted_decision`).

En Observation, Nginx calcule la variable
`$npm_security_would_deny` mais **ne renvoie pas HTTP 403**.
Il faut intégrer cette variable dans un format de log NPM si l'on souhaite
suivre les « aurait été bloqué » en exploitation. Le mode Observation
**n'émet pas automatiquement d'alerte** ; ce sera une fonctionnalité
distincte.

Changer le mode ne déclenche jamais le déploiement Nginx : l'export
devient en attente d'application, avec `nginx -t` et rechargement
explicite depuis l'hôte. Les anciens déploiements restent par défaut
en Blocage, pour préserver le comportement existant.

## Simulateur de décision de politique

Le centre de contrôle dispose d'une **prévisualisation sans effet de bord**.
Saisir une IP et un domaine cible, avec un pays facultatif, permet de
calculer la décision attendue par les règles actuellement enregistrées.
L'API est `GET /security-control/policy/preview` (administrateur).

L'aperçu affiche les règles globales ou par host qui correspondent à
l'adresse et au pays, les exemptions IP/CIDR ou réseaux internes, ainsi
qu'une décision `allow`, `deny` ou `unknown`. Le verdict reste
`unknown` si une règle géographique pourrait s'appliquer et que le
pays n'est pas fourni.

**Ce n'est pas un test de requête réelle vers Nginx.** Le calcul ne
modifie ni SQLite ni les fichiers de configuration, et n'active aucun
blocage. Les éventuelles divergences dues à GeoIP2, au proxy amont ou
aux règles déployées hors du dashboard doivent être vérifiées en
conditions réelles.

## Vérification réelle des décisions Nginx en CI

En plus de `nginx -t`, la suite de tests lance maintenant un **Nginx local
jetable** sur `127.0.0.1` et exécute des requêtes HTTP réelles. Elle vérifie
la réponse `403` ou `204` sur différents domaines pour les politiques
IP/CIDR/pays globales et ciblées, ainsi que les exemptions IP/CIDR et les
réseaux d'administration.

La configuration de test simule la géolocalisation avec une variable
Nginx alimentée depuis un header strictement réservé au test. Elle ne
charge **pas** MaxMind et ne s'applique à **aucun proxy de production**.
Pour tester GeoIP2 et la chaîne de proxies réels, utiliser un environnement
de recette avec le module et la base MMDB de NPM.

Les tests nécessitent `nginx` et sont exécutés sur GitHub Actions. Ils
sont ignorés uniquement sur les postes de développement dépourvus du
binaire Nginx.

## Politiques de blocage par domaine

Les règles de blocage IP, CIDR et pays peuvent désormais cibler un proxy host
précis (`host`) ou rester globales lorsque ce champ est vide. La migration
SQLite conserve les anciennes règles comme globales, ainsi que leurs dates
d'expiration. Les formulaires « Listes » et « Block List Manager » proposent
un champ domaine facultatif et affichent la portée de chaque règle.

Le rendu Nginx utilise `geo` et `map` pour isoler les IP/CIDR par host
et `$geoip2_data_country_code` pour le géoblocage mondial ou par host.
Les exceptions IP/CIDR restent prioritaires. Une règle globale continue
à s'appliquer à tous les proxy hosts, même si des règles ciblées existent.

Documentation et précautions : [Politiques NPM](docs/NPM_POLICY_ENFORCEMENT.md).
La suite CI inclut la vérification de la syntaxe des snippets via `nginx -t`
sur une configuration de test.

## Garde-fous des blocages manuels

Les endpoints `POST /blocklist` et `POST /block_ip/{ip}` refusent désormais
avec **HTTP 409** les IP ou CIDR qui recouvrent les réseaux d'administration
déclarés dans `INTERNAL_NETWORKS`. La configuration d'exemple inclut aussi
les réseaux IPv6 loopback, ULA et link-local.

Bloquer une IP déjà couverte par une entrée de confiance IP/CIDR renvoie
également HTTP 409 : une entrée « trusted » a priorité dans la politique
Nginx et le blocage serait inopérant. Il faut d'abord retirer la règle de
confiance, ou gérer les exceptions depuis les listes. Le blocage d'un CIDR
public peut conserver des exceptions IP de confiance à l'intérieur.

Les pays sont toujours bloquables, mais seuls les codes ASCII à deux lettres
sont acceptés. Les formulaires affichent maintenant les erreurs HTTP réelles
au lieu d'annoncer un succès quand l'API a rejeté l'action.

## Bannissements temporaires

La blocklist permet maintenant un blocage temporaire de **15 minutes, 1 heure,
24 heures, 7 jours ou 30 jours**, ou permanent, depuis l'onglet « Listes ».

Le champ JSON `duration_minutes` de `POST /blocklist` est facultatif (1 à
43200 minutes). Les endpoints `POST /block_ip/{ip}` et
`POST /block_country/{code}` acceptent également le paramètre de requête
`duration_minutes`. Un job toutes les minutes supprime les règles expirées,
consigne l'action et régénère les exports.

Les bans automatiques, toujours désactivés par défaut et en simulation par défaut,
expirent après `AUTO_BAN_DURATION_MINUTES=60` lorsque leur activation est explicite.

L'expiration en base doit aussi être **appliquée à Nginx** via
`scripts/npm-sec-apply.sh` ou un mécanisme d'application sur l'hôte NPM.
Les règles expirées ne sont plus exportées, mais une configuration Nginx déjà
chargée conserve son état jusqu'au prochain rechargement.

## Application réelle des règles Nginx

Le dashboard génère désormais deux snippets Nginx :
- `npm-blocklist.conf` : politique IP/CIDR/pays, exemptions d'IP de confiance et décision d'accès ;
- `npm-server-guard.conf` : condition de refus dans les `server` NPM (HTTP 403).

Les deux snippets doivent être inclus dans Nginx Proxy Manager par l'administrateur.
L'application n'est **pas** automatique par simple ajout d'une règle en base.
Le script `scripts/npm-sec-apply.sh`, exécuté sur l'hôte NPM, sauvegarde la configuration
précédente, valide avec `nginx -t`, fait `nginx -s reload` et restaure en cas d'échec.

Voir [docs/NPM_POLICY_ENFORCEMENT.md](docs/NPM_POLICY_ENFORCEMENT.md) avant toute
activation. L'API authentifiée `/blocklist/deployment` distingue les exports en attente
de ceux effectivement confirmés par le script.

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
