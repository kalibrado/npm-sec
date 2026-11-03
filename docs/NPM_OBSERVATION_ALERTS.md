# Télémétrie réelle des règles NPM Security en mode Observation

## Principe

Le mode `observe` continue à calculer `$npm_security_would_deny`
mais ne renvoie pas de `403` à la place de NPM. Pour créer une alerte
d'observation, le collecteur **exige la présence explicite** de ces deux
champs dans une même ligne JSON d'access log Nginx :

- `npm_security_policy_mode` : `observe` ou `block` ;
- `npm_security_would_deny` : `0` ou `1`.

L'événement `observe + 1` signifie : **cette requête aurait été refusée
par la politique NPM Security, mais elle est passée en observation**.
Cela ne prouve ni une intrusion ni une tentative de compromission.
Une requête `block + 1` est comptabilisée dans la télémétrie, mais ne
crée **aucun incident d'observation**.

Le dashboard n'essaie pas de deviner ces champs en consultant les règles
enregistrées. Ces règles peuvent différer de la configuration réellement
chargée. En l'absence de log instrumenté, la console affiche un avertissement
et aucune observation.

## Ajouter les champs au format JSON existant

Sur l'instance **de recette** Nginx Proxy Manager, inspecter d'abord le
`log_format` JSON utilisé pour le fichier `access-geo-detailed.log`
que NPM SEC lit déjà. Ajouter ces deux clés sans supprimer les champs
actuels du journal :

```nginx
"npm_security_policy_mode":"$npm_security_policy_mode",
"npm_security_would_deny":"$npm_security_would_deny"
```

Exemple **illustratif** d'un format JSON minimal, à adapter à votre
configuration NPM existante plutôt que de créer un second journal :

```nginx
log_format npm_security_json escape=json
  '{"timestamp":"$time_iso8601",'
  '"remote_addr":"$remote_addr",'
  '"host":"$host",'
  '"uri":"$request_uri",'
  '"status":"$status",'
  '"http_user_agent":"$http_user_agent",'
  '"npm_security_policy_mode":"$npm_security_policy_mode",'
  '"npm_security_would_deny":"$npm_security_would_deny"}';
```

**Important :** si vous utilisez déjà un `log_format` personnalisé pour
la géolocalisation, l'enrichir plutôt que d'écraser sa configuration.
Vérifier que la directive `access_log` active utilise ce format et que
le collecteur pointe vers le même fichier monté en lecture seule.
Le format doit être du JSON par ligne avec `escape=json`.

Ces champs doivent provenir **des variables Nginx générées** : ne
jamais les alimenter à partir d'un `$http_...` envoyé par un client.
Cela évite qu'un visiteur puisse déclencher artificiellement des alertes.

Sur l'hôte de recette, après sauvegarde et configuration :

```bash
docker exec npm nginx -t
docker exec npm nginx -T 2>&1 | grep 'npm_security_would_deny'
docker exec npm nginx -s reload
```

Vérifier ensuite qu'une requête de test sur un domaine en observation
produit réellement une ligne JSON comportant :

```json
{"npm_security_policy_mode":"observe","npm_security_would_deny":"1"}
```

Les autres champs obligatoires du journal (dont l'adresse IP, l'hôte
et le timestamp) doivent aussi être présents. Ne pas intégrer ce
mini-objet JSON isolément dans le collecteur.

## Incidents, alertes et anti-spam

Pour chaque nouvelle requête `observe + 1`, le collecteur met à jour
l'incident correspondant à sa paire **(domaine, IP)** en SQLite :

- Première et dernière observation, nombre total de signaux, dernière URI.
- État `open`, `acknowledged` ou `resolved`.
- Une nouvelle observation rouvre automatiquement un incident résolu.

Une alerte persistante est créée à partir de
`OBSERVE_ALERT_THRESHOLD` requêtes pour une même paire (domaine, IP)
dans une fenêtre de `OBSERVE_ALERT_WINDOW_MINUTES`. Une même paire
ne produit ensuite qu'une alerte par `OBSERVE_ALERT_COOLDOWN_MINUTES`.
Les alertes historiques restent consultables dans le cockpit.

Variables optionnelles :

```dotenv
OBSERVE_ALERT_ENABLED=true
OBSERVE_ALERT_THRESHOLD=5
OBSERVE_ALERT_WINDOW_MINUTES=5
OBSERVE_ALERT_COOLDOWN_MINUTES=15
OBSERVE_ALERT_DISCORD_ENABLED=false
```

Le webhook Discord est **désactivé par défaut**. Lorsqu'il est activé
et que `DISCORD_WEBHOOK_URL` est configuré, une notification contient
seulement la paire IP/domaine, le nombre de requêtes récentes et l'ID
d'incident. Aucune URI ni aucun User-Agent ne sont envoyés à Discord.
L'alerte est toujours conservée en SQLite, même si Discord échoue.

L'ingestion par curseur et l'unicité `source_id/source_offset` empêchent
de compter deux fois les mêmes lignes après un replay. Une requête
`observe` ne peut pas déclencher le mécanisme d'auto-ban, même si
celui-ci est activé pour d'autres types de trafic.

## API et limites

L'API requiert un compte administrateur :

- `GET /security-control/observations?hours=24&status=all&limit=50`
- `GET /security-control/observations/alerts?hours=24&limit=50`
- `POST /security-control/observations/{id}/status` avec un JSON
  `{"status":"acknowledged"}`, `{"status":"resolved"}` ou `{"status":"open"}`.

Aucune de ces actions ne modifie la politique Nginx.
La console présente les incidents observés et un indicateur
`telemetry_available` fondé sur les logs réellement instrumentés.

Les règles, le mode, GeoIP2 et les identités IP réelles doivent être
validés sur l'instance NPM de recette avant tout usage en production.
Le compteur d'incidents conserve l'historique de la paire domaine/IP ;
il n'est pas réinitialisé à chaque fenêtre temporelle.
