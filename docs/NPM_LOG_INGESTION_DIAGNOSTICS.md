# Diagnostic de collecte des logs Nginx

Le dashboard dispose d'un panneau **Santé → Collecte des logs Nginx**
qui permet de comprendre pourquoi aucune donnée n'apparaît dans les vues
Logs, Menaces ou Observation.

Le diagnostic est **en lecture seule**, accessible aux administrateurs
connectés et n'ouvre aucun socket Docker. Il lit uniquement les
métadonnées du fichier journal monté et le curseur de collecte SQLite.
Il ne renvoie **aucune requête**, URI, IP cliente ou ligne JSON brute.

## API

`GET /health/ingestion` exige une session administrateur ou un
jeton admin configuré. La réponse comprend :

- `status` (`ok`, `warning` ou `error`) et `code` : état et cause probable ;
- `advice` : action recommandée au technicien ;
- `log_file` et `file` : chemin attendu, existence, lecture, taille,
  dernière date de modification ;
- `cursor` : offset et génération SQLite, retard en octets,
  rotation/troncature à traiter ;
- `runtime` : derniers cycles de collecte, lignes lues, ajoutées,
  mal formées, déjà rencontrées, dernière erreur sous forme de **type
  uniquement** ;
- `stored` : volume total de logs et nombre d'événements instrumentés
  pour Observe parmi les 200 plus récents.

Aucune requête à cette API ne modifie les logs ou le curseur.

## États affichés

| État technique | Signification | Vérification |
|---|---|---|
| `file_missing` | Aucun fichier à `LOG_FILE` | Montage NPM et chemin .env |
| `file_unreadable` | Fichier inaccessible en lecture | UID/GID, permissions, bind mount |
| `collector_not_observed` | Aucun cycle observé par ce processus | Tâche de fond démarrée, un worker Uvicorn |
| `collector_stalled` | Aucun cycle depuis plus de 30 secondes | Logs du conteneur et tâches d'ingestion |
| `collector_error` | Erreur récente non résolue du collecteur | Logs applicatifs et base SQLite |
| `rotation_pending` | Nouveau fichier / troncature détecté | Attendre le prochain cycle de collecte |
| `invalid_log_lines` | Dernier lot contenant du JSON invalide | Format Nginx `escape=json`, fichier monté |
| `backlog` | Des octets attendent leur lecture | Taille des lots, ligne partielle, charge |
| `empty_file` | Log présent et vide | Journal NPM actif et trafic de recette |
| `up_to_date` | Fichier lu, curseur à jour | Vérifier trafic et instrumentation si nécessaire |

**Une collecte « à jour » ne prouve pas que Nginx écrit dans le bon
fichier**, ni que les variables Observe sont configurées. Si les
200 derniers événements ne contiennent aucune paire
`npm_security_policy_mode`/`npm_security_would_deny`, le panneau
signale que l'Observation n'est pas instrumentée dans l'échantillon.

## Compteurs et persistance

Les compteurs `runtime` sont **en mémoire** et se remettent à zéro
quand le processus applicatif redémarre. Ils ne remplacent pas une
surveillance externe. Leur précision suppose **un seul processus
Uvicorn** pour l'ingestion, conformément à l'architecture actuelle.

Les positions `ingestion_state` sont stockées en SQLite et survivent
aux redémarrages et aux purges manuelles de logs. La rotation est
repérée par changement d'identité physique de fichier, la
`copytruncate` par une réduction de taille.

L'actualisation du panneau est manuelle ou automatique toutes les
30 secondes tant que la vue Santé est ouverte.

## Séquence de recette

1. Vérifier que `LOG_FILE=/logs/access-geo-detailed.log` correspond au
   fichier réellement monté dans le conteneur du dashboard.
2. Ouvrir **Santé → Collecte des logs Nginx**.
3. Faire une requête de test sur un nom de domaine de recette.
4. Vérifier que le curseur progresse et que le compteur « Lignes ajoutées »
   augmente. S'il reste stable mais que le fichier grossit, inspecter
   `backlog`, le JSON et les permissions.
5. Vérifier que les événements apparaissent dans **Logs**.
6. Pour le mode Observation, suivre
   [le guide d'instrumentation](NPM_OBSERVATION_ALERTS.md) ;
   une règle stockée dans SQLite ne génère pas à elle seule un
   événement « aurait été bloqué ».

Ne pas modifier la configuration Nginx de production sans sauvegarde,
validation `nginx -t` et contrôle du comportement des domaines.
