# NSD — feuille de route produit et architecture (référence)

## Contrat produit

**Nginx Proxy Manager (NPM)** garde uniquement le routage des proxy hosts, les certificats TLS, la génération de ses server blocks et ses fonctions natives. **Nginx Security Dashboard (NSD)** est responsable de toute politique de sécurité, de sa configuration, de son historique, de sa supervision et de sa web UI.

Nginx exécute nécessairement des directives de protection dans le processus NPM. Pour limiter le couplage, les fichiers NPM `http_top.conf` et `server_proxy.conf` n'ont finalement qu'un include chacun, vers un profil compilé par NSD. Le module GeoIP2 reste chargé au démarrage du processus Nginx, selon l'image réelle. L'absence du dashboard ne doit jamais arrêter le routage : le dernier profil validé demeure en place.

La configuration héritée transmise le 03/11/2026 est la valeur **initiale** à préserver, pas le format permanent du système. Les changements futurs sont exclusivement effectués depuis l'interface NSD et validés côté serveur. Les fragments Git `config/nginx-managed/*.conf` sont des modèles d'amorçage et de migration, non une deuxième source de vérité opérationnelle.

## Composants et frontières de confiance

1. **NSD Web UI + API** : session sécurisée, rôles admin / viewer, schéma des paramètres, validation stricte, versionnement et audit des actions. Pas de socket Docker.
2. **SQLite** : réglages, règles, versions, auteurs, demandes de publication, résultat des tests, historiques et dernières versions validées. Les données d'observabilité restent distinctes.
3. **Compilateur Nginx** : transformation déterministe de paramètres typés en fichiers autorisés. Aucune directive Nginx brute fournie par un utilisateur, aucun chemin arbitraire ni commande shell. Génère un bundle candidat avec hash, métadonnées et diff ; jamais un fichier actif.
4. **Agent applicateur sur l'hôte NPM** : service séparé à privilèges réduits, exécutant exclusivement un protocole fixe sur les chemins autorisés. Sauvegarde de la version précédente, publication atomique du candidat, `nginx -t`, `nginx -s reload`, contrôle de succès, et restauration automatique si échec. Émission d'un accusé signé/validé d'application. Limiter les permissions et empêcher les chemins symboliques/évasions.
5. **Nginx/NPM** : consomme le dernier bundle correctement publié. Aucun appel sortant vers NSD sur les requêtes. L'arrêt de NSD n'affecte pas les proxys.
6. **Collecteur** : lecture asynchrone durable du JSON Nginx, marqueurs de provenance et d'observation, ingestion SQLite, SSE vers les navigateurs. Diagnostic des montages / curseurs / erreurs.

**Contrainte de sécurité** : l'agent hôte ne sera pas automatiquement installé/activé sur l'instance réelle. L'utilisateur autorise explicitement toute première migration ou mise en production. En attendant : candidat, validation en Nginx jetable, simulation et preview uniquement.

## Cycle de vie des configurations

`DEFAULTS → DRAFT → VALIDATED → PENDING_APPLY → APPLIED` ;
`VALIDATION_FAILED` ou `APPLY_FAILED → ROLLED_BACK`.

Les valeurs par défaut sont migrées sans écraser les règles SQLite actuelles. Toute édition fait une **nouvelle révision** immutable, avec ID, auteur, date, note, diff et hash ; concurrence gérée par le numéro de révision. Un rollback crée une nouvelle révision à partir d'une version précédente, sans effacer l'audit. Le déploiement n'est déclaré `APPLIED` qu'après une preuve de test + reload par l'agent. Une écriture de fichiers NSD ne suffit pas.

Pour limiter les coupures, utiliser `nginx -t` avant reload ; le reload Nginx graceful conserve les travailleurs précédents tant que possible. Prévoir une stratégie de secours si l'agent devient indisponible. Préserver la connectivité LAN d'administration, ne pas activer les bannissements automatiques par défaut.

## Interfaces prévues

| Vue | Périmètre / critères d'acceptation |
| --- | --- |
| Accueil | Volumes, refus confirmés distincts des règles configurées, bans, score de menace, top IP/pays/URI, alertes, état NPM/NSD |
| Logs temps réel | SSE robuste, pause/reprise, recherche IP/URI/status/méthode/hôte/UA/période, détails filtrés, provenance/règle, actions contextuelles |
| Carte | 2D GeoIP en direct, couleurs normal/suspect/refusé ; globe 3D optionnel soumis au coût et aux performances |
| Menaces | Taxonomie, scores configurable et justifiables, niveaux faible/moyen/élevé/critique, courbes, décisions enregistrées/effectives |
| Santé | NPM, Nginx, NSD, proxys, TLS/certificats, CPU/RAM/disque, latence 4xx/5xx, état collecte et agent |
| Configuration | Tous réglages typés documentés avec défauts, UI complète, validation, prévisualisation, diff, révisions, validation et rollback |
| Règles | CRUD IP/CIDR, pays, hôte, URI, méthode, UA ; actifs/inactifs, priorité, expiration, motif, compteur réel des occurrences, scope |
| Audit | Historique immuable des modifications, auteur, date, ancien/nouveau, statut et preuve de déploiement |

## Lots de développement autonomes

1. **Fondations** : modèle de configuration persistante validée, valeurs héritées, brouillons/versions/audit, web UI éditable, aperçu du rendu. Aucun reload.
2. **Rendu et tests** : compilateur de profils Nginx, interfaces de validation, tests vrais HTTP/JSON et `nginx -t` en CI. Diff des candidats.
3. **Agent local sécurisé** : protocole de transfert et signature/intégrité, validateur de chemins, backup/rollback, résultats transactionnels, activation manuelle explicite de la migration initiale.
4. **Règles avancées** : modèle unifié de politiques IP/CIDR/pays/URI/UA/méthode/host, priorités, exceptions, TTL, instrumentation des refus réels.
5. **Logs et carte** : diagnostic du fichier monté et reprise durable (problème réel d'avril/novembre), pause/reprise SSE, filtres enrichis, actions dérivées, GeoIP et performance ; 3D après fonctionnel 2D.
6. **Menaces** : scoring configurable par signal, détail explicable, seuils, graphiques et stratégies de prévention en simulation d'abord.
7. **Santé** : certificats, sondes des backends, ressources et alertes sans fuite d'information.
8. **Durcissement et recette** : permissions, protections anti-lockout, transactions, restauration, UX mobile/desktop, tests E2E avec NPM de recette, CI et documentation.

À chaque lot : branche issue de `dev`, PR ciblant `dev`, tests verts avant squash merge. Jamais de modification de `main` ni de rechargement du NPM réel sans approbation préalable.

## Décisions de stack

Conserver l'existant tant qu'une refonte n'apporte pas de gain mesurable : **FastAPI + Python 3.12, SQLite, JavaScript actuel et SSE, Docker Compose**. Le frontend pourra être isolé progressivement plutôt que de déclencher une réécriture React sans besoin démontré. La version Helm/OpenShift reste une cible ultérieure. Le service applicateur s'exécute sur l'hôte et reste indépendant du dashboard web.

## Suivi incrémental de l'agent (04/11/2026)

- PR #32 : vérification des chemins NPM symboliques avant publication et rollback, fusionnée dans `dev` après CI Backend tests #66 verte. Ce contrôle n'élimine pas encore les races TOCTOU entre vérification et écriture.
- Incrément suivant : la vérification d'existence Docker doit distinguer absence réelle (code 1) et erreur d'exécution (codes 2/125/126/127/etc.). Toute erreur doit interrompre le snapshot sans marquer un fichier comme absent ; tests de régression dédiés. Aucun déploiement réel autorisé.
- À traiter ensuite : confinement résistant aux changements concurrents de chemins, permissions de l'agent, puis schéma UI exhaustif et compilateur validé.

- Incrément rollback (PR en cours) : vérifier la totalité des sauvegardes et les booléens du manifeste avant toute écriture sur NPM ; tests de non-restauration partielle. Cette prévalidation ne résout pas les races TOCTOU ni l'absence de preuve Nginx réelle. Ne pas activer l'agent en production.

- Incrément TOCTOU (04/11, PR dédiée) : nouvelle vérification des chemins NPM avant chaque copie, suppression et renommage, y compris en rollback. Cette mesure réduit la fenêtre de course mais **ne garantit pas** l'absence de TOCTOU : il reste à remplacer les opérations Docker `cp/mv/rm` par des primitives confinées sans suivi de symlink, à valider en recette isolée. Aucun déploiement NPM réel autorisé.

- Incrément agent token (04/11) : lecture du secret avec `O_NOFOLLOW` et validation des permissions sur le descripteur ouvert (`fstat`) pour empêcher un échange de symlink entre contrôle et lecture. Tests dédiés. Ce correctif ne confine pas les mutations de fichiers NPM et n'autorise aucune application réelle.

- Incrément limite token (04/11) : refuser les fichiers de secret agent dépassant 4096 caractères avant suppression des espaces, afin de ne pas accepter silencieusement un fichier tronqué. Tests aux limites. Ne concerne pas le confinement des écritures NPM ; aucun déploiement réel autorisé.

- Incrément snapshot (04/11) : revalider les chemins NPM avant chaque sondage de présence et chaque copie de sauvegarde, avec tests de régression. Réduction de fenêtre TOCTOU uniquement : Docker cp reste non confiné ; aucun déploiement réel autorisé.

- Incrément snapshot (04/11, PR dédiée) : après chaque copie de sauvegarde, refuser un fichier absent ou un lien symbolique avant toute mutation NPM. Tests de non-régression pour copie silencieusement incomplète, symlink et fichier régulier. Cette vérification reste sensible aux courses TOCTOU et ne remplace pas les primitives confinées.

- Incrément validation UTF-8 (04/11, PR dédiée) : les limites de taille des fichiers et du bundle de l'agent sont désormais évaluées sur les octets UTF-8 réellement transférés, et non sur le nombre de caractères Python. Tests de dépassement individuel et cumulé avec caractères multioctets. Aucun déploiement réel autorisé ; confinement TOCTOU toujours incomplet.

## Incrément schéma typé (04/11/2026)

- Nouveau module `services/nginx_settings_schema.py` : validation stricte d'un premier sous-ensemble de six réglages (auto-ban, pays, CIDR proxies, rate/burst), types exacts, bornes et rejet des clés inconnues ; tests de régression dédiés.
- Import initial exige un SHA-256 explicite des sources historiques. **Aucune valeur de `http_top.conf` ou `server_proxy.conf` n'est inventée ou importée automatiquement.**
- Ce module n'est pas encore connecté à SQLite, à l'API ni à l'interface ; il ne génère aucune configuration et ne déclenche aucun reload. Étape suivante : extraction contrôlée des valeurs héritées, migration persistante et UI admin avec révisions/diff.

## Incrément persistance des brouillons (05/11/2026)

- `services/nginx_settings_revisions.py` : table SQLite dédiée aux révisions immuables de brouillons typés, hash SHA-256 canonique, auteur, motif, provenance optionnelle et concurrence optimiste transactionnelle (`BEGIN IMMEDIATE`).
- Tests ciblés : révisions successives, conflit d'écriture, validation préalable, métadonnées et préservation des tables existantes.
- **Limites** : module non raccordé à l'API ni à l'UI ; aucune migration automatique des fichiers historiques, aucun générateur, aucune preuve de déploiement. Les permissions admin doivent être vérifiées dans la future couche API. Statut exclusivement `DRAFT`, aucun reload NPM.

## Incrément comparaison des révisions (05/11/2026)

- `services/nginx_settings_diff.py` : comparaison déterministe, en lecture seule, de deux brouillons persistés ; vérification SHA-256 du JSON stocké, schéma validé et représentation canonique avant tout diff. Champs modifiés présentés avec valeurs avant/après.
- Tests dédiés : diff avant/arrière, révision identique, identifiants invalides, absence de révision, altération de la base et charge utile non conforme même avec hash recalculé.
- **Limites** : ce diff n'est pas encore raccordé à une API authentifiée ni à la web UI ; aucun statut `APPLIED`, aucune migration historique ni application Nginx. L'authentification et l'autorisation doivent être imposées dans la couche API à venir.

## Incrément historique vérifié (05/11/2026)

- `services/nginx_settings_history.py` : lecture paginée des métadonnées des brouillons SQLite, ordre décroissant et curseur stable, contrôle SHA-256 et schéma de chaque révision avant affichage. Aucune charge utile de réglages dans la liste.
- Tests : ordre, pagination, limites, corruption et absence de mutation.
- **Limites** : aucun endpoint ni contrôle d'accès HTTP à ce stade ; ne jamais exposer ce module directement aux utilisateurs non authentifiés. Aucune application Nginx. Prochain incrément : API admin avec autorisation serveur, puis UI.

## Incrément lecture de la dernière révision (05/11/2026)

- `latest_settings_revision` vérifie désormais le SHA-256, le schéma canonique et le statut DRAFT avant de retourner une configuration. Une altération fait échouer la lecture au lieu d'exposer un brouillon non fiable.
- Tests dédiés : absence de révision, lecture valide, hash incorrect, schéma invalide avec hash recalculé, JSON non canonique, statut invalide et lecture sans mutation.
- **Limites** : pas encore d'API authentifiée ni d'édition UI ; aucune application Nginx. Prochaine étape : endpoint de lecture admin/viewer protégé et endpoint d'écriture admin avec audit.

## Incrément API de lecture des brouillons (05/11/2026, PR dédiée)

- Routes `GET /api/nginx-settings/latest` et `GET /api/nginx-settings/history` : authentification obligatoire via `require_viewer` (admin ou viewer), vérification SHA-256 et schéma, pagination bornée, erreurs 409 si corruption. Les métadonnées d'historique ne contiennent pas le JSON des réglages.
- Initialisation de la table des brouillons au démarrage après `init_db()`, sans écraser les tables existantes. Tests HTTP : 401 sans session, 200 viewer, validation des bornes, rejet des révisions altérées.
- **Limites** : lecture uniquement, pas encore de POST admin, ni UI, ni import des fichiers historiques. Aucun déploiement ou reload Nginx. Prochaine étape : écriture admin authentifiée avec contrôle de concurrence et protection CSRF.

## Incrément API de comparaison des brouillons (05/11/2026)

- Route authentifiée en lecture `GET /api/nginx-settings/diff?before_revision=1&after_revision=2`, accessible aux rôles admin/viewer ; réutilise le comparateur SQLite existant, vérifie les empreintes et le schéma des deux révisions.
- Contrats HTTP : 401 sans authentification, 422 pour identifiants manquants/invalides, 404 pour révision absente, 409 pour révision altérée. Tests HTTP de ces cas et des différences déterministes.
- Limites : aucun endpoint d'écriture ni interface de comparaison, aucune migration des valeurs historiques, aucun effet sur NPM. Prochaine priorité : écriture admin et intégration UI.

## Durcissement des écritures de brouillons (05/11/2026)

- Avant toute insertion, `create_settings_revision` vérifie désormais, **dans la même transaction SQLite `BEGIN IMMEDIATE`**, l'intégrité SHA-256, le schéma typé et la forme canonique de la dernière révision. Une dernière révision altérée interdit l'écriture au lieu de masquer l'incident sous une nouvelle version valide.
- Tests de régression pour hash incorrect, schéma invalide malgré hash recalculé, et JSON non canonique malgré hash recalculé ; aucune insertion en cas d'échec.
- Limites : ne constitue ni une chaîne d'audit inviolable ni une protection contre la modification directe de SQLite. L'API POST admin, la protection CSRF, l'UI et l'import historique restent à développer. Aucun effet NPM.

## Correctif fond de carte CARTO (05/11/2026)

- Leaflet 2D utilise le format raster CARTO Voyager `https://basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}.png?key=...` ; le style vectoriel `style.json` nécessite MapLibre GL JS et ne peut pas être chargé comme couche raster Leaflet.
- `CARTO_BASEMAP_API_KEY` est un **jeton navigateur public** injecté par le serveur via le template JSON échappé, jamais un secret serveur. Restreindre son usage au domaine du dashboard chez CARTO. Afficher un diagnostic si la clé manque ou si les tuiles échouent.
- Limites : aucune clé fournie ni carte 3D intégrée ; la configuration depuis l'UI, MapLibre/vectoriel et le globe restent dans l'issue #49. Aucun impact NPM.

## Incrément écriture API admin des brouillons (05/11/2026)

- `POST /api/nginx-settings/revisions` : administrateur authentifié uniquement ; schéma strict, motif obligatoire, auteur issu de la session, concurrence optimiste et refus si la dernière révision est altérée.
- En-tête obligatoire `X-NSD-Intent: save-settings` pour les écritures navigateur, non autorisé par la politique CORS cross-origin actuelle ; compléter par une protection CSRF explicite et des tests d'origine avant ouverture de l'UI d'édition.
- Retour 201 pour brouillon créé, 403 sans rôle/intention, 409 en cas de conflit/corruption et 422 en cas de données invalides ; tests HTTP dédiés.
- Aucun rendu ni déploiement Nginx ; les valeurs historiques ne sont pas encore importées automatiquement. L'UI de modification reste à connecter.

## Durcissement CSRF des brouillons (05/11/2026)

- Les écritures `POST /api/nginx-settings/revisions` refusent les en-têtes `Origin` non conformes à l'hôte HTTP et les requêtes navigateur `Sec-Fetch-Site` différentes de `same-origin` ou `none`. Le contrôle `X-NSD-Intent` et les droits admin restent obligatoires.
- Tests : origines étrangères, `null`, hôtes trompeurs, contexte `same-site`/`cross-site`, aucune insertion en cas de refus et écriture same-origin autorisée.
- Limites : ce contrôle est adapté aux navigateurs ; il ne constitue pas une authentification des clients non navigateurs. Le reverse proxy doit préserver `Host` et bloquer les en-têtes d'hôte non attendus. Aucun déploiement NPM.

## Schéma HTTP pour éditeur de brouillons (05/11/2026)

- `GET /api/nginx-settings/schema` (viewer ou admin authentifié) décrit les six champs typés, leurs libellés, bornes et contraintes, sans exposer de directives Nginx exécutables.
- Aucun défaut historique n'est inventé : la migration vérifiée de `http_top.conf` et `server_proxy.conf` demeure nécessaire. La valeur `legacy_defaults_imported: false` décrit cette absence de provenance dans le schéma, pas un diagnostic du contenu de la base.
- Prochain incrément : éditeur dédié branché sur `/schema`, `/latest`, `/revisions`, `/history` et `/diff` avec permissions admin côté serveur. Aucun reload.
## Interface des brouillons typés (05/11/2026)

- La vue Config affiche une section indépendante pour les six champs du schéma typé, le motif obligatoire, la révision courante et l'historique des 20 dernières révisions.
- L'éditeur charge `/api/nginx-settings/latest`, écrit via `POST /api/nginx-settings/revisions` avec contrôle de version, et traite explicitement les conflits HTTP 409. Aucun rendu HTML non fiable ni appel d'application Nginx.
- Sans révision initiale, l'éditeur est volontairement verrouillé : les valeurs historiques doivent être importées et validées plutôt que fabriquées par l'UI. La section de configuration runtime existante reste distincte.
- Suite : import initial vérifié, comparaison détaillée et gestion UX des rôles. Aucun changement sur NPM.

## Comparaison des brouillons typés (05/11/2026)

- La section Config permet de sélectionner deux révisions et d'afficher les champs modifiés, valeurs avant/après, depuis l'API `/api/nginx-settings/diff` existante.
- Les valeurs sont injectées en texte dans le DOM (pas de HTML non fiable), avec affichage responsive et erreurs visibles. Comparaison strictement en lecture seule, sans Nginx reload.
- L'import initial vérifié reste nécessaire pour débloquer l'édition lorsqu'aucune révision n'existe.

## Import initial attesté des brouillons (05/11/2026)

- Endpoint admin `POST /api/nginx-settings/import-initial` : reçoit les six champs typés, une empreinte SHA-256 de la source historique, une description, un motif et une attestation explicite `verified_against_source=true`.
- Refuse une source absente, un schéma invalide, une origine navigateur étrangère, un rôle non admin ou une base déjà initialisée. Insertion atomique avec `expected_revision=0` ; l'empreinte est conservée dans la révision.
- **Attention** : l'API valide le format de l'empreinte et exige l'attestation de l'administrateur, mais ne peut pas vérifier que les valeurs reflètent réellement les fichiers Nginx : cette correspondance doit être contrôlée manuellement sur la source de confiance. L'empreinte ne prouve pas à elle seule la provenance.
- Exemple de payload : `{"settings":{"auto_ban_enabled":false,"country_block_enabled":false,"blocked_countries":[],"trusted_proxy_cidrs":[],"rate_limit_rps":10,"rate_limit_burst":20},"source_sha256":"<SHA-256 réel du fichier vérifié>","source_description":"fichier historique vérifié","reason":"migration initiale","verified_against_source":true}`. Les valeurs de l'exemple ne doivent **jamais** être appliquées sans vérification.
- Aucun rendu, déploiement, écriture de configuration ni reload Nginx. UI d'import guidé à prévoir après définition d'une source fiable.

## Parcours UI d'import initial (05/11/2026)

- La vue Config révèle le formulaire d'import uniquement si l'API indique qu'aucune révision initiale n'existe ; il disparaît après import réussi.
- Champs de provenance et paramètres typés sans préremplissage : source décrite, SHA-256, valeurs explicitement relevées, motif, attestation cochée et confirmation finale. La saisie de booléens non cochés est une décision explicite de l'administrateur, pas une lecture automatique du fichier.
- L'interface ne lit pas les fichiers Nginx : elle ne peut pas certifier la correspondance entre empreinte et valeurs. Contrôle manuel requis avant toute initialisation. Aucune modification NPM.

## Verrouillage du bootstrap (05/11/2026)

- L'API standard `/api/nginx-settings/revisions` refuse désormais `expected_revision=0` (HTTP 409). L'initialisation passe obligatoirement par `/api/nginx-settings/import-initial` avec source identifiée, empreinte et attestation.
- Test d'intégration HTTP complet : base vide → refus du contournement → import initial → édition admin → diff → historique → rejet du second import. Aucun appel de déploiement Nginx.

## Générateur de preview rate-limit isolé (05/11/2026)

- `services/nginx_rate_limit_preview.py` : rendu pur et déterministe de deux snippets distincts pour les contextes `http` (`limit_req_zone`) et `server` (`limit_req`, statut 429). Empreinte SHA-256 du rendu ; aucune écriture disque, commande, Docker ou reload.
- Refus explicite des paramètres auto-ban, GeoIP, pays et proxys de confiance : ils ne peuvent pas être traduits sans intégrer correctement la chaîne IP réelle et les modules Nginx présents. Le rendu est **un prototype de prévisualisation**, pas un profil complet ni une politique active.
- Les tests couvrent l'injection, la validation, les valeurs non prises en charge et la reproductibilité. Étapes ultérieures : test `nginx -t` sur serveur jetable, inventaire des modules, agent hôte isolé et procédure de rollback. Ne jamais appliquer automatiquement.

## Validation Nginx jetable du rate limiting (05/11/2026)

- Tests de syntaxe des deux snippets générés avec un `nginx -t` sur configuration temporaire isolée, sans démarrer Nginx et sans toucher aux fichiers NPM. Paramètres aux bornes et cas usuel.
- Workflow CI dédié installant Nginx dans le runner GitHub pour garantir l'exécution réelle (pas de simple test Python). Aucun test GeoIP2, comportement HTTP ou application de profil à ce stade.

## Contrôle négatif de la validation Nginx jetable (05/11/2026)

- Le workflow de syntaxe vérifie également qu'une directive Nginx volontairement inconnue provoque un échec de `nginx -t` et que le diagnostic mentionne la directive rejetée.
- Ce test évite de considérer une CI verte comme preuve de validation si le banc de test cessait de détecter les configurations invalides. Il n'exécute aucun daemon, reload ou accès à NPM.
- Suite : valider le comportement HTTP dans un serveur jetable et construire l'agent d'application isolé, sans activation sur NPM réel.


## API de prévisualisation des brouillons (05/11/2026)

- `GET /api/nginx-settings/preview` expose, en lecture authentifiée, les deux snippets rate-limit du dernier brouillon validé, sa révision et son empreinte SHA-256.
- Réponse explicite `PREVIEW_ONLY` ; aucun rendu sur disque, aucun déploiement ni reload. Les réglages non pris en charge (GeoIP, auto-ban, proxy de confiance) sont rejetés, sans application partielle silencieuse.
- Tests HTTP : authentification, absence de brouillon, reproductibilité, paramètres non supportés, révision corrompue et absence de mutation.
- Suite : parcours UI admin de comparaison/restauration, puis contrat de l'agent hôte isolé et validation de candidat sur Nginx jetable avant tout mécanisme de déploiement.


## Prévisualisation des révisions historiques (05/11/2026)

- API authentifiée `GET /api/nginx-settings/revisions/{revision}/preview` : rendu déterministe et sans effet de bord d'une révision historique dont l'empreinte et le schéma sont vérifiés.
- Réponse marquée `PREVIEW_ONLY` avec empreinte du rendu ; erreurs explicites pour révision absente, corrompue ou paramètres non pris en charge.
- Prochaine étape : interface de comparaison et restauration administrateur ; aucun agent hôte ni déploiement NPM activé.


## Restauration de brouillon depuis l'interface (05/11/2026)

- Le panneau Config propose une restauration de la révision « Avant » uniquement après comparaison réussie avec la révision courante « Après ».
- Motif obligatoire, confirmation explicite, contrôle de concurrence côté API, retour utilisateur et rafraîchissement de l'historique.
- L'opération crée une nouvelle révision DRAFT ; aucun déploiement, écriture Nginx ni reload.
- Suite : tests navigateur interactifs, prévisualisation détaillée et protocole d'agent hôte isolé avant toute activation réelle.


## Comparaisons UI : réponses HTTP obsolètes (05/11/2026)

- Une génération de comparaison invalide les réponses arrivées après un changement de sélection ou un rechargement de l'historique.
- La sélection « Avant / Après » est revérifiée après la réponse HTTP avant d'autoriser une restauration.
- Tests de garde statiques ajoutés ; un test navigateur simulant des réponses hors ordre reste à réaliser.
