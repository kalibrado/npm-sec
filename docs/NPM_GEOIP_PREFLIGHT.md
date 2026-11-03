# Diagnostic en lecture seule de NPM Security et GeoIP2

Ce diagnostic sert à vérifier la **configuration Nginx effectivement chargée**
avant de déployer des règles IP, pays ou une instrumentation Observe.

Il ne modifie **aucun fichier**, ne lance **aucun rechargement Nginx**,
ne redémarre aucun conteneur, ne crée aucune règle IP et ne contacte aucun
service distant. Il s'exécute depuis l'hôte Docker avec accès au conteneur NPM.

## Commandes

Dans le dépôt, sur l'hôte Docker où tourne Nginx Proxy Manager :

```bash
python3 scripts/npm-sec-preflight.py --container npm
```

Pour récupérer un résultat exploitable dans un pipeline :

```bash
python3 scripts/npm-sec-preflight.py --container npm --json
```

- Code retour **0** : tous les contrôles requis sont passés.
- Code retour **1** : au moins une configuration requise manque.
- Code retour **2** : le diagnostic n'a pas pu examiner Nginx.

Il utilise uniquement `docker exec npm nginx -T` et, si des pays sont
activés, `docker exec npm test -r <chemin-MMDB>`. Aucune autre opération
Docker n'est lancée. Le diagnostic **n'affiche jamais** le contenu complet
de la configuration Nginx, qui peut contenir des valeurs sensibles.

Pour analyser un export `nginx -T` déjà collecté hors ligne, sans
utiliser Docker :

```bash
python3 scripts/npm-sec-preflight.py --config-dump ./nginx-dump.txt --json
```

Attention : un fichier de configuration complet peut contenir des
secrets. Ne pas l'envoyer sur un dépôt Git ou un service public.

## Contrôles effectués

1. Inclusion du fichier de politique NPM Security dans le contexte HTTP.
2. Inclusion du garde-fou dans les serveurs proxy.
3. Présence des variables `$npm_security_policy_mode`,
   `$npm_security_would_deny` et `$npm_security_deny`.
4. Existence d'un `log_format` JSON `escape=json` avec les champs
   `timestamp`, `remote_addr`, `host`, `npm_security_policy_mode`
   et `npm_security_would_deny`, et d'un `access_log` actif utilisant
   **ce même format**.
5. Si la politique chargée contient une règle pays : déclaration GeoIP2
   de `$geoip2_data_country_code` et disponibilité de la base `.mmdb`
   dans le conteneur.
6. Avertissement systématique sur la configuration `real_ip_header`
   et les réseaux de confiance `set_real_ip_from`. La simple présence
   de ces directives ne prouve pas l'absence d'usurpation.

Une alerte sur GeoIP2 ne doit pas encourager à télécharger au hasard une
bibliothèque incompatible avec le binaire NPM. Vérifier le module, l'image
NPM et la base MMDB utilisés sur l'environnement de recette avant
d'installer quoi que ce soit.

## Ce que le diagnostic ne prouve pas

- Que le log JSON instrumenté est **celui réellement monté et lu** par
  le collecteur du dashboard.
- Que le module GeoIP2 déduit le bon pays pour les IP publiques et les
  CDN : la base peut être obsolète ou la chaîne `real_ip` mal configurée.
- Qu'une requête sur chaque domaine reçoit le statut attendu.
- Que les règles ont été rechargées avec succès depuis le dernier export.

Pour la validation complète, utiliser aussi les tests en CI
`tests/test_nginx_runtime_http.py` et la procédure manuelle de recette
du [guide d'observation](NPM_OBSERVATION_ALERTS.md) :

1. Contrôler `nginx -t` et le diagnostic en lecture seule.
2. Mettre **un seul** domaine de recette en Observe.
3. Émettre une requête de test depuis une IP autorisée à la recette.
4. Vérifier que le Nginx log JSON contient
   `npm_security_policy_mode=observe` et `npm_security_would_deny=1`.
5. Vérifier que le fichier de logs est monté sur le dashboard et que
   la console crée un incident et les alertes attendues.
6. Tester les exceptions et le retour en mode Block, puis valider
   explicitement tout déploiement de production.

**Ne jamais exécuter le script de rechargement de production pendant
un test de préflight.**
