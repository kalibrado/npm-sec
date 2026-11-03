# Navigation, retours des actions et purge des logs

## Centre de contrôle et listes

Le **Centre de contrôle** dispose de son propre onglet sur ordinateur et
de sa propre entrée dans la navigation mobile. Il présente les métriques
de protection, les observations, les IP suspectes, les modes par domaine
et le simulateur de politique.

La **vue Listes** est réservée aux blocklists, aux règles de confiance
et à l'historique des actions. Sur mobile, elle se trouve dans le menu
**Plus → Listes**.

Le contenu du Centre de contrôle défile indépendamment du haut de page.
La zone principale est aussi accessible au clavier.

## Retours utilisateur

Les formulaires de règles IP/CIDR/pays et d'entrées de confiance
présentent désormais :

- un message d'erreur affiché dans le formulaire si un champ requis est vide ;
- un bouton désactivé temporairement pendant l'opération ;
- un message de résultat persistant, en plus d'une notification courte ;
- le détail des erreurs renvoyées par l'API.

La simulation ne peut plus être validée silencieusement sans IP ni domaine.

Depuis le gestionnaire de blocklist, l'action **Écrire fichiers**
signale explicitement les chemins générés, notamment
`npm-server-guard.conf`. Cette action **n'applique pas** les fichiers
à NPM, elle ne fait que les écrire dans le dossier d'exports du dashboard.
Le rechargement Nginx est une opération distincte avec confirmation.
Si le runtime ne permet pas le reload, l'interface le mentionne au lieu
d'annoncer un succès ambigu.

## Purger les logs enregistrés

Dans **Logs → Purger les logs**, un dialogue détaillant la portée de
la suppression impose de saisir exactement `PURGER`. L'API nécessite
en plus une authentification administrateur et l'en-tête
`X-Purge-Confirmation: PURGER`, afin de limiter les actions involontaires
ou initiées depuis un autre site.

Exemple d'API, avec un jeton administrateur disponible :

```bash
curl -X POST http://localhost:8000/db/purge-logs \
  -H 'X-Admin-Token: <JETON_ADMIN>' \
  -H 'X-Purge-Confirmation: PURGER' \
  -H 'Content-Type: application/json' \
  -d '{"confirmation":"PURGER"}'
```

La purge supprime **dans une transaction SQLite unique** :
- les logs HTTP enregistrés (`access_logs`) ;
- les événements et tags de menace issus de ces logs ;
- les incidents et alertes d'Observation.

Elle **préserve** les règles IP/CIDR/pays, les entrées de confiance,
les modes de protection, les audits des actions, les utilisateurs,
les sessions et surtout les curseurs persistants du collecteur.
Conserver les curseurs est important pour ne pas réimporter
immédiatement les anciennes lignes après purge.

La purge **ne touche pas** aux logs sources de Nginx et ne modifie
pas la configuration ou les conteneurs NPM. Les nouvelles requêtes
continueront d'être collectées.

**Attention :** cette opération est destructrice et ne crée pas
automatiquement de sauvegarde. Pour conserver un historique, effectuer
d'abord une sauvegarde de la base via **Config → Backup DB**.
SQLite peut conserver des pages libres dans son fichier après suppression ;
l'action existante **Config → Compact DB** permet ensuite de récupérer
l'espace sur disque. Ne pas supprimer le fichier SQLite, ce qui
effacerait également les règles et les comptes.

Aucune de ces actions n'est exécutée automatiquement lors de
l'installation ou de la mise à jour du dépôt.
