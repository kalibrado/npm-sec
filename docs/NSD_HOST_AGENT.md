# Déploiement NSD par agent hôte séparé

La séparation est stricte : **le dashboard ne connaît pas le socket Docker**
et n'exécute jamais `nginx -t` ou `nginx -s reload`. Il crée uniquement
une demande immuable, associée à la révision et au hash SHA-256 exact des
quatre snippets Nginx compilés. L'agent tourne **sur l'hôte Docker NPM**,
récupère ces demandes par HTTPS avec un token dédié, et conserve ses
sauvegardes localement.

Cette partie est disponible en `dev` mais le **mode production n'est
pas activé par défaut**. Aucune installation ni modification de ton
NPM n'a été exécutée.

## Configuration et sécurité

Dans le fichier `.env` du conteneur NSD, définir une valeur aléatoire
d'au moins 32 caractères pour `NSD_AGENT_TOKEN`. Elle ne doit être ni
committée ni exposée au navigateur.

Sur l'hôte Docker NPM, stocker la même valeur dans un fichier de
permissions strictes (ex. `/etc/nsd-agent/token`, mode `0600`).

Le client de l'agent **exige HTTPS avec validation du certificat** :
utiliser le domaine NSD avec un certificat valide. Les redirections HTTP
sont interdites afin d'éviter de transmettre le secret à un autre hôte.
Le service de l'agent est totalement distinct du conteneur NSD.
Attention : accéder au socket Docker donne des privilèges élevés
sur l'hôte. Installer ce service dans un contexte hôte isolé et auditer
ses permissions avant de l'activer.

## Utilisation de la web UI

**Configuration → Configuration de sécurité NSD** :

1. Modifier les paramètres et afficher leur preview (validation de
   schéma et diff Nginx ; **pas encore `nginx -t`**).
2. Enregistrer une révision et un motif (ou utiliser les valeurs par
   défaut de la révision 0).
3. Cliquer **Demander l'application par l'agent** et saisir
   exactement `APPLIQUER`.
4. Une demande `pending` est conservée en base, avec les fichiers
   compilés et leur hash. Une seule demande est autorisée à la fois.
5. Après exécution de l'agent, l'état devient `applied`,
   `rolled_back` ou `failed`. Le statut `applied` n'est présenté
   comme à jour que si le bundle actuellement attendu correspond au
   hash réellement appliqué. Toute nouvelle règle rend la configuration
   potentiellement obsolète.

Un redémarrage de NSD ne perd ni les demandes ni les résultats.
L'agent qui redémarre après un crash tente d'abord de restaurer toute
transaction locale marquée `in_progress`, avant de reprendre la file.

## Procédure d'installation : décision explicite de l'administrateur

**Ne pas exécuter ces étapes sur un NPM réel sans sauvegarde vérifiée
et accord de l'administrateur.** Ce guide décrit une installation
future, une fois la recette et les tests de bout en bout effectués.

Le script `scripts/nsd-host-agent.py` est sans effet sans `--apply` :

```bash
python3 scripts/nsd-host-agent.py
# PLAN UNIQUEMENT
```

Avant la première migration, sauvegarder tout
`/data/nginx/custom/`, vérifier le chargement réel des trois bases
GeoIP2 dans `/var/lib/geoip`, le module installé dans
`root_top.conf`, les chemins de logs et les exceptions d'accès LAN.

L'administrateur demande **d'abord** l'application depuis la web UI.
Le premier amorçage, qui sauvegarde les deux fichiers NPM existants
avant de les remplacer par les hooks minimalistes, nécessite
une approbation spécifique :

```bash
python3 scripts/nsd-host-agent.py \
  --apply --bootstrap --confirm MIGRER_NPM_SEC \
  --url https://nsd.exemple.fr \
  --token-file /etc/nsd-agent/token \
  --container npm \
  --state-dir /var/lib/nsd-agent
```

Les mises à jour suivantes, après activation explicite du service
hôte, peuvent être traitées à la demande avec :

```bash
python3 scripts/nsd-host-agent.py \
  --apply --confirm AGENT_ENABLED \
  --url https://nsd.exemple.fr \
  --token-file /etc/nsd-agent/token \
  --container npm --state-dir /var/lib/nsd-agent
```

L'option `--loop --interval 15` permet à un service systemd hôte,
activé par un opérateur, de récupérer les nouvelles demandes. Ne pas
l'activer pendant la recette sur production : la première exécution
doit être contrôlée.

## Transaction de déploiement

1. Vérification du conteneur NPM et de la configuration actuellement
   chargée (`nginx -t`).
2. Vérification de l'empreinte du bundle et des **quatre noms exacts**
   attendus. Les données de configuration sont compilées depuis des
   champs typés côté NSD, jamais fournies sous forme de directives brutes
   depuis l'interface.
3. Sauvegarde locale des anciennes versions de tous les fichiers.
4. Copie des candidats dans le dossier NPM autorisé et renommages
   atomiques de chaque fichier.
5. Pour le premier bootstrap seulement : sauvegarde et remplacement
   des deux hooks natifs NPM par un seul include chacun.
6. Vérification `nginx -t` sur les snippets activés puis rechargement
   `nginx -s reload` (pas de `docker restart`).
7. Sur échec après mutation : restauration des fichiers sauvegardés,
   test et reload de l'ancienne configuration. La demande n'est pas
   marquée comme appliquée.
8. En cas de succès : sauvegarde du reçu local et transmission du
   statut à NSD. Un reçu local évite un second reload si l'agent redémarre
   après réussite mais avant l'accusé API.

Les sauvegardes sont conservées sous
`/var/lib/nsd-agent/backups/`. La récupération des transactions
interrompues est prioritaire sur toute nouvelle demande.

**Limites importantes :** `nginx -t` valide la syntaxe et les références
locales, mais ne prouve pas qu'un certificat, un backend ou un proxy
extérieur est accessible. Les tests GeoIP2 vrais et le fonctionnement
de la restauration restent obligatoires sur une instance de recette
équivalente à la production. Une coupure réseau après un reload peut
retarder l'accusé mais le reçu local permet une reprise idempotente.

## API réservée à l'agent

- `POST /agent/deployments/claim` : récupère au plus une demande et son
  bundle, ou `{"job":null}`. Une demande déjà réclamée est rendue de
  nouveau après redémarrage, pour récupération.
- `POST /agent/deployments/{id}/complete` : déclare `applied`,
  `rolled_back` ou `failed` avec le hash de la demande. Une
  modification concurrente ou une mauvaise empreinte est rejetée.
- Ces routes nécessitent l'en-tête `X-NSD-Agent-Token`, un secret
  distinct des comptes admin et des tokens d'API utilisateur.

Une mauvaise connexion HTTPS, des permissions laxistes sur le secret,
un manque de prérequis ou l'absence de confirmation conduisent à un
**refus explicite**, pas à une tentative de déploiement silencieuse.

Voir aussi [la feuille de route NSD](NSD_PRODUCT_ROADMAP.md).
