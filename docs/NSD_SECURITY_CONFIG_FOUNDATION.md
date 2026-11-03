# NSD : prise en charge de la configuration historique de Nginx

Cette fonctionnalité crée les **fondations** de l'éditeur de sécurité du
futur Nginx Security Dashboard. Elle ne remplace **pas encore** la
configuration NPM de production et ne propose **pas encore** un bouton
d'application réel. Les réglages existants continuent à fonctionner
inchangés tant que l'agent d'application n'est pas installé et validé.

## Responsabilités

NPM conserve proxy hosts, certificats, routage et ses deux points
d'extension habituels. Les directives de sécurité seront compilées par
NSD à partir de paramètres typés et de règles enregistrées. En cible,
`/data/nginx/custom/http_top.conf` et
`/data/nginx/custom/server_proxy.conf` contiendront chacun un simple
`include`, pointant vers le dernier profil validé.

Les fichiers Git `config/nginx-managed/http-security.conf` et
`config/nginx-managed/server-security.conf` constituent une **copie de
référence initiale** de la configuration historique communiquée le
03/11/2026, pas une source de vérité opératoire à éditer manuellement.

Le script `scripts/npm-sec-migrate-nginx.py` propose une commande de
planification **sans modification**, mais son action `--apply` est
volontairement bloquée tant que l'agent hôte et son contrat de
validation/déploiement des révisions ne sont pas livrés. Le rollback
de sauvegardes antérieures reste implémenté pour un éventuel secours.

## Éditeur Web UI

Dans **Configuration → Configuration de sécurité NSD**, huit paramètres
sont éditables dans ce premier lot :

1. Requêtes par seconde et par IP (100 par défaut).
2. Rafale autorisée avant 429 (70 par défaut).
3. Pays autorisés par l'ancien filtre (FR par défaut).
4. Réseaux locaux exemptés de géoblocage
   (127.0.0.1/32, 192.168.1.0/24).
5. Signatures simples User-Agent des scanners (les neuf signatures
   héritées).
6. Activation/désactivation du filtre géographique historique.
7. Refus des User-Agents vides.
8. Code de refus 444 ou 403 pour la partie historique.

Chaque champ affiche sa valeur, son défaut et sa description.
Les paramètres sont validés côté serveur : type, bornes, CIDR, pays,
signatures non interprétées comme directives arbitraires.

Le bouton **Prévisualiser et vérifier** compare le candidat à la
dernière révision enregistrée et affiche un diff Nginx. **Il n'exécute
pas `nginx -t`** et ne prétend pas avoir validé le runtime NPM.

Le bouton **Enregistrer une révision** écrit exclusivement en SQLite
une nouvelle version immutable. Motif obligatoire de 5 à 240 caractères.
L'API impose le numéro de révision attendu, pour ne pas perdre
silencieusement les modifications d'un autre administrateur.

La restauration d'une révision ancienne **crée une nouvelle révision**,
sans supprimer l'historique et sans toucher à NPM.

### API

- `GET /security-profile` : champs, valeurs, défauts, révision, histoire,
  message d'attente de déploiement.
- `POST /security-profile/preview` :
  `{"settings":{...}}` : validation, hash du bundle candidat, diff.
- `POST /security-profile/revisions` :
  `{"settings":{...},"expected_revision":0,"note":"Motif..."}`.
- `GET /security-profile/revisions`, `GET /security-profile/revisions/{id}`.
- `POST /security-profile/revisions/{id}/restore` :
  `{"expected_revision":N}`.

Tous ces endpoints exigent le rôle administrateur et renvoient `403`
aux comptes lecture seule. Les paramètres enregistrés sont **des
brouillons** : aucun bouton ne déclenche de reload Nginx.

## Limites documentées et étapes suivantes

Le profil de référence couvre également les autres directives héritées
(GeoIP2 MMDB, rate-limit, reverse-proxy headers, pages d'erreur, chemins
sensibles, logs détaillés et exclusions LAN), mais plusieurs d'entre
elles **ne sont pas encore éditables dans ce premier lot**.

À développer avant toute migration production :

- Couvrir toutes les valeurs par un schéma éditable, y compris
  headers, GeoIP, chemins, types de règles, WAF, alertes et notifications.
- Unifier l'édition des IP, CIDR, pays, chemins, UA et méthodes avec
  priorités, durée de vie et visibilité des règles réellement effectives.
- Produire un bundle candidat immutable depuis la révision SQLite,
  le valider avec une instance Nginx de recette puis `nginx -t` sur le
  NPM cible, avant publication atomique.
- Déployer un agent hôte indépendant, à permissions minimales,
  sans socket Docker dans le dashboard : backup, test, reload gracieux,
  accusé d'application, restauration automatique si une étape échoue.
- Procéder à la migration initiale depuis la Web UI **avec
  confirmation explicite de l'utilisateur**, sans écraser
  `root_top.conf` ni casser les certificats et les sites.

Le géoblocage FR historique et les restrictions User-Agent continueront
à s'appliquer même si le **moteur dynamique** NSD passe en observation.
La différence doit rester visible dans l'interface : `observe`
ne suspend pas les protections legacy.

Les tests CI utilisent un Nginx local jetable et simulent les pays
par des variables de test. Ils ne garantissent pas la disponibilité
du module GeoIP2 ni des trois bases MMDB sur ton NPM réel. Avant un
premier déploiement, vérifier aussi l'identité IP réelle des visiteurs,
les plages `set_real_ip_from`, les chemins de logs et les fichiers
de pages d'erreur.

Voir [la feuille de route complète](NSD_PRODUCT_ROADMAP.md).
