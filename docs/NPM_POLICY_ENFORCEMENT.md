# Application des règles NPM Security dans Nginx Proxy Manager

## Sécurité et fonctionnement

Le dashboard écrit les règles dans son dossier `/data/exports` et **n'a pas accès au socket Docker**.
Un script d'administration facultatif, lancé sur l'hôte Docker de NPM, installe les règles,
vérifie la syntaxe avec `nginx -t`, recharge Nginx avec `nginx -s reload` et revient
aux fichiers précédents si une étape échoue.

**L'enregistrement d'une IP ou d'un pays dans le dashboard ne déclenche pas automatiquement
un blocage Nginx** sans ce mécanisme d'application et ses includes NPM.

## Règles globales et règles par domaine

Une règle de blocage peut porter sur tous les proxy hosts (champ `host` vide)
ou viser **un nom de domaine exact** tel que `cloud.kaliorbis.fr`.

Depuis l'API admin `POST /blocklist`, envoyer par exemple :

```json
{
  "type": "country",
  "value": "CN",
  "host": "cloud.kaliorbis.fr",
  "duration_minutes": 1440,
  "reason": "Blocage ciblé Nextcloud"
}
```

Le même code pays peut être utilisé sur plusieurs domaines distincts et en
parallèle sur la portée globale. `GET /blocklist` liste toutes les règles ;
`GET /blocklist?host=cloud.kaliorbis.fr` filtre le domaine exact ;
`GET /blocklist?host=` montre uniquement les règles globales.

La configuration exportée utilise :
- des directives `geo` dédiées à chaque domaine pour les IP et CIDR ;
- des directives `map` sur `$host` pour choisir la règle de ce domaine ;
- un `map` sur `$host:$geoip2_data_country_code` pour les pays ciblés ;
- la même priorité des exceptions IP/CIDR de confiance sur tous les domaines.

Un blocage global et un blocage ciblé se cumulent. La portée **n'est pas
une exception à un blocage global**. Les domaines wildcard, les URLs avec
schéma, les ports et les syntaxes Nginx sont refusés. Le champ doit être un
nom DNS exact ASCII, en punycode pour les domaines internationalisés.

Les règles sont associées à la variable Nginx `$host`. Confirmer que les
`server_name` de NPM correspondent à ces domaines et que l'IP cliente
réelle est résolue à partir de proxies de confiance. Pour les domaines
derrière un CDN, une configuration `real_ip_header` non maîtrisée peut
fausser les décisions, voire autoriser une usurpation.

**Le dashboard écrit uniquement les exports.** Une règle en attente ne
s'applique qu'après le contrôle et le rechargement Nginx décrits ci-dessous.

## Préparation initiale sur l'hôte NPM

Les points d'inclusion officiels NPM sont :
- `/data/nginx/custom/http_top.conf` dans le contexte HTTP ;
- `/data/nginx/custom/server_proxy.conf` dans les serveurs proxy.

1. Générer les exports depuis le dashboard (action « Appliquer export » ou `POST /blocklist/export/apply` avec une session admin). Prévoir un montage ou un transfert sécurisé de `data/exports` sur l'hôte NPM.
2. Créer les fichiers initiaux dans NPM **avant** d'activer les includes :

```bash
docker exec npm mkdir -p /data/nginx/custom/npm-security
docker cp ./data/exports/npm-blocklist.conf npm:/data/nginx/custom/npm-security/npm-blocklist.conf
docker cp ./data/exports/npm-server-guard.conf npm:/data/nginx/custom/npm-security/npm-server-guard.conf
```

3. Ajouter la ligne suivante à la fin de `/data/nginx/custom/http_top.conf`, en conservant les paramètres déjà présents :

```nginx
include /data/nginx/custom/npm-security/npm-blocklist.conf;
```

4. Ajouter la ligne suivante à la fin de `/data/nginx/custom/server_proxy.conf` :

```nginx
include /data/nginx/custom/npm-security/npm-server-guard.conf;
```

5. Vérifier et recharger NPM (depuis l'hôte) :

```bash
docker exec npm nginx -t
docker exec npm nginx -s reload
```

6. Sur l'hôte NPM, depuis une copie locale du projet dont `./data/exports` pointe
vers le dossier des exports du dashboard :

```bash
NPM_CONTAINER=npm EXPORT_DIR=./data/exports bash scripts/npm-sec-apply.sh
```

Le script **refuse** de s'exécuter lorsque les includes ne sont pas configurés ou
les fichiers initiaux n'existent pas. Il laisse `main` et les conteneurs de production
inchangés tant que l'administrateur ne l'exécute pas. On pourra ensuite le déclencher
par un service systemd `.path` dédié sur l'hôte, après tests et sauvegarde des fichiers NPM.

## Activer GeoIP2 pour le blocage pays

Le blocage des IP/CIDR fonctionne sans base GeoIP2. Si des pays sont bloqués,
la variable Nginx `$geoip2_data_country_code` doit être fournie par le module GeoIP2
et la base MaxMind GeoLite2 Country. Vérifier la disponibilité du module sur la
version installée de NPM, puis configurer le module dans
`/data/nginx/custom/root_top.conf` :

```nginx
load_module /usr/lib/nginx/modules/ngx_http_geoip2_module.so;
```

Dans le même fichier `http_top.conf`, **avant l'include NPM Security** :

```nginx
geoip2 /data/geoip2/GeoLite2-Country.mmdb {
    $geoip2_data_country_code country iso_code;
}
```

La base MMDB doit effectivement exister dans le conteneur NPM et être maintenue à jour.
La configuration globale d'adresses IP réelles `real_ip_header` / `set_real_ip_from`
doit être évaluée : n'accepter les headers de proxy que de proxies en qui on a confiance.
L'accès admin, VPN et réseaux privés doit être testé avant de bloquer un pays.

## Simuler une politique avant de l'appliquer

Pour tester la politique enregistrée sur un domaine sans modifier NPM :

```bash
curl -G 'http://localhost:8000/security-control/policy/preview' \
  -H "X-Admin-Token: <token-admin>" \
  --data-urlencode 'ip=203.0.113.20' \
  --data-urlencode 'host=cloud.kaliorbis.fr' \
  --data-urlencode 'country_code=CN'
```

La réponse décrit les règles IP/CIDR et pays correspondantes, les
exceptions IP/CIDR prioritaires et la décision **prévue en base**.
Lorsque le pays manque et qu'une règle géographique pourrait modifier
la décision, le résultat est indéterminé. Le statut `policy` donne
la dernière preuve de chargement des exports, pas l'état permanent
du proxy réel.

La simulation ne déclenche aucun rechargement et ne remplace jamais
un test de connectivité depuis les réseaux/continents concernés.

## Audit du déploiement

`GET /blocklist/deployment` (admin) renvoie :
- `not_configured` : les exports nécessaires sont absents ;
- `pending` : fichiers exportés non confirmés par le script d'application ;
- `applied` : les hashes sont identiques à ceux de la dernière validation + recharge du script.

`applied` signifie **dernière application confirmée par le script**, pas une vérification
permanente de l'état d'un NPM modifié en dehors de ce script. Une modification ultérieure
des exports fait automatiquement revenir l'état à `pending`.

## Reprise d'urgence

Si une règle coupe un accès indispensable, copier les fichiers
`npm-blocklist.conf.previous` et `npm-server-guard.conf.previous` vers leurs noms actifs,
tester puis recharger :

```bash
docker exec npm cp /data/nginx/custom/npm-security/npm-blocklist.conf.previous /data/nginx/custom/npm-security/npm-blocklist.conf
docker exec npm cp /data/nginx/custom/npm-security/npm-server-guard.conf.previous /data/nginx/custom/npm-security/npm-server-guard.conf
docker exec npm nginx -t
docker exec npm nginx -s reload
```

Les lignes de confiance `trusted_entries` IP/CIDR et les réseaux internes protègent
contre les blocages NPM. Les entrées de confiance par country/UA ne sont **pas**
des exemptions au niveau Nginx, afin qu'un User-Agent falsifié ne puisse pas contourner
la politique réseau.

Documentation officielle : https://nginxproxymanager.com/advanced-config/
