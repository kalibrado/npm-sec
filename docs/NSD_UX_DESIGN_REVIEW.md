# NSD — Revue UX/UI initiale (04/11/2026)

Statut : **proposition de design**, sans modification de l'interface ni activation NPM. Branche issue de `dev`.

## Constat documentaire vérifié

Le README de `dev` décrit un dashboard FastAPI avec onglets **Centre de contrôle**, **Listes de sécurité** et **Logs**, une navigation mobile **Plus → Listes**, une fiche IP et des actions de blocage soumises à confirmation. La feuille de route distingue déjà les refus réellement observés des règles enregistrées, les états de publication et les rôles admin/lecture seule.

Cette revue est **documentaire** : aucune capture d'écran ni recette visuelle du rendu actuel n'a été réalisée. Les points ci-dessous sont des hypothèses de conception à valider, pas des défauts observés.

## Principes de design

1. **Vérité opérationnelle** : distinguer partout « règle enregistrée », « candidat validé », « appliquée avec preuve » et « blocage observé ». Jamais de KPI qui assimile une règle à un refus effectif.
2. **Action sûre** : lecture et exploration immédiates ; modifications sous rôle admin, confirmation explicite, aperçu/diff, et déploiement désactivé en recette par défaut.
3. **Fraîcheur visible** : horodatage des dernières données, santé du collecteur, source du log et éventuel retard. Une série vide n'est pas présentée comme un trafic nul si la collecte est en panne.
4. **Navigation prévisible** : structure identique sur desktop et mobile ; états vides, erreurs, chargements et accès clavier.
5. **Progressivité** : garder FastAPI/JS/SSE actuels ; pas de réécriture frontend avant mesure d'un besoin.

## Architecture d'information cible

Navigation principale :
- **Vue d'ensemble** : KPIs, évolution du trafic, refus réellement observés, menaces, top IP/pays/URI, état des composants et alertes.
- **Journal temps réel** : flux SSE, pause/reprise, filtres, détail de requête et provenance.
- **Menaces** : signaux, score explicable, enquête IP et événements corrélés.
- **Carte** : géolocalisation 2D, états normal/suspect/refusé, échantillonnage explicite.
- **Politiques** : règles, listes et exceptions, priorité, durée, statut enregistré/appliqué.
- **Configuration** : paramètres typés, valeurs héritées, brouillons, validation, diff, historique et restauration.
- **Santé & audit** : collecteur, NPM/Nginx/NSD, agent, certificats, événements administratifs.

## Premier écran à réaliser : Vue d'ensemble

Ordre de lecture recommandé :
1. Barre de contexte : environnement **recette/production**, période, dernière ingestion, statut collecte, statut politique.
2. KPIs distincts : requêtes observées, refus **observés**, menaces détectées, règles **enregistrées**, bans **effectivement appliqués** si preuve disponible.
3. Courbe de trafic avec répartition succès/4xx/5xx/refus observés ; indication explicite des données manquantes.
4. Colonnes « Menaces récentes » et « Top IP / pays / URI » ; accès direct aux détails filtrés.
5. État infra et alertes prioritaires ; pas de faux « tout est sain » si sonde absente.

### Comportements et états

- **Collecte retardée** : bandeau d'avertissement avec dernier événement et source, pas de compteurs artificiellement à zéro.
- **Aucune donnée** : écran vide explicatif, lien vers diagnostic des logs, pas d'illustration qui masque l'erreur.
- **Mode lecture seule** : aucune action de mutation affichée comme disponible ; protection impérative côté serveur.
- **Enquête IP** : panneau latéral accessible depuis les tableaux ; informations, preuves et historique avant toute action.
- **Blocage** : confirmation, périmètre, durée et avertissement « enregistré ≠ appliqué » ; jamais de bannissement automatique par défaut.
- **Responsive** : priorité à la période, aux statuts et aux KPIs ; tableaux horizontaux défilables et filtres repliables sur mobile.
- **Accessibilité** : contraste WCAG AA visé, focus visible, navigation clavier, labels textuels en plus des couleurs, support `prefers-reduced-motion`.

## Direction visuelle proposée

Thème sombre bleu nuit, surfaces neutres, accent cyan réservé à la navigation et aux liens. Orange = avertissement, rouge = critique/refus confirmé, vert = santé prouvée. La couleur ne constitue jamais l'unique indicateur d'état. Typographie système, chiffres tabulaires, densité ajustée pour desktop ; animations discrètes et désactivables.

## Découpage de livraison

- **Design 1 (ce document)** : cadrage, inventaire documentaire, hiérarchie de navigation et critères d'acceptation. Aucun code UI modifié.
- **Design 2** : inventorier les vrais composants/routes/API de `dev`, auditer le rendu desktop/mobile avec captures de recette, puis établir les écarts et une liste de composants réutilisables.
- **Design 3** : implémenter uniquement l'en-tête de contexte et les états de fraîcheur des données sur la Vue d'ensemble, avec tests d'affichage et permissions.
- **Design 4** : normaliser les KPIs et les interactions d'enquête ; tests E2E.

## Critères d'acceptation de la revue

- Chaque KPI a une source, une période, un état de fraîcheur et une définition documentés.
- Aucune confusion visuelle entre **configuré**, **validé**, **appliqué** et **observé**.
- Aucune action dangereuse ni aucun reload NPM ajouté par les changements de design.
- Navigation clavier et affichage mobile testés avant validation d'un changement UI.
- La branche `main` et l'instance NPM réelle ne sont jamais modifiées par ce chantier.
