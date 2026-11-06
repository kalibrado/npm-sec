# NSD frontend (React + TypeScript + Vite)

L'interface React est accessible à **/app** après compilation. L'interface historique reste accessible à **/**.

```sh
cd frontend
npm ci
npm run build
# Démarrer FastAPI selon votre déploiement habituel, puis ouvrir /app
```

En développement, `npm run dev` proxifie les endpoints FastAPI sans préfixe vers `127.0.0.1:8000`.

Fonctionnalités React disponibles : authentification par session, accueil, logs, menaces, centre de contrôle, blocages IP/CIDR/pays et exceptions de confiance, configuration versionnée avec prévisualisation, demandes d'application par agent hôte, santé et synthèse géographique.

**Limites actuelles** : la vue géographique est une répartition par pays, pas la carte interactive historique. Certaines fonctions avancées de l'ancienne interface restent à migrer. La demande d'application Nginx nécessite un agent hôte configuré et ne signifie pas que les règles ont été appliquées. Ne pas supprimer l'interface historique avant parité fonctionnelle.
