# NSD frontend (React + TypeScript + Vite)

Migration incrémentale : le tableau de bord historique reste la version active.

```sh
cd frontend
npm install
npm run dev
npm run build
```

Le serveur Vite proxifie `/api` vers FastAPI en développement. Le build produit des assets sous `static/react-app/`, servis par FastAPI. L'aperçu n'est pas encore substitué à `/`. Les vues React sont des placeholders, pas des fonctionnalités migrées. Ne pas déployer comme remplacement de l'interface actuelle.
