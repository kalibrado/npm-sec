import { useState } from "react";
import { Overview } from "./features/dashboard/Overview";
import { LogsView } from "./features/logs/LogsView";

const sections = ["Accueil", "Logs", "Menaces", "Centre de contrôle", "Carte", "Santé", "Configuration"] as const;
type Section = typeof sections[number];

export function App() {
  const [section, setSection] = useState<Section>("Accueil");
  return <div className="shell">
    <aside className="sidebar"><h1>NSD <small>Security Dashboard</small></h1>
      <nav aria-label="Navigation principale">{sections.map(item =>
        <button key={item} type="button" aria-current={section === item ? "page" : undefined}
          onClick={() => setSection(item)}>{item}</button>)}</nav>
    </aside>
    <main id="content"><header><span>Nouvelle interface · Aperçu</span><strong>{section}</strong></header>
      <section className="panel" aria-labelledby="section-title">
        <h2 id="section-title">{section}</h2>
        {section === "Accueil" ? <Overview /> : section === "Logs" ? <LogsView /> : <p>Cette vue est en cours de migration. Les fonctions de production restent disponibles dans l’interface actuelle.</p>}
        <a href="/">Retour au tableau de bord actuel</a>
      </section>
    </main>
  </div>;
}
