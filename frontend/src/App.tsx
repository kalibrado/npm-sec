import { useState } from "react";
import { Overview } from "./features/dashboard/Overview";
import { LogsView } from "./features/logs/LogsView";
import { ThreatsView } from "./features/threats/ThreatsView";
import { ControlView } from "./features/control/ControlView";
import { SettingsView } from "./features/settings/SettingsView";
import { GeoView } from "./features/map/GeoView";
import { HealthView } from "./features/health/HealthView";
import { RulesView } from "./features/rules/RulesView";

const sections = ["Accueil", "Logs", "Menaces", "Centre de contrôle", "Règles", "Carte", "Santé", "Configuration"] as const;
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
        {section === "Accueil" ? <Overview /> : section === "Logs" ? <LogsView /> : section === "Menaces" ? <ThreatsView /> : section === "Centre de contrôle" ? <ControlView /> : section === "Configuration" ? <SettingsView /> : section === "Règles" ? <RulesView /> : section === "Carte" ? <GeoView /> : <HealthView />}
        <a href="/">Retour au tableau de bord actuel</a>
      </section>
    </main>
  </div>;
}
