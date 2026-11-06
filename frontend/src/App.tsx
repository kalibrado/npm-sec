import { useEffect, useState } from "react";
import { getJson } from "./services/api";
import { LoginView } from "./features/auth/LoginView";
import { logout, type AuthResponse, type User } from "./features/auth/authApi";
import { Overview } from "./features/dashboard/Overview";
import { LogsView } from "./features/logs/LogsView";
import { ThreatsView } from "./features/threats/ThreatsView";
import { ControlView } from "./features/control/ControlView";
import { SettingsView } from "./features/settings/SettingsView";
import { GeoView } from "./features/map/GeoView";
import { HealthView } from "./features/health/HealthView";
import { RulesView } from "./features/rules/RulesView";

const sections = ["Accueil", "Logs", "Menaces", "Centre de contrôle", "Règles", "Carte", "Santé", "Configuration"] as const;
const adminOnly = new Set<Section>(["Menaces", "Centre de contrôle", "Règles", "Santé", "Configuration"]);
type Section = typeof sections[number];

export function App() {
  const [section, setSection] = useState<Section>("Accueil");
  const [user, setUser] = useState<User | null>(null);
  const [checking, setChecking] = useState(true);
  const [authError, setAuthError] = useState("");
  useEffect(() => {
    const controller = new AbortController();
    getJson<AuthResponse>("/auth/me", controller.signal).then(result => setUser(result.user))
      .catch(() => { if (!controller.signal.aborted) setUser(null); })
      .finally(() => { if (!controller.signal.aborted) setChecking(false); });
    return () => controller.abort();
  }, []);
  if (checking) return <main className="login-page"><p role="status">Vérification de la session…</p></main>;
  if (!user) return <LoginView onLogin={setUser}/>;
  return <div className="shell">
    <aside className="sidebar"><h1>NSD <small>Security Dashboard</small></h1>
      <p className="session-user">{user.username} · {user.role}</p>
      <button className="logout-button" type="button" onClick={() => { void logout().then(() => { setUser(null); setSection("Accueil"); }).catch(err => setAuthError(String(err))); }}>Déconnexion</button>
      {authError && <p role="alert">{authError}</p>}
      <nav aria-label="Navigation principale">{sections.filter(item => user.role === "admin" || !adminOnly.has(item)).map(item =>
        <button key={item} type="button" aria-current={section === item ? "page" : undefined}
          onClick={() => setSection(item)}>{item}</button>)}</nav>
    </aside>
    <main id="content"><header><span>Nouvelle interface · Aperçu</span><strong>{section}</strong></header>
      <section className="panel" aria-labelledby="section-title">
        <h2 id="section-title">{section}</h2>
        {user.role !== "admin" && adminOnly.has(section) ? <p>Accès réservé aux administrateurs.</p> : section === "Accueil" ? <Overview /> : section === "Logs" ? <LogsView /> : section === "Menaces" ? <ThreatsView /> : section === "Centre de contrôle" ? <ControlView /> : section === "Configuration" ? <SettingsView /> : section === "Règles" ? <RulesView /> : section === "Carte" ? <GeoView /> : <HealthView />}
        <a href="/">Retour au tableau de bord actuel</a>
      </section>
    </main>
  </div>;
}
