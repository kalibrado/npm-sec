import { useState } from "react";
import { login, type User } from "./authApi";

export function LoginView({ onLogin }: { onLogin: (user: User) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  return <main className="login-page"><form className="login-form" onSubmit={async event => {
    event.preventDefault(); setBusy(true); setError("");
    try { onLogin(await login(username, password)); }
    catch (err) { setError(err instanceof Error ? err.message : String(err)); }
    finally { setBusy(false); }
  }}>
    <h1>NSD</h1><p>Connexion au tableau de bord de sécurité</p>
    <label>Utilisateur <input autoComplete="username" required value={username} onChange={e => setUsername(e.target.value)}/></label>
    <label>Mot de passe <input type="password" autoComplete="current-password" required value={password} onChange={e => setPassword(e.target.value)}/></label>
    <button type="submit" disabled={busy}>{busy ? "Connexion…" : "Se connecter"}</button>
    {error && <p role="alert">{error}</p>}
  </form></main>;
}
