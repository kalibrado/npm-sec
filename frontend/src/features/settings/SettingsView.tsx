import { useEffect, useState } from "react";
import { getJson } from "../../services/api";
import { SettingField } from "./SettingField";
import { DeploymentView } from "./DeploymentView";
import { RevisionHistory } from "./RevisionHistory";
import type { Preview, Profile, SettingValue } from "./types";

async function postJson<T>(url: string, payload: unknown): Promise<T> {
  const response = await fetch(url, { method: "POST", credentials: "same-origin",
    headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
  if (!response.ok) {
    const body: unknown = await response.json().catch(() => null);
    const detail = body && typeof body === "object" && "detail" in body ? JSON.stringify(body.detail) : response.statusText;
    throw new Error(`HTTP ${response.status}: ${detail}`);
  }
  return response.json() as Promise<T>;
}

export function SettingsView() {
  const [profile, setProfile] = useState<Profile | null>(null);
  const [settings, setSettings] = useState<Record<string, SettingValue>>({});
  const [preview, setPreview] = useState<Preview | null>(null);
  const [note, setNote] = useState("");
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    getJson<Profile>("/security-profile", controller.signal).then(data => {
      setProfile(data); setSettings(data.settings);
    }).catch(err => { if (!controller.signal.aborted) setError(String(err.message)); });
    return () => controller.abort();
  }, []);
  const update = (name: string, value: SettingValue) => {
    setSettings(previous => ({ ...previous, [name]: value }));
    setPreview(null); setMessage("");
  };
  const execute = async (action: "preview" | "save") => {
    if (!profile) return;
    setBusy(true); setError(""); setMessage("");
    try {
      if (action === "preview") {
        setPreview(await postJson<Preview>("/security-profile/preview", { settings }));
        setMessage("Aperçu généré, aucune règle appliquée.");
      } else {
        if (!preview) throw new Error("Prévisualiser les changements avant enregistrement.");
        await postJson("/security-profile/revisions", { settings, expected_revision: profile.revision, note });
        const refreshed = await getJson<Profile>("/security-profile");
        setProfile(refreshed); setSettings(refreshed.settings); setPreview(null); setNote("");
        setMessage("Nouvelle révision enregistrée. Aucun déploiement demandé.");
      }
    } catch (err) { setError(err instanceof Error ? err.message : String(err)); }
    finally { setBusy(false); }
  };
  if (!profile) return <p role={error ? "alert" : "status"}>{error || "Chargement des réglages…"}</p>;
  return <form onSubmit={e => { e.preventDefault(); void execute("preview"); }}>
    <p className="hint">Révision enregistrée : {profile.revision}. État du déploiement : {profile.deployment.message}</p>
    <div className="settings-grid">{Object.entries(profile.schema).map(([name, schema]) =>
      <SettingField key={name} name={name} schema={schema} value={settings[name]}
        onChange={value => update(name, value)}/>)}</div>
    <label className="setting-note">Note de modification <input maxLength={240} value={note} onChange={e => setNote(e.target.value)}/></label>
    <div className="settings-actions"><button type="submit" disabled={busy}>Prévisualiser</button>
      <button type="button" disabled={busy || !preview} onClick={() => void execute("save")}>Enregistrer une révision</button></div>
    {error && <p role="alert">{error}</p>}{message && <p role="status">{message}</p>}
    {preview && <section aria-label="Aperçu de configuration"><h3>Différences proposées</h3>
      <p className="hint">{preview.warning}</p>
      {preview.changed_files.length === 0 ? <p>Aucun changement dans les fichiers générés.</p> :
        preview.changed_files.map(name => <details key={name}><summary>{name}</summary>
          <pre className="diff-view">{preview.diff[name] || "Aucun diff textuel."}</pre></details>)}
    </section>}
    <RevisionHistory currentRevision={profile.revision} onRestored={async () => {
      const refreshed = await getJson<Profile>("/security-profile");
      setProfile(refreshed); setSettings(refreshed.settings); setPreview(null); setNote("");
    }}/>
    <DeploymentView revision={profile.revision}/>
  </form>;
}
