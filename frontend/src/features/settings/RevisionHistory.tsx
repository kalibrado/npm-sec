import { useEffect, useState } from "react";
import { getJson } from "../../services/api";

type Revision = { id: number; created_at: string; created_by: string; note?: string; parent_revision?: number };
export function RevisionHistory({ currentRevision, onRestored }: { currentRevision: number; onRestored: () => Promise<void> }) {
  const [items, setItems] = useState<Revision[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [reload, setReload] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    getJson<Revision[]>("/security-profile/revisions", controller.signal).then(setItems)
      .catch(err => { if (!controller.signal.aborted) setError(String(err.message)); });
    return () => controller.abort();
  }, [reload, currentRevision]);
  const restore = async (item: Revision) => {
    if (!window.confirm(`Restaurer la révision #${item.id} ? Une nouvelle révision sera créée, sans application automatique dans Nginx.`)) return;
    setBusy(true); setError(""); setMessage("");
    try {
      const response = await fetch(`/security-profile/revisions/${item.id}/restore`, {
        method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ expected_revision: currentRevision }),
      });
      if (!response.ok) {
        const body: { detail?: unknown } = await response.json().catch(() => ({}));
        throw new Error(body.detail ? JSON.stringify(body.detail) : `HTTP ${response.status}`);
      }
      await onRestored();
      setMessage(`Révision #${item.id} restaurée dans une nouvelle révision. Application Nginx non demandée.`);
      setReload(n => n + 1);
    } catch (err) { setError(err instanceof Error ? err.message : String(err)); }
    finally { setBusy(false); }
  };
  return <section aria-label="Historique des révisions"><h3>Historique et restauration</h3>
    <p className="hint">La restauration crée une révision versionnée. Elle ne déclenche pas de déploiement.</p>
    <button type="button" disabled={busy} onClick={() => setReload(n => n + 1)}>Actualiser</button>
    {error && <p role="alert">{error}</p>}{message && <p role="status">{message}</p>}
    <div className="table-scroll"><table><thead><tr><th>Révision</th><th>Date</th><th>Auteur</th><th>Note</th><th>Action</th></tr></thead>
      <tbody>{items.map(item => <tr key={item.id}><td>#{item.id}{item.id === currentRevision ? " (active)" : ""}</td>
        <td>{item.created_at}</td><td>{item.created_by}</td><td>{item.note || "—"}</td>
        <td><button type="button" disabled={busy || item.id === currentRevision} onClick={() => void restore(item)}>Restaurer</button></td>
      </tr>)}</tbody></table></div>
  </section>;
}
