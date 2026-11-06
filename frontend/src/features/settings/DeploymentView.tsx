import { useEffect, useState } from "react";
import { getJson } from "../../services/api";

type Job = { id: number; revision: number; status: string; requested_by: string;
  requested_at: string; completed_at?: string | null; result_message?: string | null };
type DeploymentRequest = { id: number; status: string; message: string };

export function DeploymentView({ revision }: { revision: number }) {
  const [jobs, setJobs] = useState<Job[]>([]);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [reload, setReload] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    getJson<Job[]>("/security-profile/deployments", controller.signal).then(setJobs)
      .catch(err => { if (!controller.signal.aborted) setError(String(err.message)); });
    return () => controller.abort();
  }, [reload]);
  const request = async () => {
    if (!window.confirm("Demander à l'agent d'appliquer les règles enregistrées ? Cette opération peut modifier Nginx.")) return;
    setBusy(true); setError(""); setMessage("");
    try {
      const response = await fetch("/security-profile/deployments/request", {
        method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ expected_revision: revision, confirmation: "APPLIQUER" }),
      });
      if (!response.ok) {
        const body: { detail?: string } = await response.json().catch(() => ({}));
        throw new Error(body.detail || `HTTP ${response.status}`);
      }
      const result: DeploymentRequest = await response.json();
      setMessage(`Demande #${result.id} créée. En attente de l'agent, application non confirmée.`);
      setReload(n => n + 1);
    } catch (err) { setError(err instanceof Error ? err.message : String(err)); }
    finally { setBusy(false); }
  };
  return <section aria-label="Déploiement des règles">
    <h3>Application des règles Nginx</h3>
    <p className="hint">La demande est traitée par l'agent hôte, avec validation Nginx et compte rendu. Une demande acceptée n'est pas une application réussie.</p>
    <div className="settings-actions"><button type="button" disabled={busy} onClick={() => void request()}>Demander l'application</button>
      <button type="button" disabled={busy} onClick={() => setReload(n => n + 1)}>Actualiser l'historique</button></div>
    {error && <p role="alert">{error}</p>}{message && <p role="status">{message}</p>}
    <div className="table-scroll"><table><thead><tr><th>Demande</th><th>Révision</th><th>État</th><th>Par</th><th>Créée</th><th>Résultat</th></tr></thead>
      <tbody>{jobs.map(job => <tr key={job.id}><td>#{job.id}</td><td>{job.revision}</td><td>{job.status}</td>
        <td>{job.requested_by}</td><td>{job.requested_at}</td><td>{job.result_message || "—"}</td></tr>)}</tbody></table></div>
    {jobs.length === 0 && <p>Aucune demande d'application enregistrée.</p>}
  </section>;
}
