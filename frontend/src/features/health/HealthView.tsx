import { useEffect, useState } from "react";
import { getJson } from "../../services/api";

type NpmHealth = { total: number; server_errors: number; server_error_rate: number;
  top_error_status?: { status: number; count: number }[] };
type Ingestion = Record<string, unknown>;

export function HealthView() {
  const [health, setHealth] = useState<NpmHealth | null>(null);
  const [ingestion, setIngestion] = useState<Ingestion | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true); setError("");
    Promise.all([getJson<NpmHealth>("/npm-health", controller.signal),
      getJson<Ingestion>("/health/ingestion", controller.signal)])
      .then(([npm, collector]) => { setHealth(npm); setIngestion(collector); })
      .catch(err => { if (!controller.signal.aborted) setError(String(err.message)); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [refresh]);
  return <section aria-label="Santé des services">
    <p className="hint">Diagnostic en lecture seule. Les erreurs HTTP proviennent des logs ingérés.</p>
    <button type="button" className="action-button" onClick={() => setRefresh(n => n + 1)}>Actualiser</button>
    {loading && <p role="status">Chargement du diagnostic…</p>}
    {error && <p role="alert">{error}</p>}
    {!loading && !error && health && <>
      <div className="metrics">{[
        ["Requêtes observées", health.total], ["Erreurs HTTP 5xx", health.server_errors],
        ["Taux d'erreur 5xx", `${health.server_error_rate} %`],
      ].map(([label, value]) => <article className="metric" key={label}>
        <span>{label}</span><strong>{typeof value === "number" ? value.toLocaleString("fr-FR") : value}</strong>
      </article>)}</div>
      <details><summary>Diagnostic du collecteur</summary><pre className="diff-view">{JSON.stringify(ingestion, null, 2)}</pre></details>
    </>}
  </section>;
}
