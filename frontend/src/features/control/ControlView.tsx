import { useEffect, useState } from "react";
import { getJson } from "../../services/api";
import type { ControlOverview, Suspect } from "./types";

export function ControlView() {
  const [hours, setHours] = useState(24);
  const [overview, setOverview] = useState<ControlOverview | null>(null);
  const [suspects, setSuspects] = useState<Suspect[]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError("");
    Promise.all([
      getJson<ControlOverview>(`/security-control/overview?hours=${hours}`, controller.signal),
      getJson<Suspect[]>(`/security-control/suspects?hours=${hours}&limit=30`, controller.signal),
    ]).then(([status, ips]) => { setOverview(status); setSuspects(ips); })
      .catch(err => { if (!controller.signal.aborted) setError(String(err.message)); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [hours]);
  return <section aria-label="Centre de contrôle de sécurité">
    <p className="hint">État des règles enregistrées et événements observés. Une règle présente n'implique pas son application effective par Nginx.</p>
    <label className="control-period">Période <select value={hours} onChange={event => setHours(Number(event.target.value))}>
      <option value={1}>1 heure</option><option value={24}>24 heures</option><option value={168}>7 jours</option>
    </select></label>
    {loading && <p role="status">Chargement du centre de contrôle…</p>}
    {error && <p role="alert">{error}</p>}
    {!loading && !error && overview && <>
      <div className="metrics">
        <Metric title="Règles enregistrées" value={overview.rules.active_total}/>
        <Metric title="Entrées de confiance" value={overview.rules.trusted_total}/>
        <Metric title="Refus observés" value={overview.traffic.proxy_blocked}/>
        <Metric title="Signaux suspects" value={overview.detections.signals}/>
      </div>
      <p>Auto-ban : <strong>{overview.auto_ban_mode}</strong></p>
      <h3>IP à examiner</h3>
      <div className="table-scroll"><table><thead><tr><th>IP</th><th>Score maximal</th><th>Signaux</th><th>Confiance</th><th>Règle enregistrée</th></tr></thead>
        <tbody>{suspects.map(item => <tr key={item.ip}>
          <td>{item.ip}</td><td>{item.max_score}</td><td>{item.signals}</td>
          <td>{item.trusted ? "Oui" : "Non"}</td><td>{item.block_rule ? `${item.block_rule.type}: ${item.block_rule.value}` : "Aucune"}</td>
        </tr>)}</tbody></table></div>
      {suspects.length === 0 && <p>Aucune IP suspecte dans cette période.</p>}
      <p className="hint">Les actions de blocage restent disponibles dans le tableau de bord historique pendant la migration.</p>
    </>}
  </section>;
}

function Metric({ title, value }: { title: string; value: number }) {
  return <article className="metric"><span>{title}</span><strong>{value.toLocaleString("fr-FR")}</strong></article>;
}
