import { useEffect, useState } from "react";
import { getJson } from "../../services/api";
import type { Threat, ThreatSummary } from "./types";

export function ThreatsView() {
  const [events, setEvents] = useState<Threat[]>([]);
  const [summary, setSummary] = useState<ThreatSummary | null>(null);
  const [minimum, setMinimum] = useState(50);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError("");
    Promise.all([
      getJson<Threat[]>(`/threats?limit=100&min_score=${minimum}`, controller.signal),
      getJson<ThreatSummary>("/threats/summary", controller.signal),
    ]).then(([items, overview]) => { setEvents(items); setSummary(overview); })
      .catch(err => { if (!controller.signal.aborted) setError(String(err.message)); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [minimum]);
  return <section aria-label="Événements suspects">
    <p className="hint">Détections observées, pas des blocages automatiques. Les données de synthèse couvrent les sept derniers jours.</p>
    <label className="score-filter">Score minimum : {minimum}
      <input type="range" min="0" max="100" step="10" value={minimum}
        onChange={event => setMinimum(Number(event.target.value))} />
    </label>
    {loading && <p role="status">Chargement des menaces…</p>}
    {error && <p role="alert">{error}</p>}
    {!loading && !error && <>
      <div className="rankings">
        <Ranking title="Types détectés (7 jours)" entries={(summary?.by_type ?? []).map(x => [x.threat_type, x.count])}/>
        <Ranking title="IP suspectes (7 jours)" entries={(summary?.top_ips ?? []).slice(0, 10).map(x => [x.ip, x.count])}/>
      </div>
      <h3>Dernières détections (100 maximum)</h3>
      <div className="table-scroll"><table><thead><tr><th>Date</th><th>IP</th><th>Type</th><th>Score</th><th>Hôte</th><th>URI</th></tr></thead>
        <tbody>{events.map(item => <tr key={item.id}>
          <td>{item.created_at ?? "—"}</td><td>{item.ip}</td><td>{item.threat_type ?? "—"}</td>
          <td>{item.score}</td><td>{item.host ?? "—"}</td><td className="uri-cell" title={item.uri}>{item.uri ?? "—"}</td>
        </tr>)}</tbody></table></div>
      {events.length === 0 && <p>Aucune détection avec ce score minimum.</p>}
    </>}
  </section>;
}

function Ranking({ title, entries }: { title: string; entries: [string, number][] }) {
  return <section className="ranking"><h3>{title}</h3>
    {entries.length ? <ol>{entries.map(([label, count]) => <li key={label}><span>{label}</span><strong>{count}</strong></li>)}</ol>
      : <p>Aucune détection.</p>}
  </section>;
}
