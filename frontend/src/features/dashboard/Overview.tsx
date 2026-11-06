import { useEffect, useState } from "react";
import { getJson, type Stats } from "../../services/api";

export function Overview() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    const controller = new AbortController();
    getJson<Stats>("/stats", controller.signal).then(setStats).catch(err => {
      if (!controller.signal.aborted) setError(String(err.message));
    }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, []);
  if (loading) return <p role="status">Chargement des statistiques…</p>;
  if (error) return <p role="alert">Impossible de charger les statistiques : {error}</p>;
  if (!stats) return <p>Aucune statistique disponible.</p>;
  const metrics = [
    ["Requêtes observées", stats.total],
    ["Requêtes autorisées", stats.allowed],
    ["Refus observés", stats.blocked],
    ["Taux de refus", `${stats.block_rate} %`],
  ] as const;
  return <>
    <p className="hint">Statistiques historiques des logs ingérés. Les règles enregistrées ne sont pas comptées comme des blocages effectifs.</p>
    <div className="metrics">{metrics.map(([label, value]) => <article className="metric" key={label}>
      <span>{label}</span><strong>{value.toLocaleString("fr-FR")}</strong>
    </article>)}</div>
    <div className="rankings">
      <Ranking title="IP les plus refusées" items={stats.top_attackers.map(x => [x.ip, x.count])}/>
      <Ranking title="URI les plus refusées" items={stats.top_uris.map(x => [x.uri, x.count])}/>
    </div>
  </>;
}

function Ranking({ title, items }: { title: string; items: [string, number][] }) {
  return <section className="ranking"><h3>{title}</h3>{items.length ?
    <ol>{items.map(([name, count]) => <li key={name}><span>{name}</span><strong>{count}</strong></li>)}</ol> :
    <p>Aucune donnée observée.</p>}</section>;
}
