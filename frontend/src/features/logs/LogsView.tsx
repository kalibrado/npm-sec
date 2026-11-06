import { useEffect, useState } from "react";
import { getJson } from "../../services/api";
import type { AccessLog, HistoryResponse } from "./types";

export function LogsView() {
  const [query, setQuery] = useState("");
  const [search, setSearch] = useState("");
  const [mode, setMode] = useState("all");
  const [rows, setRows] = useState<AccessLog[]>([]);
  const [cursor, setCursor] = useState<number | null>(null);
  const [next, setNext] = useState<number | null>(null);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [page, setPage] = useState(0);
  const [live, setLive] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    const params = new URLSearchParams({ limit: "50", search });
    if (mode === "blocked") params.set("blocked_only", "true");
    if (mode === "allowed") params.set("allowed_only", "true");
    if (cursor !== null) params.set("cursor", String(cursor));
    setLoading(true);
    setError("");
    getJson<HistoryResponse>(`/history?${params}`, controller.signal)
      .then(result => { setRows(result.logs); setNext(result.next_cursor); setTotal(result.total); })
      .catch(err => { if (!controller.signal.aborted) setError(String(err.message)); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [search, mode, cursor, page]);
  useEffect(() => {
    if (!live || cursor !== null) return;
    const timer = window.setInterval(() => setPage(p => p + 1), 5000);
    return () => window.clearInterval(timer);
  }, [live, cursor]);
  const reset = () => { setCursor(null); setNext(null); setRows([]); setPage(p => p + 1); };
  return <section aria-label="Investigation des logs">
    <form className="log-filters" onSubmit={event => { event.preventDefault(); setSearch(query.trim()); reset(); }}>
      <label>Rechercher <input value={query} onChange={event => setQuery(event.target.value)} placeholder="IP, host, URI…" /></label>
      <label>Trafic <select value={mode} onChange={event => { setMode(event.target.value); reset(); }}>
        <option value="all">Tout</option><option value="blocked">Refusé</option><option value="allowed">Autorisé</option>
      </select></label>
      <button type="submit">Rechercher</button>
      <button type="button" onClick={reset}>Actualiser</button>
      <label><input type="checkbox" checked={live} onChange={e => { setLive(e.target.checked); reset(); }}/> Suivi automatique (5 s)</label>
    </form>
    {live && cursor !== null && <p className="hint">Suivi automatique suspendu pendant la pagination.</p>}
    <p className="hint" role="status">{loading ? "Chargement…" : `${total.toLocaleString("fr-FR")} événements correspondent aux filtres`}</p>
    {error && <p role="alert">{error}</p>}
    <div className="table-scroll"><table><thead><tr><th>Date</th><th>IP</th><th>Host</th><th>Méthode</th><th>URI</th><th>HTTP</th><th>Décision</th></tr></thead>
      <tbody>{rows.map(row => <tr key={row.id}>
        <td>{row.timestamp ?? "—"}</td><td>{row.ip ?? "—"}</td><td>{row.host ?? "—"}</td>
        <td>{row.method ?? "—"}</td><td className="uri-cell" title={row.uri}>{row.uri ?? "—"}</td>
        <td>{row.status ?? "—"}</td><td>{row.blocked ? "Refusé" : "Autorisé"}</td>
      </tr>)}</tbody></table></div>
    {!loading && !error && rows.length === 0 && <p>Aucun événement pour ces filtres.</p>}
    <div className="pager"><button disabled={loading || !next || rows.length === 0} onClick={() => setCursor(next)}>Afficher les 50 suivants</button></div>
  </section>;
}
