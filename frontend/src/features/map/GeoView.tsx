import { useEffect, useState } from "react";
import { getJson, type Stats } from "../../services/api";

export function GeoView() {
  const [countries, setCountries] = useState<Stats["top_countries"]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    const controller = new AbortController();
    getJson<Stats>("/stats", controller.signal).then(stats => setCountries(stats.top_countries))
      .catch(err => { if (!controller.signal.aborted) setError(String(err.message)); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, []);
  const max = Math.max(1, ...countries.map(item => item.count));
  return <section aria-label="Répartition géographique du trafic">
    <p className="hint">Répartition des requêtes observées par pays. Cette synthèse ne représente pas encore la carte interactive historique.</p>
    {loading && <p role="status">Chargement des données géographiques…</p>}
    {error && <p role="alert">{error}</p>}
    {!loading && !error && (countries.length ? <div className="country-bars">{countries.map(country =>
      <div className="country-row" key={country.country_code}>
        <span>{country.country_code || "Inconnu"}</span>
        <div className="country-track"><div className="country-fill" style={{ width: `${country.count / max * 100}%` }}/></div>
        <strong>{country.count.toLocaleString("fr-FR")}</strong>
      </div>)}</div> : <p>Aucune donnée géographique disponible.</p>)}
  </section>;
}
