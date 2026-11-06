import { useEffect, useState } from "react";
import { ruleApi } from "./RuleApi";
import type { Rule, RuleType, Trusted } from "./types";

export function RulesView() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [trusted, setTrusted] = useState<Trusted[]>([]);
  const [type, setType] = useState<RuleType>("ip");
  const [value, setValue] = useState("");
  const [reason, setReason] = useState("");
  const [trust, setTrust] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  useEffect(() => {
    const controller = new AbortController();
    ruleApi.load(controller.signal).then(([blocked, safe]) => {
      setRules(blocked); setTrusted(safe);
    }).catch(err => { if (!controller.signal.aborted) setError(String(err.message)); });
    return () => controller.abort();
  }, [refresh]);
  const execute = async (action: () => Promise<unknown>, confirmation?: string) => {
    if (confirmation && !window.confirm(confirmation)) return;
    setBusy(true); setError(""); setMessage("");
    try { await action(); setRefresh(n => n + 1); setMessage("Modification enregistrée. Application Nginx non confirmée."); }
    catch (err) { setError(err instanceof Error ? err.message : String(err)); }
    finally { setBusy(false); }
  };
  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    const target = value.trim();
    if (!target) return;
    void execute(() => trust ? ruleApi.addTrust(type, target, reason) : ruleApi.addBlock(type, target, reason),
      `Confirmer l'ajout de ${target} dans ${trust ? "les exceptions" : "la liste de blocage"} ?`);
  };
  return <section aria-label="Règles IP, CIDR et pays">
    <p className="hint">Les modifications sont enregistrées et exportées. Leur application effective par Nginx doit être vérifiée séparément.</p>
    <form className="rule-form" onSubmit={submit}>
      <label>Action <select value={trust ? "trust" : "block"} onChange={e => { setTrust(e.target.value === "trust"); if (e.target.value === "trust" && type === "country") setType("ip"); }}>
        <option value="block">Bloquer</option><option value="trust">Faire confiance</option>
      </select></label>
      <label>Type <select value={type} onChange={e => setType(e.target.value as RuleType)}>
        <option value="ip">IP</option><option value="cidr">CIDR</option>{!trust && <option value="country">Pays</option>}
      </select></label>
      <label>Valeur <input required value={value} onChange={e => setValue(e.target.value)} placeholder={type === "country" ? "FR" : "203.0.113.5"}/></label>
      <label>Motif <input value={reason} onChange={e => setReason(e.target.value)}/></label>
      <button disabled={busy} type="submit">Ajouter</button>
    </form>
    {error && <p role="alert">{error}</p>}{message && <p role="status">{message}</p>}
    <h3>Blocages enregistrés ({rules.length})</h3>
    <div className="table-scroll"><table><thead><tr><th>Type</th><th>Valeur</th><th>Hôte</th><th>Motif</th><th>Expiration</th><th>Action</th></tr></thead>
      <tbody>{rules.map(rule => <tr key={rule.id}><td>{rule.type}</td><td>{rule.value}</td>
        <td>{rule.host || "Tous"}</td><td>{rule.reason || "—"}</td><td>{rule.expires_at || "Permanent"}</td>
        <td><button disabled={busy} onClick={() => void execute(() => ruleApi.removeBlock(rule.id), `Supprimer le blocage ${rule.value} ?`)}>Supprimer</button></td>
      </tr>)}</tbody></table></div>
    <h3>Exceptions de confiance ({trusted.length})</h3>
    <div className="table-scroll"><table><thead><tr><th>Type</th><th>Valeur</th><th>Motif</th><th>Action</th></tr></thead>
      <tbody>{trusted.map(item => <tr key={item.id}><td>{item.type}</td><td>{item.value}</td><td>{item.reason || "—"}</td>
        <td><button disabled={busy} onClick={() => void execute(() => ruleApi.removeTrust(item.id), `Supprimer l'exception ${item.value} ?`)}>Supprimer</button></td>
      </tr>)}</tbody></table></div>
  </section>;
}
