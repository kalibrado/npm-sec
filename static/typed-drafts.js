/* Typed settings drafts are isolated from the legacy runtime profile. */
(() => {
  'use strict';
  const root = document.getElementById('typed-drafts-card');
  if (!root) return;
  const el = id => document.getElementById(id);
  const form = el('typed-drafts-form');
  const message = el('typed-drafts-message');
  const save = el('typed-drafts-save');
  const revisionLabel = el('typed-drafts-revision');
  let revision = 0;
  let loaded = false;
  let busy = false;

  function notice(value, error = false) {
    message.textContent = value;
    message.dataset.error = String(error);
  }
  function setBusy(value) {
    busy = value;
    save.disabled = value || !loaded;
    el('typed-drafts-reload').disabled = value;
  }
  function parseLines(value, separator) {
    return value.split(separator).map(x => x.trim()).filter(Boolean);
  }
  function values() {
    return {
      auto_ban_enabled: el('typed-auto-ban').checked,
      country_block_enabled: el('typed-country-block').checked,
      blocked_countries: parseLines(el('typed-countries').value.toUpperCase(), ','),
      trusted_proxy_cidrs: parseLines(el('typed-proxies').value, /\r?\n/),
      rate_limit_rps: Number(el('typed-rps').value),
      rate_limit_burst: Number(el('typed-burst').value),
    };
  }
  function populate(settings) {
    el('typed-auto-ban').checked = settings.auto_ban_enabled;
    el('typed-country-block').checked = settings.country_block_enabled;
    el('typed-countries').value = settings.blocked_countries.join(', ');
    el('typed-proxies').value = settings.trusted_proxy_cidrs.join('\n');
    el('typed-rps').value = settings.rate_limit_rps;
    el('typed-burst').value = settings.rate_limit_burst;
  }
  function renderHistory(items) {
    const node = el('typed-drafts-history');
    node.replaceChildren();
    if (!items.length) { node.textContent = 'Aucune révision.'; return; }
    for (const item of items) {
      const line = document.createElement('p');
      line.textContent = `#${item.revision} · ${item.author} · ${item.reason} · ${item.created_at}`;
      node.appendChild(line);
    }
  }
  async function readJson(response) {
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = typeof body.detail === 'string' ? body.detail : `HTTP ${response.status}`;
      const error = new Error(detail);
      error.status = response.status;
      throw error;
    }
    return body;
  }
  async function reload() {
    if (busy) return;
    setBusy(true);
    loaded = false;
    try {
      const [latestResponse, historyResponse] = await Promise.all([
        fetch('/api/nginx-settings/latest', {credentials: 'same-origin'}),
        fetch('/api/nginx-settings/history?limit=20', {credentials: 'same-origin'}),
      ]);
      const latest = await readJson(latestResponse);
      const history = await readJson(historyResponse);
      renderHistory(history.revisions || []);
      if (!latest.draft) {
        revision = 0;
        revisionLabel.textContent = 'Révision 0';
        notice('Aucun brouillon initial. Importer les valeurs historiques vérifiées avant toute édition.', true);
        form.hidden = true;
      } else {
        revision = latest.draft.revision;
        revisionLabel.textContent = `Révision ${revision}`;
        populate(latest.draft.settings);
        loaded = true;
        form.hidden = false;
        notice('Brouillon chargé. Les modifications restent sans effet sur Nginx.');
      }
    } catch (error) {
      form.hidden = true;
      notice(`Lecture impossible : ${error.message}`, true);
    } finally {
      setBusy(false);
    }
  }
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (busy || !loaded || !form.reportValidity()) return;
    const reason = el('typed-reason').value.trim();
    if (!reason) { notice('Le motif est obligatoire.', true); return; }
    setBusy(true);
    try {
      const response = await fetch('/api/nginx-settings/revisions', {
        method: 'POST', credentials: 'same-origin',
        headers: {'Content-Type': 'application/json', 'X-NSD-Intent': 'save-settings'},
        body: JSON.stringify({settings: values(), expected_revision: revision, reason}),
      });
      await readJson(response);
      el('typed-reason').value = '';
      notice('Brouillon enregistré. Aucun déploiement Nginx effectué.');
      setBusy(false);
      await reload();
    } catch (error) {
      notice(error.status === 409
        ? 'Conflit de révision ou intégrité : actualiser avant de réessayer.'
        : `Enregistrement refusé : ${error.message}`, true);
      setBusy(false);
    }
  });
  el('typed-drafts-reload').addEventListener('click', reload);
  form.hidden = true;
  reload();
})();
