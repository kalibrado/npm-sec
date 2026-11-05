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
  let comparedTarget = null;
  let compareGeneration = 0;

  function notice(value, error = false) {
    message.textContent = value;
    message.dataset.error = String(error);
  }
  function setBusy(value) {
    busy = value;
    save.disabled = value || !loaded;
    el('typed-drafts-reload').disabled = value;
    el('typed-drafts-restore-btn').disabled = value || comparedTarget === null;
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
  function importValues() {
    return {
      auto_ban_enabled: el('typed-import-auto-ban').checked,
      country_block_enabled: el('typed-import-country-block').checked,
      blocked_countries: parseLines(el('typed-import-countries').value.toUpperCase(), ','),
      trusted_proxy_cidrs: parseLines(el('typed-import-proxies').value, /\r?\n/),
      rate_limit_rps: Number(el('typed-import-rps').value),
      rate_limit_burst: Number(el('typed-import-burst').value),
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
  function updateCompareOptions(items) {
    compareGeneration += 1;
    comparedTarget = null;
    el('typed-drafts-restore-btn').disabled = true;
    const before = el('typed-drafts-before');
    const after = el('typed-drafts-after');
    for (const select of [before, after]) {
      select.replaceChildren();
      for (const item of items) {
        const option = document.createElement('option');
        option.value = String(item.revision);
        option.textContent = `Révision #${item.revision}`;
        select.appendChild(option);
      }
    }
    if (items.length > 1) before.value = String(items[1].revision);
    if (items.length) after.value = String(items[0].revision);
    el('typed-drafts-compare-btn').disabled = items.length < 2;
    el('typed-drafts-diff-results').replaceChildren();
    el('typed-drafts-diff-message').textContent = items.length < 2
      ? 'Deux révisions sont nécessaires pour comparer.'
      : 'Sélectionner deux révisions puis cliquer sur Comparer.';
  }
  function renderDiff(changes) {
    const container = el('typed-drafts-diff-results');
    container.replaceChildren();
    const entries = Object.entries(changes || {});
    if (!entries.length) {
      container.textContent = 'Aucune différence entre ces révisions.';
      return;
    }
    const table = document.createElement('table');
    table.className = 'compact-table';
    const header = document.createElement('tr');
    for (const name of ['Paramètre', 'Avant', 'Après']) {
      const cell = document.createElement('th');
      cell.textContent = name;
      header.appendChild(cell);
    }
    table.appendChild(header);
    for (const [key, value] of entries) {
      const row = document.createElement('tr');
      for (const item of [key, JSON.stringify(value.before), JSON.stringify(value.after)]) {
        const cell = document.createElement('td');
        cell.textContent = item;
        row.appendChild(cell);
      }
      table.appendChild(row);
    }
    container.appendChild(table);
  }
  async function compare() {
    const generation = ++compareGeneration;
    comparedTarget = null;
    el('typed-drafts-restore-btn').disabled = true;
    const before = Number(el('typed-drafts-before').value);
    const after = Number(el('typed-drafts-after').value);
    const status = el('typed-drafts-diff-message');
    if (!Number.isInteger(before) || !Number.isInteger(after) || before < 1 || after < 1) return;
    const button = el('typed-drafts-compare-btn');
    button.disabled = true;
    status.textContent = 'Comparaison en cours…';
    try {
      const response = await fetch(
        `/api/nginx-settings/diff?before_revision=${before}&after_revision=${after}`,
        {credentials: 'same-origin'},
      );
      const result = await readJson(response);
      if (generation !== compareGeneration ||
          Number(el("typed-drafts-before").value) !== before ||
          Number(el("typed-drafts-after").value) !== after) return;
      renderDiff(result.changes);
      status.textContent = `Comparaison #${before} → #${after}. Aucun changement appliqué.`;
      if (after === revision && before !== revision) {
        comparedTarget = {target: before, current: revision};
        el('typed-drafts-restore-btn').disabled = false;
      }
      el('typed-drafts-restore-message').textContent = comparedTarget
        ? `La révision #${before} peut être restaurée en nouveau brouillon après confirmation.`
        : 'Pour restaurer, comparer une ancienne révision (Avant) avec la révision actuelle (Après).';
    } catch (error) {
      if (generation !== compareGeneration) return;
      el('typed-drafts-diff-results').replaceChildren();
      status.textContent = `Comparaison impossible : ${error.message}`;
    } finally {
      button.disabled = false;
    }
  }
  async function restoreDraft() {
    const selected = comparedTarget;
    if (busy || !selected || selected.current !== revision) return;
    const reason = el('typed-drafts-restore-reason').value.trim();
    const status = el('typed-drafts-restore-message');
    if (!reason) { status.textContent = 'Motif de restauration obligatoire.'; return; }
    if (!window.confirm(`Créer une nouvelle révision brouillon à partir de #${selected.target} ? Aucun déploiement Nginx ne sera effectué.`)) return;
    setBusy(true);
    try {
      const response = await fetch('/api/nginx-settings/restore', {
        method: 'POST', credentials: 'same-origin',
        headers: {'Content-Type': 'application/json', 'X-NSD-Intent': 'restore-settings'},
        body: JSON.stringify({
          target_revision: selected.target, expected_revision: selected.current, reason,
        }),
      });
      await readJson(response);
      el('typed-drafts-restore-reason').value = '';
      comparedTarget = null;
      await reload();
      status.textContent = 'Ancienne version copiée dans un nouveau brouillon. Aucun déploiement Nginx.';
    } catch (error) {
      status.textContent = error.status === 409
        ? 'Conflit de version ou intégrité : actualiser et comparer à nouveau.'
        : `Restauration refusée : ${error.message}`;
    } finally {
      setBusy(false);
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
      updateCompareOptions(history.revisions || []);
      el('typed-import-section').hidden = Boolean(latest.draft);
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
      el('typed-import-section').hidden = true;
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
  el('typed-import-form').addEventListener('submit', async event => {
    event.preventDefault();
    const importForm = el('typed-import-form');
    if (busy || !importForm.reportValidity()) return;
    if (!el('typed-import-verified').checked) {
      notice('Attestation de vérification obligatoire.', true);
      return;
    }
    const source = el('typed-import-source').value.trim();
    const reason = el('typed-import-reason').value.trim();
    const sha = el('typed-import-sha').value.trim();
    if (!source || !reason || !/^[0-9a-f]{64}$/.test(sha)) {
      notice('Source, motif et empreinte SHA-256 valides obligatoires.', true);
      return;
    }
    const settings = importValues();
    if (!window.confirm('Confirmer que les valeurs saisies correspondent exactement à la source vérifiée ? Aucun changement Nginx ne sera appliqué.')) return;
    setBusy(true);
    el('typed-import-submit').disabled = true;
    try {
      const response = await fetch('/api/nginx-settings/import-initial', {
        method: 'POST', credentials: 'same-origin',
        headers: {'Content-Type': 'application/json', 'X-NSD-Intent': 'import-settings'},
        body: JSON.stringify({
          settings, source_sha256: sha, source_description: source,
          reason, verified_against_source: true,
        }),
      });
      await readJson(response);
      notice('Révision initiale importée. Aucun changement Nginx appliqué.');
      setBusy(false);
      await reload();
    } catch (error) {
      notice(error.status === 409
        ? 'Import déjà effectué ou conflit : actualiser avant de réessayer.'
        : `Import refusé : ${error.message}`, true);
      setBusy(false);
    } finally {
      el('typed-import-submit').disabled = false;
    }
  });
  el('typed-drafts-reload').addEventListener('click', reload);
  el('typed-drafts-compare-btn').addEventListener('click', compare);
  el('typed-drafts-restore-btn').addEventListener('click', restoreDraft);
  for (const id of ['typed-drafts-before', 'typed-drafts-after']) {
    el(id).addEventListener('change', () => {
      compareGeneration += 1;
      comparedTarget = null;
      el('typed-drafts-restore-btn').disabled = true;
    });
  }
  form.hidden = true;
  reload();
})();
