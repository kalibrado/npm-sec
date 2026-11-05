const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const script = fs.readFileSync(path.join(__dirname, '../static/typed-drafts.js'), 'utf8');
const settings = {
  auto_ban_enabled: false, country_block_enabled: false,
  blocked_countries: [], trusted_proxy_cidrs: [],
  rate_limit_rps: 10, rate_limit_burst: 20,
};
const tick = () => new Promise(resolve => setImmediate(resolve));
const response = body => ({ok: true, json: async () => body});

function harness() {
  const elements = new Map();
  function element(id = '') {
    if (!elements.has(id)) elements.set(id, {
      id, value: '', checked: false, disabled: false, hidden: false,
      textContent: '', dataset: {}, children: [], listeners: {},
      addEventListener(type, fn) { this.listeners[type] = fn; },
      replaceChildren(...items) { this.children = [...items]; },
      appendChild(item) { this.children.push(item); },
      reportValidity() { return true; },
    });
    return elements.get(id);
  }
  const requests = [];
  let currentRevision = 2;
  const setCurrentRevision = value => { currentRevision = value; };
  const document = {
    getElementById: element,
    createElement: tag => element('created-' + tag + '-' + Math.random()),
  };
  const fetch = (url, options = {}) => {
    if (url === '/api/nginx-settings/latest') return Promise.resolve(response({
      draft: {revision: currentRevision, settings},
    }));
    if (url.startsWith('/api/nginx-settings/history')) return Promise.resolve(response({
      revisions: [
        {revision: currentRevision, author: 'admin', reason: 'new', created_at: 'today'},
        {revision: 1, author: 'admin', reason: 'old', created_at: 'yesterday'},
      ],
    }));
    return new Promise(resolve => requests.push({url, options, resolve}));
  };
  vm.runInNewContext(script, {document, fetch, window: {confirm: () => true}, console});
  return {element, requests, setCurrentRevision};
}

test('stale comparison cannot enable restoration after selection changes', async () => {
  const h = harness();
  await tick(); await tick();
  const before = h.element('typed-drafts-before');
  const after = h.element('typed-drafts-after');
  assert.equal(before.value, '1');
  assert.equal(after.value, '2');
  const pending = h.element('typed-drafts-compare-btn').listeners.click();
  assert.equal(h.requests.length, 1);
  before.value = '2';
  before.listeners.change();
  h.requests[0].resolve(response({changes: {rate_limit_rps: {before: 10, after: 20}}}));
  await pending;
  assert.equal(h.element('typed-drafts-restore-btn').disabled, true);
  assert.equal(h.element('typed-drafts-diff-results').children.length, 0);
});

test('restoration refreshes current revision and history', async () => {
  const h = harness();
  await tick(); await tick();
  const compare = h.element('typed-drafts-compare-btn').listeners.click();
  h.requests[0].resolve(response({changes: {rate_limit_rps: {before: 5, after: 10}}}));
  await compare;
  assert.equal(h.element('typed-drafts-restore-btn').disabled, false);
  h.element('typed-drafts-restore-reason').value = 'revert';
  const restoring = h.element('typed-drafts-restore-btn').listeners.click();
  assert.equal(h.requests[1].url, '/api/nginx-settings/restore');
  const payload = JSON.parse(h.requests[1].options.body);
  assert.equal(payload.target_revision, 1);
  assert.equal(payload.expected_revision, 2);
  h.setCurrentRevision(3);
  h.requests[1].resolve(response({revision: 3}));
  await restoring;
  assert.equal(h.element('typed-drafts-revision').textContent, 'Révision 3');
  assert.match(h.element('typed-drafts-history').children[0].textContent, /#3/);
  assert.equal(h.element('typed-drafts-restore-btn').disabled, true);
  assert.match(h.element('typed-drafts-restore-message').textContent, /nouveau brouillon/);
});

test('older comparison cannot unlock button while a newer request is pending', async () => {
  const h = harness();
  await tick(); await tick();
  const click = h.element('typed-drafts-compare-btn').listeners.click;
  const first = click();
  h.element('typed-drafts-before').value = '2';
  h.element('typed-drafts-before').listeners.change();
  const second = click();
  assert.equal(h.requests.length, 2);
  assert.equal(h.element('typed-drafts-compare-btn').disabled, true);
  h.requests[0].resolve(response({changes: {}}));
  await first;
  assert.equal(h.element('typed-drafts-compare-btn').disabled, true);
  h.requests[1].resolve(response({changes: {}}));
  await second;
  assert.equal(h.element('typed-drafts-compare-btn').disabled, false);
});
