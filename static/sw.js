const CACHE_NAME = 'npm-security-shell-v0.5.10.1';
const SHELL_ASSETS = [
  '/',
  '/static/dashboard.css',
  '/static/dashboard.js',
  '/static/manifest.webmanifest',
  '/static/icons/icon-192.png',
  '/static/icons/icon-512.png'
];

self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(SHELL_ASSETS)).catch(() => null));
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))))
  );
  self.clients.claim();
});

function isDynamicRequest(url) {
  return [
    '/events', '/history', '/stats', '/timeline', '/heatmap', '/sparklines', '/whois',
    '/blocklist', '/trusted', '/ban-events', '/threats', '/health', '/config',
    '/npm-health', '/metrics', '/auth', '/users', '/db', '/export', '/threat-intel'
  ].some(prefix => url.pathname.startsWith(prefix));
}

self.addEventListener('fetch', event => {
  const req = event.request;
  const url = new URL(req.url);

  if (req.method !== 'GET' || url.origin !== self.location.origin || isDynamicRequest(url)) {
    return;
  }

  event.respondWith(
    caches.match(req).then(cached => cached || fetch(req).then(resp => {
      const copy = resp.clone();
      caches.open(CACHE_NAME).then(cache => cache.put(req, copy)).catch(() => null);
      return resp;
    }).catch(() => caches.match('/')))
  );
});
