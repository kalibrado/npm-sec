// Offline cache only for the app shell. Never cache authenticated API data.
const CACHE_NAME = 'npm-security-shell-v0.6.1';
const SHELL_ASSETS = [
  '/',
  '/static/dashboard.css',
  '/static/dashboard.js',
  '/static/manifest.webmanifest',
  '/static/icons/icon-192.png',
  '/static/icons/icon-512.png'
];
const NETWORK_FIRST = new Set(['/', '/static/dashboard.css', '/static/dashboard.js']);

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(SHELL_ASSETS)).catch(() => null)
  );
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys => Promise.all(
      keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key))
    ))
  );
  self.clients.claim();
});

self.addEventListener('fetch', event => {
  const req = event.request;
  const url = new URL(req.url);
  if (req.method !== 'GET' || url.origin !== self.location.origin) return;

  // This allowlist intentionally excludes /security-control and every
  // other API endpoint, including future authenticated routes. Their
  // responses must never be written into a persistent browser cache.
  if (!SHELL_ASSETS.includes(url.pathname)) return;

  if (NETWORK_FIRST.has(url.pathname)) {
    event.respondWith(
      fetch(req).then(response => {
        if (response.ok) {
          const copy = response.clone();
          event.waitUntil(
            caches.open(CACHE_NAME).then(cache => cache.put(req, copy)).catch(() => null)
          );
        }
        return response;
      }).catch(() => caches.match(req))
    );
    return;
  }

  event.respondWith(
    caches.match(req).then(cached => cached || fetch(req).then(response => {
      if (response.ok) {
        const copy = response.clone();
        event.waitUntil(
          caches.open(CACHE_NAME).then(cache => cache.put(req, copy)).catch(() => null)
        );
      }
      return response;
    }))
  );
});
