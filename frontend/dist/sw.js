/**
 * SG-X Guardian Service Worker
 * Provides offline shell caching for PWA support.
 */

const CACHE_NAME = "sgx-guardian-v2.4.1";

// Assets to pre-cache for offline shell
const PRECACHE_URLS = [
  "/",
];

// ── Install: pre-cache shell ──────────────────────────────────────────────────
self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(PRECACHE_URLS);
    })
  );
  self.skipWaiting();
});

// ── Activate: clean up old caches ────────────────────────────────────────────
self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((key) => key !== CACHE_NAME)
          .map((key) => caches.delete(key))
      )
    )
  );
  self.clients.claim();
});

// ── Fetch: network-first with cache fallback ─────────────────────────────────
self.addEventListener("fetch", (event) => {
  const { request } = event;

  // Skip non-GET and cross-origin requests
  if (request.method !== "GET") return;
  if (!request.url.startsWith(self.location.origin)) return;

  // API/Supabase calls: network only
  if (
    request.url.includes("supabase.co") ||
    request.url.includes("/functions/v1/")
  ) {
    return;
  }

  event.respondWith(
    fetch(request)
      .then((response) => {
        // Cache successful responses for static assets
        if (response.ok && (request.url.includes("/assets/") || request.url.endsWith(".js") || request.url.endsWith(".css"))) {
          const cloned = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(request, cloned));
        }
        return response;
      })
      .catch(() => {
        // Fallback to cache for navigation requests
        return caches.match(request).then((cached) => {
          if (cached) return cached;
          // For navigate requests, return the app shell
          if (request.mode === "navigate") {
            return caches.match("/");
          }
          return Response.error();
        });
      })
  );
});
