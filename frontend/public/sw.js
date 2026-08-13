/** SG-X Guardian offline shell. Authenticated API data is never cached here. */
const params = new URL(self.location.href).searchParams;
const VERSION = params.get("v") || "dev";
const SHELL_CACHE = `sgx-guardian-shell-${VERSION}`;
const CACHE_PREFIX = "sgx-guardian-shell-";
const CORE = ["/", "/manifest.json", "/favicon.png", "/icon-192.png", "/icon-512.png"];

const sameOrigin = (url) => url.origin === self.location.origin;
const isApi = (url) => url.pathname === "/api" || url.pathname.startsWith("/api/");
const isStatic = (url) => url.pathname.startsWith("/assets/")
  || /\.(?:js|css|woff2?|png|jpg|jpeg|svg|webp|ico)$/i.test(url.pathname);

async function discoverShellAssets() {
  const response = await fetch(new Request("/", { cache: "no-store" }));
  if (!response.ok) throw new Error(`shell discovery failed: ${response.status}`);
  const html = await response.text();
  const urls = new Set(CORE);
  for (const match of html.matchAll(/(?:src|href)=["']([^"']+)["']/g)) {
    const url = new URL(match[1], self.location.origin);
    if (sameOrigin(url) && !isApi(url) && isStatic(url)) urls.add(url.pathname + url.search);
  }
  const cache = await caches.open(SHELL_CACHE);
  await cache.put("/", new Response(html, {
    status: 200,
    headers: { "Content-Type": "text/html; charset=utf-8", "X-SGX-Offline-Shell": VERSION },
  }));
  // A worker must not report itself installed with a partial executable
  // shell. In particular, missing hashed JS/CSS would turn a later offline
  // navigation into a blank page even though registration appeared healthy.
  await Promise.all([...urls].filter((url) => url !== "/").map(async (url) => {
    const asset = await fetch(new Request(url, { cache: "reload" }));
    if (!asset.ok || asset.type === "opaque") {
      throw new Error(`shell asset unavailable: ${url} (${asset.status})`);
    }
    await cache.put(url, asset);
  }));
}

self.addEventListener("install", (event) => {
  event.waitUntil(discoverShellAssets());
  // Do not skipWaiting: the open app must explicitly approve this version.
});

self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys
      .filter((key) => key.startsWith(CACHE_PREFIX) && key !== SHELL_CACHE)
      .map((key) => caches.delete(key)));
    await self.clients.claim();
  })());
});

self.addEventListener("message", (event) => {
  if (event.data?.type === "SKIP_WAITING") self.skipWaiting();
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  const url = new URL(request.url);
  if (request.method !== "GET" || !sameOrigin(url) || isApi(url)) return;

  if (request.mode === "navigate") {
    event.respondWith((async () => {
      try {
        return await fetch(request);
      } catch {
        const cache = await caches.open(SHELL_CACHE);
        return (await cache.match("/"))
          || new Response("Guardian PWA shell is unavailable", { status: 503 });
      }
    })());
    return;
  }

  if (isStatic(url)) {
    event.respondWith((async () => {
      const cache = await caches.open(SHELL_CACHE);
      const cached = await cache.match(request);
      if (cached) return cached;
      const response = await fetch(request);
      if (response.ok && response.type !== "opaque") {
        await cache.put(request, response.clone());
      }
      return response;
    })());
  }
});
