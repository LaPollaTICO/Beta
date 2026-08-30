// Service Worker de La Polla TICO — V25A1.
// Actualización confirmada por el usuario: el SW nuevo espera hasta que se pulse
// “Actualizar”, toma el control y recién entonces la app recarga una sola vez.

const SHELL_CACHE = 'polla-tico-shell-v25a1';
const RUNTIME_CACHE = 'polla-tico-runtime-v25a1';

const SHELL_FILES = [
  './',
  './index.html',
  './manifest.json',
  './icon-180.png',
  './icon-192.png',
  './icon-512.png',
  './icon-maskable-512.png',
  './apple-touch-icon.png',
  './favicon-32x32.png',
  './favicon-16x16.png',
  './mascota-gallo-peru.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil((async()=>{
    const cache = await caches.open(SHELL_CACHE);
    // Fuerza una copia fresca del shell para no reutilizar HTML viejo del HTTP cache.
    await Promise.all(SHELL_FILES.map(async (path) => {
      try{
        const response = await fetch(new Request(path, {cache:'reload'}));
        if(response && response.ok) await cache.put(path, response.clone());
      }catch(_){ /* un asset opcional no debe romper toda la instalación */ }
    }));
  })());
  // V25A1: NO skipWaiting automático. Esperamos la confirmación del usuario.
});

self.addEventListener('message', (event) => {
  if(event.data && event.data.type === 'SKIP_WAITING') self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async()=>{
    const names = await caches.keys();
    await Promise.all(names
      .filter(n => n !== SHELL_CACHE && n !== RUNTIME_CACHE)
      .map(n => caches.delete(n)));
    if(self.registration.navigationPreload){
      try{ await self.registration.navigationPreload.enable(); }catch(_){ }
    }
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;

  // Navegación: respuesta inmediata desde el shell y revalidación en segundo plano.
  if (event.request.mode === 'navigate' || url.pathname.endsWith('/index.html')) {
    event.respondWith((async()=>{
      const cache = await caches.open(SHELL_CACHE);
      const cached = await cache.match(event.request) || await cache.match('./index.html');
      const refresh = (async()=>{
        try{
          const preload = event.preloadResponse ? await event.preloadResponse : null;
          const resp = preload || await fetch(event.request, {cache:'no-cache'});
          if(resp && resp.ok) await cache.put('./index.html', resp.clone());
          return resp;
        }catch(_){ return null; }
      })();
      event.waitUntil(refresh.then(()=>{}));
      if(cached) return cached;
      const fresh = await refresh;
      return fresh || new Response('Sin conexión', {status:503, headers:{'Content-Type':'text/plain; charset=utf-8'}});
    })());
    return;
  }

  // Comunicados: cache-first después del primer uso, con actualización en background.
  if (url.pathname.includes('/comunicados/')) {
    event.respondWith(
      caches.match(event.request).then(cached => {
        const fresh = fetch(event.request).then(resp => {
          if (resp && resp.ok) caches.open(RUNTIME_CACHE).then(c => c.put(event.request, resp.clone())).catch(()=>{});
          return resp;
        }).catch(() => cached);
        return cached || fresh;
      })
    );
    return;
  }

  // Assets locales pequeños: cache-first.
  event.respondWith(
    caches.match(event.request).then(cached => {
      if (cached) return cached;
      return fetch(event.request).then(resp => {
        if (resp && resp.ok) caches.open(RUNTIME_CACHE).then(c => c.put(event.request, resp.clone())).catch(()=>{});
        return resp;
      });
    })
  );
});
