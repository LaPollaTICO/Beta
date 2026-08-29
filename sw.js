// Service Worker de La Polla TICO — V22.
// Shell inmediato + revalidación en segundo plano. Los datos de Supabase
// continúan fuera del Service Worker para no mezclar sesiones ni permisos.

const SHELL_CACHE = 'polla-tico-shell-v22';
const RUNTIME_CACHE = 'polla-tico-runtime-v22';

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
  event.waitUntil(
    caches.open(SHELL_CACHE).then(cache => cache.addAll(SHELL_FILES)).catch(() => {})
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    Promise.all([
      caches.keys().then(names =>
        Promise.all(names.filter(n => n !== SHELL_CACHE && n !== RUNTIME_CACHE).map(n => caches.delete(n)))
      ),
      self.registration.navigationPreload ? self.registration.navigationPreload.enable().catch(()=>{}) : Promise.resolve()
    ])
  );
  self.clients.claim();
  event.waitUntil(
    self.clients.matchAll({type:'window', includeUncontrolled:true}).then(clients => {
      clients.forEach(client => client.postMessage({type:'APP_UPDATE_READY', version:'V22'}));
    }).catch(()=>{})
  );
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;

  // V18: el HTML ya cacheado se entrega inmediatamente. En paralelo se baja
  // una copia fresca para la próxima navegación. El cambio de versión del SW
  // sigue renovando todo el shell durante install.
  if (event.request.mode === 'navigate' || url.pathname.endsWith('/index.html')) {
    event.respondWith((async()=>{
      const cache = await caches.open(SHELL_CACHE);
      const cached = await cache.match(event.request) || await cache.match('./index.html');
      const refresh = (async()=>{
        try{
          const preload = event.preloadResponse ? await event.preloadResponse : null;
          const resp = preload || await fetch(event.request);
          if(resp && resp.ok) await cache.put(event.request, resp.clone());
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

  // Comunicados: no frenan la instalación; cache-first después del primer uso.
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
