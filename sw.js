// Service Worker de La Polla TICO — V25H5.0.3 hotfix de caché/frontend.
// Actualización confirmada por el usuario: el SW nuevo espera hasta que se pulse
// “Actualizar”, toma el control y recién entonces la app recarga una sola vez.

const SHELL_CACHE = 'polla-tico-shell-v25h503';
const RUNTIME_CACHE = 'polla-tico-runtime-v25h503';

const ESSENTIAL_SHELL_FILES = [
  // H5: './' y './index.html' eran el mismo documento y se descargaban dos veces.
  './index.html',
  './app-core.js',
  './app-main.js',
  './app-pwa.js',
  './styles.css',
  './manifest.json'
];
const OPTIONAL_SHELL_FILES = [
  // H5.0.1: la mascota usa nombre versionado. No reutilizar el mismo nombre
  // cuando cambien sus bytes; así una PWA instalada nunca conserva una copia vieja.
  // Los iconos de instalación los gestiona el navegador/manifest; recachearlos
  // en cada versión del SW solo añadía ~1 MB de transferencia de fondo.
  './mascota-gallo-peru-v25h503.webp'
];

self.addEventListener('install', (event) => {
  event.waitUntil((async()=>{
    const cache=await caches.open(SHELL_CACHE);
    // Un SW nuevo NO puede instalarse si falta una pieza esencial del app shell.
    // Así evitamos activar una actualización parcial que deje la PWA en blanco.
    for(const path of ESSENTIAL_SHELL_FILES){
      const response=await fetch(new Request(path,{cache:'reload'}));
      if(!response || !response.ok) throw new Error(`Essential shell unavailable: ${path}`);
      await cache.put(path,response.clone());
    }
    // Íconos/mascota son visuales opcionales: si uno falla no rompe el update.
    await Promise.all(OPTIONAL_SHELL_FILES.map(async(path)=>{
      try{
        const response=await fetch(new Request(path,{cache:'reload'}));
        if(response && response.ok) await cache.put(path,response.clone());
      }catch(_){ }
    }));
  })());
  // No skipWaiting automático: esperamos la confirmación del usuario.
});

const SW_VERSION = 'V25H5.0.3';

self.addEventListener('message', (event) => {
  if(event.data && event.data.type === 'SKIP_WAITING'){
    self.skipWaiting();
    return;
  }
  if(event.data && event.data.type === 'GET_VERSION'){
    event.ports?.[0]?.postMessage({version: SW_VERSION});
  }
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async()=>{
    const names = await caches.keys();
    await Promise.all(names
      .filter(n => n.startsWith('polla-tico-') && n !== SHELL_CACHE && n !== RUNTIME_CACHE)
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

  // H4.3 — Navegación cache-first. La app ya tiene un flujo explícito de
  // actualización de Service Worker; por eso no hace falta esperar a la red en
  // cada apertura. El shell actual abre inmediatamente y la nueva versión solo
  // toma control cuando el usuario confirma "Actualizar".
  if (event.request.mode === 'navigate' || url.pathname.endsWith('/index.html')) {
    event.respondWith((async()=>{
      const cache = await caches.open(SHELL_CACHE);
      const cached = await cache.match('./index.html') || await cache.match(event.request);
      if(cached) return cached;
      try{
        const preload = event.preloadResponse ? await event.preloadResponse : null;
        const fresh = preload || await fetch(event.request, {cache:'no-cache'});
        if(fresh && fresh.ok){ await cache.put('./index.html', fresh.clone()); return fresh; }
      }catch(_){}
      return new Response('Sin conexión', {status:503, headers:{'Content-Type':'text/plain; charset=utf-8'}});
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
    caches.match(event.request, {ignoreSearch:true}).then(cached => {
      if (cached) return cached;
      return fetch(event.request).then(resp => {
        if (resp && resp.ok) caches.open(RUNTIME_CACHE).then(c => c.put(event.request, resp.clone())).catch(()=>{});
        return resp;
      });
    })
  );
});
