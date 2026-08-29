// Service Worker de La Polla TICO — V23.
// Actualización confirmada por el usuario: el SW nuevo espera hasta que se pulse
// “Actualizar”, toma el control y recién entonces la app recarga una sola vez.

const SHELL_CACHE = 'polla-tico-shell-v23';
const RUNTIME_CACHE = 'polla-tico-runtime-v23';

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

    // Fuerza una copia fresca del shell para no reutilizar HTML viejo
    // que pudiera quedar en el caché HTTP del navegador.
    await Promise.all(SHELL_FILES.map(async (path) => {
      try{
        const response = await fetch(
          new Request(path, { cache: 'reload' })
        );

        if(response && response.ok){
          await cache.put(path, response.clone());
        }
      }catch(_){
        // Un asset opcional no debe romper toda la instalación.
      }
    }));
  })());

  // V23:
  // NO usamos skipWaiting() automáticamente.
  // Esperamos a que el usuario pulse "Actualizar".
});


// ============================================================
// ACTUALIZACIÓN MANUAL
// ============================================================

self.addEventListener('message', (event) => {
  if(
    event.data &&
    event.data.type === 'SKIP_WAITING'
  ){
    self.skipWaiting();
  }
});


// ============================================================
// ACTIVACIÓN
// ============================================================

self.addEventListener('activate', (event) => {
  event.waitUntil((async()=>{

    // Elimina cachés de versiones anteriores.
    const names = await caches.keys();

    await Promise.all(
      names
        .filter(
          n =>
            n !== SHELL_CACHE &&
            n !== RUNTIME_CACHE
        )
        .map(n => caches.delete(n))
    );

    // Navigation Preload si el navegador lo soporta.
    if(self.registration.navigationPreload){
      try{
        await self.registration.navigationPreload.enable();
      }catch(_){}
    }

    // El nuevo Service Worker toma control de las pestañas.
    await self.clients.claim();

  })());
});


// ============================================================
// FETCH
// ============================================================

self.addEventListener('fetch', (event) => {

  if(event.request.method !== 'GET'){
    return;
  }

  const url = new URL(event.request.url);

  // Solo manejamos archivos del mismo dominio.
  if(url.origin !== self.location.origin){
    return;
  }


  // ==========================================================
  // NAVEGACIÓN / INDEX.HTML
  // ==========================================================
  //
  // Entrega inmediatamente el HTML guardado.
  // Después actualiza una copia fresca en segundo plano.
  //
  // Esto hace que abrir/refrescar la app sea rápido,
  // incluso con conexión lenta.
  // ==========================================================

  if(
    event.request.mode === 'navigate' ||
    url.pathname.endsWith('/index.html')
  ){

    event.respondWith((async()=>{

      const cache = await caches.open(SHELL_CACHE);

      const cached =
        await cache.match(event.request) ||
        await cache.match('./index.html');


      const refresh = (async()=>{

        try{

          const preload =
            event.preloadResponse
              ? await event.preloadResponse
              : null;

          const resp =
            preload ||
            await fetch(
              event.request,
              { cache: 'no-cache' }
            );


          if(resp && resp.ok){

            await cache.put(
              './index.html',
              resp.clone()
            );

          }

          return resp;

        }catch(_){

          return null;

        }

      })();


      // Dejamos que la actualización termine en background.
      event.waitUntil(
        refresh.then(()=>{})
      );


      // Si ya existe copia local, mostrarla inmediatamente.
      if(cached){
        return cached;
      }


      // Primera visita: esperar la descarga.
      const fresh = await refresh;

      return fresh || new Response(
        'Sin conexión',
        {
          status: 503,
          headers: {
            'Content-Type':
              'text/plain; charset=utf-8'
          }
        }
      );

    })());

    return;
  }


  // ==========================================================
  // COMUNICADOS
  // ==========================================================
  //
  // Cache-first después del primer uso.
  // Actualización silenciosa en segundo plano.
  // ==========================================================

  if(url.pathname.includes('/comunicados/')){

    event.respondWith(

      caches.match(event.request)
        .then(cached => {

          const fresh =
            fetch(event.request)
              .then(resp => {

                if(resp && resp.ok){

                  caches
                    .open(RUNTIME_CACHE)
                    .then(
                      c => c.put(
                        event.request,
                        resp.clone()
                      )
                    )
                    .catch(()=>{});

                }

                return resp;

              })
              .catch(() => cached);


          return cached || fresh;

        })

    );

    return;
  }


  // ==========================================================
  // ASSETS LOCALES
  // ==========================================================
  //
  // Imágenes, manifest, íconos, etc.
  // ==========================================================

  event.respondWith(

    caches.match(event.request)
      .then(cached => {

        if(cached){
          return cached;
        }


        return fetch(event.request)
          .then(resp => {

            if(resp && resp.ok){

              caches
                .open(RUNTIME_CACHE)
                .then(
                  c => c.put(
                    event.request,
                    resp.clone()
                  )
                )
                .catch(()=>{});

            }

            return resp;

          });

      })

  );

});