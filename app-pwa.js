// LaPollaTICO — runtime PWA/actualizaciones (V25H4.3)
// Separado del index para reducir riesgo y facilitar mantenimiento.

/* ============ SERVICE WORKER + ACTUALIZACIONES DE LA PWA ============ */
let appUpdateRegistration = null;
let appUpdateApplying = false;
let appUpdateReloaded_ = false;
let offeredWorkerVersion_ = '';

function removeAppUpdateNotice_(){
  document.getElementById('appUpdateNotice')?.remove();
}

function getWorkerVersion_(worker){
  return new Promise(resolve => {
    if(!worker){ resolve(''); return; }
    const channel = new MessageChannel();
    let done = false;
    const finish = value => {
      if(done) return;
      done = true;
      clearTimeout(timer);
      resolve(String(value || ''));
    };
    channel.port1.onmessage = ev => finish(ev.data?.version || '');
    const timer = setTimeout(() => finish(''), 1200);
    try{ worker.postMessage({type:'GET_VERSION'}, [channel.port2]); }
    catch(_){ finish(''); }
  });
}

async function offerWaitingWorker_(reg){
  const waiting = reg?.waiting;
  const controller = navigator.serviceWorker.controller;
  if(!waiting || !controller) return;

  // La versión correcta para comparar es la que CONTROLA esta pestaña, no la
  // versión del HTML. GitHub puede entregar el index nuevo antes de que el SW
  // nuevo tome control; comparar contra APP_VERSION ocultaba el aviso en ese caso.
  const [waitingVersion, controllerVersion] = await Promise.all([
    getWorkerVersion_(waiting),
    getWorkerVersion_(controller)
  ]);
  if(waitingVersion && controllerVersion && waitingVersion === controllerVersion) return;
  const identity = waitingVersion || `${waiting.scriptURL || 'waiting'}:${waiting.state}`;
  if(identity === offeredWorkerVersion_) return;

  offeredWorkerVersion_ = identity;
  showAppUpdateNotice(waitingVersion);
}

function showAppUpdateNotice(waitingVersion=''){
  if(document.getElementById('appUpdateNotice')) return;
  const bar = document.createElement('div');
  bar.id = 'appUpdateNotice';
  bar.setAttribute('role','status');
  bar.setAttribute('aria-live','polite');
  bar.style.cssText = [
    'position:fixed','left:12px','right:12px','bottom:14px','z-index:99999',
    'max-width:620px','margin:0 auto','padding:12px 14px','border:1px solid rgba(242,193,78,.65)',
    'border-radius:14px','background:rgba(8,18,16,.97)','box-shadow:0 12px 32px rgba(0,0,0,.4)',
    'display:flex','align-items:center','gap:12px','font-family:inherit','color:#F6F3EA'
  ].join(';');
  bar.innerHTML = `
    <div style="min-width:0;flex:1;line-height:1.25">
      <b style="display:block;color:#F2C14E;margin-bottom:3px">✨ Nueva actualización disponible</b>
      <span style="font-size:13px;opacity:.88">Actualiza para cargar la versión más reciente de LaPollaTICO</span>
    </div>
    <button id="applyAppUpdateBtn" type="button" style="flex:0 0 auto;border:0;border-radius:10px;padding:9px 12px;background:#F2C14E;color:#07110F;font-weight:800;cursor:pointer">Actualizar</button>`;
  document.body.appendChild(bar);

  document.getElementById('applyAppUpdateBtn')?.addEventListener('click', async () => {
    if(appUpdateApplying) return;
    if(hasUnsavedPredictions_()){
      showToast_('📝 Guarda tus pronósticos pendientes antes de actualizar');
      return;
    }
    const waiting = appUpdateRegistration?.waiting;
    if(!waiting){
      showToast_('La actualización todavía se está preparando');
      appUpdateRegistration?.update().catch(()=>{});
      return;
    }

    appUpdateApplying = true;
    const btn = document.getElementById('applyAppUpdateBtn');
    if(btn){ btn.disabled = true; btn.textContent = 'Actualizando…'; }
    waiting.postMessage({type:'SKIP_WAITING'});
    // F4: algunos navegadores/PWA tardan en emitir controllerchange aunque el
    // worker nuevo ya se haya activado. No dejamos el botón eternamente en
    // “Actualizando…”. Si en 8 s no llegó el evento, hacemos una única recarga
    // controlada; el SW nuevo usa network-first para servir el HTML fresco.
    setTimeout(()=>{
      if(!appUpdateApplying || appUpdateReloaded_) return;
      appUpdateReloaded_ = true;
      removeAppUpdateNotice_();
      location.reload();
    },8000);
  });
}

if('serviceWorker' in navigator){
  window.addEventListener('load', async () => {
    try{
      const reg = await navigator.serviceWorker.register('sw.js', {updateViaCache:'none'});
      appUpdateRegistration = reg;

      await offerWaitingWorker_(reg);

      reg.addEventListener('updatefound', () => {
        const worker = reg.installing;
        if(!worker) return;
        worker.addEventListener('statechange', () => {
          if(worker.state === 'installed') void offerWaitingWorker_(reg);
        });
      });

      // D2.2: además de registration.update(), consultamos sw.js con cache-bust.
      // GitHub Pages/CDN puede tardar en refrescar la copia usada por el registro;
      // esta sonda permite detectar una versión nueva sin obligar al usuario a refrescar.
      async function probeLatestServiceWorker_(){
        try{
          const probeUrl = `sw.js?update-check=${Date.now()}`;
          const probeRes = await fetch(probeUrl, {cache:'no-store', credentials:'same-origin'});
          if(!probeRes.ok) return;
          const source = await probeRes.text();
          const match = source.match(/const\s+SW_VERSION\s*=\s*['"]([^'"]+)['"]/);
          const latestVersion = match?.[1] || '';
          if(!latestVersion) return;

          const controllerVersion = await getWorkerVersion_(navigator.serviceWorker.controller);
          if(controllerVersion && latestVersion === controllerVersion){
            await offerWaitingWorker_(appUpdateRegistration);
            return;
          }

          // Solo cambiamos la URL del script cuando realmente detectamos otra versión.
          // Así evitamos instalar un worker falso en cada comprobación.
          const freshReg = await navigator.serviceWorker.register(
            `sw.js?v=${encodeURIComponent(latestVersion)}`,
            {scope:'./', updateViaCache:'none'}
          );
          appUpdateRegistration = freshReg;

          const installing = freshReg.installing;
          if(installing){
            installing.addEventListener('statechange', () => {
              if(installing.state === 'installed') void offerWaitingWorker_(freshReg);
            }, {once:false});
          }
          await offerWaitingWorker_(freshReg);
        }catch(err){
          console.debug('Comprobación de actualización omitida:', err);
        }
      }

      reg.update().catch(()=>{});
      let lastSwUpdateCheck_ = 0;
      const checkForAppUpdate_ = async () => {
        // Evita comprobaciones duplicadas por online/visibility en el mismo instante.
        if(Date.now() - lastSwUpdateCheck_ < 15000) return;
        lastSwUpdateCheck_ = Date.now();
        try{ await reg.update(); }catch(_){}
        await offerWaitingWorker_(appUpdateRegistration || reg);
        await probeLatestServiceWorker_();
      };

      // Una primera comprobación poco después de abrir y luego con una cadencia
      // centralizada en app_config. El mínimo es 60 s y el máximo 15 min.
      setTimeout(checkForAppUpdate_, 12000);
      const scheduleNextUpdateCheck_ = () => {
        const seconds = Math.min(900, Math.max(60, Number(appConfig_.updateCheckSeconds || 120)));
        setTimeout(async () => {
          await checkForAppUpdate_();
          scheduleNextUpdateCheck_();
        }, seconds * 1000);
      };
      scheduleNextUpdateCheck_();
      document.addEventListener('visibilitychange', () => {
        if(document.visibilityState === 'visible') checkForAppUpdate_();
      });
      window.addEventListener('focus', checkForAppUpdate_);
      window.addEventListener('online', checkForAppUpdate_);

      navigator.serviceWorker.addEventListener('controllerchange', () => {
        if(!appUpdateApplying || appUpdateReloaded_) return;
        appUpdateReloaded_ = true;
        removeAppUpdateNotice_();
        location.reload();
      });
    }catch(err){
      console.warn('No se pudo registrar el service worker:', err);
    }
  });
}

/* ============ BOTÓN "INSTALAR APP" EN LA PANTALLA PRINCIPAL ============ */
function isStandaloneMode(){
  return window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone === true;
}
function isIOS(){
  return /iPad|iPhone|iPod/.test(navigator.userAgent) && !window.MSStream;
}

// Chrome/Android: el navegador dispara este evento cuando decide que la app
// es instalable. Lo interceptamos para lanzarlo nosotros cuando el usuario
// toque nuestro botón, en vez de depender del avisito nativo poco visible.
window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  deferredInstallPrompt = e;
  if(!isStandaloneMode()) document.getElementById('installAppBtn')?.classList.remove('hidden');
});

window.addEventListener('appinstalled', () => {
  deferredInstallPrompt = null;
  document.getElementById('installAppBtn')?.classList.add('hidden');
});

async function handleInstallClick(){
  if(deferredInstallPrompt){
    deferredInstallPrompt.prompt();
    await deferredInstallPrompt.userChoice;
    deferredInstallPrompt = null;
    document.getElementById('installAppBtn')?.classList.add('hidden');
  } else if(isIOS()){
    alert('Para instalarla en iPhone:\n\n1. Toca el botón "Compartir" en Safari (el cuadrado con la flecha hacia arriba).\n2. Elige "Agregar a pantalla de inicio".');
  }
}

// iPhone nunca dispara beforeinstallprompt (Apple no lo soporta), así que ahí
// mostramos el botón igual, pero con instrucciones manuales en vez del prompt nativo.
if(isIOS() && !isStandaloneMode()){
  document.getElementById('installAppBtn')?.classList.remove('hidden');
}
