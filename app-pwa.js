// LaPollaTICO — runtime PWA/actualizaciones (V25H5.0.5)
// Separado del index para reducir riesgo y facilitar mantenimiento.

/* ============ SERVICE WORKER + ACTUALIZACIONES DE LA PWA ============ */
let appUpdateRegistration = null;
let appUpdateApplying = false;
let appUpdateReloaded_ = false;
let offeredWorkerVersion_ = '';
let appUpdateExpectedVersion_ = '';

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

  // H5.0.5: solo mostramos una actualización si podemos demostrar que el worker
  // en espera tiene una versión distinta de la que controla esta pestaña.
  // Esto evita avisos falsos durante la primera instalación/reanudación de Android.
  if(!waitingVersion || !controllerVersion) return;
  if(waitingVersion === controllerVersion) return;
  const identity = waitingVersion;
  if(identity === offeredWorkerVersion_) return;

  offeredWorkerVersion_ = identity;
  showAppUpdateNotice(waitingVersion);
}

async function reloadWhenNewWorkerControls_(expectedVersion='',previousController=null){
  const deadline=Date.now()+22000;
  while(appUpdateApplying && !appUpdateReloaded_ && Date.now()<deadline){
    const controller=navigator.serviceWorker.controller;
    const controllerVersion=controller ? await getWorkerVersion_(controller) : '';
    const controllerChanged = controller && previousController && controller !== previousController;
    if(controller && (expectedVersion ? controllerVersion===expectedVersion : controllerChanged)){
      appUpdateReloaded_=true;
      removeAppUpdateNotice_();
      location.reload();
      return true;
    }
    await new Promise(r=>setTimeout(r,350));
  }
  if(appUpdateApplying && !appUpdateReloaded_){
    appUpdateApplying=false;
    const btn=document.getElementById('applyAppUpdateBtn');
    if(btn){ btn.disabled=false; btn.textContent='Reintentar'; }
    showToast_('La actualización sigue preparándose. No hace falta recargar manualmente; pulsa Reintentar en unos segundos.');
  }
  return false;
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
    const previousController=navigator.serviceWorker.controller;
    const expectedVersion = waitingVersion || await getWorkerVersion_(waiting);
    appUpdateExpectedVersion_ = expectedVersion || '';
    waiting.postMessage({type:'SKIP_WAITING'});
    // H5.0.2: nunca recargamos por tiempo suponiendo que el worker nuevo ya controla
    // la pestaña. Esperamos a comprobarlo; controllerchange sigue siendo la vía rápida.
    void reloadWhenNewWorkerControls_(expectedVersion,previousController);
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

          const activeReg = appUpdateRegistration || reg;
          const [controllerVersion, waitingVersion] = await Promise.all([
            getWorkerVersion_(navigator.serviceWorker.controller),
            getWorkerVersion_(activeReg?.waiting)
          ]);

          if(waitingVersion && waitingVersion === latestVersion){
            await offerWaitingWorker_(activeReg);
            return;
          }
          if(controllerVersion && latestVersion === controllerVersion) return;

          // H5.0.5: mantenemos SIEMPRE la URL estable sw.js. Registrar sw.js?v=...
          // cambiaba el scriptURL de la misma scope y podía crear un worker nuevo
          // aunque la versión publicada fuera la misma, generando un aviso fantasma.
          try{ await activeReg?.update(); }catch(_){}
          await offerWaitingWorker_(activeReg);
        }catch(err){
          console.debug('Comprobación de actualización omitida:', err);
        }
      }

      reg.update().catch(()=>{});
      let lastSwUpdateCheck_ = 0;
      const checkForAppUpdate_ = async (force=false) => {
        // H5: no gastamos radio/batería en segundo plano ni intentamos red estando offline.
        // Al volver a primer plano / recuperar conexión sí hacemos una comprobación inmediata.
        if(!force && document.visibilityState === 'hidden') return;
        if(navigator.onLine === false) return;
        // Evita comprobaciones duplicadas por online/visibility/focus en el mismo instante.
        if(Date.now() - lastSwUpdateCheck_ < 15000) return;
        lastSwUpdateCheck_ = Date.now();
        await offerWaitingWorker_(appUpdateRegistration || reg);
        await probeLatestServiceWorker_();
      };

      // Primera comprobación poco después de abrir. Después, 10 min por defecto.
      // En ahorro de datos o conexiones lentas subimos a 15 min; focus/online/visible
      // siguen comprobando de inmediato, así no se sacrifica la detección práctica.
      setTimeout(()=>void checkForAppUpdate_(false), 12000);
      const scheduleNextUpdateCheck_ = () => {
        const c=navigator.connection || navigator.mozConnection || navigator.webkitConnection || null;
        const slow=!!c?.saveData || ['slow-2g','2g','3g'].includes(String(c?.effectiveType||'').toLowerCase());
        const configured=Math.min(900, Math.max(300, Number(appConfig_.updateCheckSeconds || 600)));
        const seconds=slow ? 900 : configured;
        setTimeout(async () => {
          await checkForAppUpdate_(false);
          scheduleNextUpdateCheck_();
        }, seconds * 1000);
      };
      scheduleNextUpdateCheck_();
      document.addEventListener('visibilitychange', () => {
        if(document.visibilityState === 'visible') void checkForAppUpdate_(true);
      });
      window.addEventListener('focus', () => void checkForAppUpdate_(true));
      window.addEventListener('online', () => void checkForAppUpdate_(true));

      navigator.serviceWorker.addEventListener('controllerchange', async () => {
        if(!appUpdateApplying || appUpdateReloaded_) return;
        const controllerVersion=await getWorkerVersion_(navigator.serviceWorker.controller);
        if(appUpdateExpectedVersion_ && controllerVersion && controllerVersion!==appUpdateExpectedVersion_) return;
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
