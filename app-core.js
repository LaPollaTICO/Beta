// LaPollaTICO — núcleo liviano de ciclo de vida (V25H5.0.2)
// Mantiene en un solo lugar las reglas visuales del estado de una Polla.
(function(global){
  'use strict';
  function truthy(v){ return v === true || v === 1 || v === '1' || v === 'true'; }
  function classifyPolla(p){
    if(!p) return {key:'NONE', compacted:false, finished:false, canPlayerLogin:false, canRegister:false, canWrite:false};
    const compacted = !!(p.compactedAt || p.compacted_at);
    const finished = String(p.status || '').toLowerCase() === 'finalizada' || truthy(p.isArchived) || truthy(p.is_archived);
    if(compacted){
      return {key:'COMPACTED', compacted:true, finished:true, canPlayerLogin:false, canRegister:false, canWrite:false};
    }
    if(finished){
      return {key:'FINAL_REVIEW', compacted:false, finished:true, canPlayerLogin:true, existingOnly:true, canRegister:false, canWrite:false};
    }
    return {key:'ACTIVE', compacted:false, finished:false, canPlayerLogin:true, existingOnly:false, canRegister:true, canWrite:true};
  }
  global.TicoCore = Object.freeze({ version:'V25H5.0.2', classifyPolla });
})(window);
