// V15: optimizaciones estructurales de payload/latencia; reglas de negocio sin cambios.
// ============================================================================
// LA POLLA "TICO" — Supabase Edge Function: polla-api
// Estado actual de migración:
//   ✅ Lecturas públicas
//   ✅ authName
//   ✅ selfRegister
//   ✅ setSecurityAnswer
//   ✅ selfResetPin
//   ✅ savePrediction / savePredictionsBulk
//   ✅ Acciones ADMIN
//   ✅ Históricos / temporada / backups / auditoría
//   ✅ Reapertura segura + recálculo tras eliminación de participantes
//   ✅ Activación segura, privacidad de pronósticos y limpieza de identidades
//   ✅ Rate limit por origen para Admin/recuperación
//
// IMPORTANTE:
// - Las tablas tienen RLS cerrado para anon.
// - Esta Edge Function usa SERVICE_ROLE solamente del lado servidor.
// - Configurar secret PLAYER_AUTH_PEPPER antes de desplegar.
// ============================================================================

import { createClient } from "npm:@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL");
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
const AUTH_PEPPER = Deno.env.get("PLAYER_AUTH_PEPPER");
const BACKEND_VERSION = "V25H5.0";

if (!SUPABASE_URL) throw new Error("Falta SUPABASE_URL");
if (!SUPABASE_SERVICE_ROLE_KEY) throw new Error("Falta SUPABASE_SERVICE_ROLE_KEY");
if (!AUTH_PEPPER) throw new Error("Falta PLAYER_AUTH_PEPPER");

const supabase = createClient(
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  },
);

// H4: CORS cerrado por defecto. En producción define CORS_ALLOWED_ORIGIN con
// el origen exacto del GitHub Pages definitivo (sin ruta final ni slash).
const CORS_ALLOWED_ORIGIN = String(
  Deno.env.get("CORS_ALLOWED_ORIGIN") || "https://lapollatico.github.io"
).trim().replace(/\/$/, "");
const corsHeaders = {
  "Access-Control-Allow-Origin": CORS_ALLOWED_ORIGIN,
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-admin-session, x-admin-confirm, x-request-id",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
};


let JSZipModule_: any = null;
async function getJSZip_(){
  if(JSZipModule_) return JSZipModule_;
  const mod = await import("npm:jszip@3.10.1");
  JSZipModule_ = mod.default || mod;
  return JSZipModule_;
}

const BACKUP_BUCKET = "polla-backups";

async function ensureBackupBucket_() {
  const { data, error } = await supabase.storage.getBucket(BACKUP_BUCKET);
  if (!error && data) return;
  const created = await supabase.storage.createBucket(BACKUP_BUCKET, {
    public: false,
    fileSizeLimit: 50 * 1024 * 1024,
  });
  if (created.error && !String(created.error.message || "").toLowerCase().includes("already")) {
    throw created.error;
  }
}

function safeFilePart_(value: unknown) {
  return String(value ?? "")
    .trim()
    .replace(/[^a-zA-Z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "") || "item";
}

function extFromContentType_(contentType: string) {
  const ct = String(contentType || "").toLowerCase();
  if (ct.includes("png")) return "png";
  if (ct.includes("webp")) return "webp";
  if (ct.includes("gif")) return "gif";
  if (ct.includes("svg")) return "svg";
  return "jpg";
}

async function fetchBackupImage_(url: string) {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) throw new Error(`No se pudo incluir una imagen del respaldo (${response.status}).`);
  const contentType = response.headers.get("content-type") || "image/jpeg";
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (!bytes.length) throw new Error("Una imagen del respaldo llegó vacía.");
  return { bytes, contentType };
}

function storageObjectPathFromPublicUrl_(urlValue: unknown): string | null {
  const raw = String(urlValue || "").trim();
  if (!raw) return null;
  try {
    const u = new URL(raw);
    const base = new URL(String(SUPABASE_URL));
    if (u.origin !== base.origin) return null;
    const prefix = `/storage/v1/object/public/${STORAGE_BUCKET}/`;
    if (!u.pathname.startsWith(prefix)) return null;
    const encoded = u.pathname.slice(prefix.length);
    if (!encoded) return null;
    return decodeURIComponent(encoded);
  } catch (_) {
    return null;
  }
}

async function verifySecureBackupZip_(receipt: any) {
  if (!receipt?.object_path || !receipt?.sha256) {
    return { ok:false, error:"El recibo de respaldo no tiene ruta o SHA-256." };
  }
  const downloaded = await supabase.storage.from(BACKUP_BUCKET).download(receipt.object_path);
  if (downloaded.error || !downloaded.data) {
    return { ok:false, error:"No se pudo descargar el ZIP verificado desde Storage privado." };
  }
  const bytes = new Uint8Array(await downloaded.data.arrayBuffer());
  if (!bytes.length) return { ok:false, error:"El ZIP verificado está vacío." };
  if (Number(receipt.size_bytes || 0) > 0 && bytes.byteLength !== Number(receipt.size_bytes)) {
    return { ok:false, error:"El tamaño del ZIP ya no coincide con el recibo verificado." };
  }
  const sha = await sha256Hex_(bytes);
  if (sha !== String(receipt.sha256)) {
    return { ok:false, error:"La huella SHA-256 del ZIP ya no coincide con el recibo verificado." };
  }
  let manifest:any = null;
  try {
    const JSZip = await getJSZip_();
    const zip = await JSZip.loadAsync(bytes);
    const manifestFile = zip.file("manifest.json");
    if (!manifestFile) return { ok:false, error:"El ZIP no contiene manifest.json." };
    manifest = JSON.parse(await manifestFile.async("string"));
    const listed = Array.isArray(manifest?.images) ? manifest.images : [];
    if (listed.length !== Number(receipt.image_count || 0)) {
      return { ok:false, error:"El número de imágenes del manifest no coincide con el recibo verificado." };
    }
    for (const item of listed) {
      if (!item?.path || !zip.file(String(item.path))) {
        return { ok:false, error:"El ZIP verificado no contiene todas las imágenes declaradas en el manifest." };
      }
    }
  } catch (e) {
    return { ok:false, error:`No se pudo validar el contenido del ZIP: ${String((e as any)?.message || e)}` };
  }
  return { ok:true, bytes, manifest, sha256:sha };
}

async function sha256Hex_(bytes: Uint8Array) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function stableCanonical_(value: any): any {
  if (Array.isArray(value)) return value.map(stableCanonical_);
  if (value && typeof value === "object") {
    const out: Record<string, any> = {};
    for (const key of Object.keys(value).sort()) out[key] = stableCanonical_(value[key]);
    return out;
  }
  return value;
}

function sortRowsById_(rows: any[]) {
  return [...(rows || [])].sort((a,b)=>String(a?.id||"").localeCompare(String(b?.id||"")));
}

async function snapshotSha256_(payload: any) {
  const canonical = JSON.stringify(stableCanonical_(payload));
  return await sha256Hex_(new TextEncoder().encode(canonical));
}

// F4.1: la huella estricta de F2/F3 incluía metadatos técnicos (p. ej. updated_at).
// Esos campos pueden cambiar sin alterar el contenido deportivo de la Polla.
// Para decidir si el sello sigue siendo válido comparamos también una vista semántica
// que conserva IDs, marcadores, pagos, resultados, puntos, referidos, etc., pero ignora
// únicamente marcas de tiempo operativas.
function compactionSemanticView_(value:any):any {
  if (Array.isArray(value)) return value.map(compactionSemanticView_);
  if (!value || typeof value !== "object") return value;
  const volatile = new Set([
    "created_at","updated_at","compacted_at","ts","last_seen_at","last_updated_at"
  ]);
  const out:any = {};
  for (const key of Object.keys(value).sort()) {
    if (volatile.has(key)) continue;
    out[key] = compactionSemanticView_(value[key]);
  }
  return out;
}

async function compactionSemanticSha256_(snapshot:any) {
  return await snapshotSha256_(compactionSemanticView_(snapshot));
}

async function compactionChangedSections_(sealed:any,current:any) {
  const keys=["polla","matches","participants","predictions","referidos","standings"];
  const changed:string[]=[];
  for (const k of keys) {
    const a=await compactionSemanticSha256_(sealed?.[k] ?? null);
    const b=await compactionSemanticSha256_(current?.[k] ?? null);
    if(a!==b) changed.push(k);
  }
  return changed;
}

function buildCompactionSnapshot_(polla:any, matches:any[], participants:any[], predictions:any[], refs:any[], standings:any[]) {
  return {
    version: 2,
    polla,
    matches: sortRowsById_(matches),
    participants: sortRowsById_(participants),
    predictions: sortRowsById_(predictions),
    referidos: sortRowsById_(refs),
    standings: [...(standings || [])].sort((a,b)=>String(a?.name||"").localeCompare(String(b?.name||""))),
  };
}

async function loadPollaCompactionData_(pollaId:string) {
  const { data: polla, error: pollaErr } = await supabase.from("pollas").select("*").eq("id", pollaId).maybeSingle();
  if (pollaErr) throw pollaErr;
  if (!polla) return null;
  const [matches, participants, refs] = await Promise.all([
    fetchAllPages<any>((from,to)=>supabase.from("partidos").select("*").eq("polla_id",pollaId).range(from,to)),
    fetchAllPages<any>((from,to)=>supabase.from("participantes").select("*, jugadores(name)").eq("polla_id",pollaId).range(from,to)),
    fetchAllPages<any>((from,to)=>supabase.from("referidos").select("*").eq("polla_id",pollaId).range(from,to)),
  ]);
  const matchIds = matches.map((m:any)=>m.id);
  const predictions = matchIds.length
    ? await fetchAllPages<any>((from,to)=>supabase.from("pronosticos").select("*, jugadores(name)").in("partido_id",matchIds).range(from,to))
    : [];
  const standings = await computePollaStandingsForAdmin(pollaId);
  const imageCount = (polla.image_url ? 1 : 0) + matches.filter((m:any)=>!!m.image_url).length;
  const counts = { participants: participants.length, matches: matches.length, predictions: predictions.length, referrals: refs.length, images: imageCount };
  const snapshot = buildCompactionSnapshot_(polla, matches, participants, predictions, refs, standings);
  const snapshotSha256 = await snapshotSha256_(snapshot);
  return { polla, matches, participants, refs, predictions, standings, counts, snapshot, snapshotSha256 };
}


async function getCompactedHistory_(pollaId:string) {
  const { data, error } = await supabase
    .from("polla_compacted_history")
    .select("id,polla_id,compacted_at,snapshot_json,standings_json,participant_count,match_count,prediction_count,image_count,storage_cleaned_at,storage_cleaned_by,storage_cleanup_status,storage_removed_count,storage_skipped_count,storage_cleanup_manifest")
    .eq("polla_id", pollaId)
    .maybeSingle();
  if (error) {
    // Compatibilidad durante despliegue: si F4 SQL aún no está aplicado,
    // las lecturas históricas siguen usando las tablas operativas.
    if (String(error.message || "").toLowerCase().includes("polla_compacted_history")) return null;
    throw error;
  }
  return data || null;
}

function snapshotParticipantName_(row:any):string {
  const j = row?.jugadores;
  if (Array.isArray(j)) return String(j[0]?.name || "");
  return String(j?.name || row?.name || "");
}
function snapshotPredictionPublic_(pr:any){
  return {
    name:snapshotParticipantName_(pr), home:pr?.home, away:pr?.away,
    editCount:pr?.edit_count ?? pr?.editCount ?? 0, points:pr?.points,
    ts:pr?.updated_at ?? pr?.ts ?? null,
  };
}

// G1: los respaldos/snapshots compactados son inmutables. Si una identidad se
// elimina desde Admin, no reescribimos el respaldo sellado: aplicamos una capa
// de anonimización al LEER el histórico. Así no se rompe ningún SHA ni sello.
async function getHistoricalErasureMaps_(){
  const {data=[], error}=await supabase
    .from("player_history_erasure")
    .select("player_id,original_name_key,anonymous_name");
  if(error){
    if(String(error.message||"").toLowerCase().includes("player_history_erasure")) return {byId:new Map(),byKey:new Map()};
    throw error;
  }
  const byId=new Map<string,string>();
  const byKey=new Map<string,string>();
  for(const r of data||[]){
    const anon=String(r.anonymous_name||"Jugador eliminado");
    if(r.player_id) byId.set(String(r.player_id),anon);
    if(r.original_name_key) byKey.set(String(r.original_name_key),anon);
  }
  return {byId,byKey};
}
function historicalVisibleName_(row:any,maps:any):string{
  const id=String(row?.jugador_id ?? row?.player_id ?? "");
  if(id && maps?.byId?.has(id)) return maps.byId.get(id);
  const raw=snapshotParticipantName_(row);
  const key=normalizeName(raw);
  if(key && maps?.byKey?.has(key)) return maps.byKey.get(key);
  return raw;
}
function historicalStandingVisible_(row:any,maps:any){
  const raw=String(row?.name||"");
  const key=normalizeName(raw);
  return key && maps?.byKey?.has(key) ? {...row,name:maps.byKey.get(key)} : row;
}

function jsonOut(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json; charset=utf-8",
    },
  });
}

// ============================================================================
// HELPERS GENERALES
// ============================================================================

// Mismo criterio de identidad que la app:
// - ignora mayúsculas/minúsculas
// - ignora tildes
// - ignora espacios internos
function normalizeName(s: string) {
  return String(s || "")
    .trim()
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/\s+/g, "");
}

function cleanName(value: unknown): string {
  return String(value ?? "")
    .trim()
    .replace(/\s+/g, " ");
}

function cleanPin(value: unknown): string {
  return String(value ?? "").trim();
}

// H4.5: durante Beta aceptamos PIN histórico de 4 dígitos al AUTENTICAR.
function validExistingPin(pin: string): boolean {
  return /^\d{4,5}$/.test(pin);
}

// Todo PIN NUEVO desde H4.5 debe tener exactamente 5 dígitos.
function validNewPin(pin: string): boolean {
  return /^\d{5}$/.test(pin);
}

function normalizeWhatsapp(value: unknown): string | null {
  const raw = String(value ?? "").trim();
  if (!raw) return null;
  const digits = raw.replace(/\D/g, "");
  if (digits.length < 7 || digits.length > 15) return "__INVALID__";
  return raw.startsWith("+") ? "+" + digits : digits;
}


type AppConfig = {
  maintenanceEnabled: boolean;
  maintenanceMessage: string;
  predictionsEnabled: boolean;
  registrationsEnabled: boolean;
  tutorialUrl: string;
  updateCheckSeconds: number;
};

const DEFAULT_APP_CONFIG: AppConfig = {
  maintenanceEnabled: false,
  maintenanceMessage: "",
  predictionsEnabled: true,
  registrationsEnabled: true,
  tutorialUrl: "https://www.youtube.com/@TU_CANAL_AQUI",
  updateCheckSeconds: 600,
};

let appConfigCache_: { data: AppConfig | null; at: number } = { data: null, at: 0 };

async function getAppConfig_(): Promise<AppConfig> {
  if (appConfigCache_.data && Date.now() - appConfigCache_.at < 5000) return appConfigCache_.data;
  const { data, error } = await supabase
    .from("app_config")
    .select("maintenance_enabled,maintenance_message,predictions_enabled,registrations_enabled,tutorial_url,update_check_seconds")
    .eq("id", 1)
    .maybeSingle();
  if (error) {
    // Fallback seguro para un despliegue donde el SQL aún no llegó: no romper la app.
    console.error("app_config read", error.message);
    return DEFAULT_APP_CONFIG;
  }
  const cfg: AppConfig = data ? {
    maintenanceEnabled: !!data.maintenance_enabled,
    maintenanceMessage: String(data.maintenance_message || ""),
    predictionsEnabled: data.predictions_enabled !== false,
    registrationsEnabled: data.registrations_enabled !== false,
    tutorialUrl: String(data.tutorial_url || DEFAULT_APP_CONFIG.tutorialUrl),
    updateCheckSeconds: Math.min(900, Math.max(60, Number(data.update_check_seconds || DEFAULT_APP_CONFIG.updateCheckSeconds))),
  } : DEFAULT_APP_CONFIG;
  appConfigCache_ = { data: cfg, at: Date.now() };
  return cfg;
}

function maintenanceBlocked_(cfg: AppConfig) {
  return cfg.maintenanceEnabled;
}

function relatedName(value: any): string {
  if (!value) return "";
  if (Array.isArray(value)) return value[0]?.name ?? "";
  return value.name ?? "";
}

// Supabase suele limitar una respuesta REST a 1000 filas. Cualquier lectura
// que pueda superar ese tamaño debe paginar para no truncar silenciosamente
// pronósticos, standings, tendencias o backups.
async function fetchAllPages<T>(
  makeQuery: (from: number, to: number) => PromiseLike<{ data: T[] | null; error: any }>,
  pageSize = 1000,
): Promise<T[]> {
  const out: T[] = [];
  for (let from = 0; ; from += pageSize) {
    const { data, error } = await makeQuery(from, from + pageSize - 1);
    if (error) throw error;
    const rows = data || [];
    out.push(...rows);
    if (rows.length < pageSize) break;
  }
  return out;
}

// Ranking 0-based para que el frontend siga usando rank + 1.
function assignRanks<T extends { totalPoints: number; rank?: number }>(
  list: T[],
): T[] {
  let currentRank = 0;

  list.forEach((s, i) => {
    if (i > 0 && s.totalPoints < list[i - 1].totalPoints) {
      currentRank++;
    }
    s.rank = currentRank;
  });

  return list;
}

// ============================================================================
// HASH PRIVADO DE PIN / RESPUESTA DE SEGURIDAD
// ============================================================================

let AUTH_HMAC_KEY_PROMISE_: Promise<CryptoKey> | null = null;
function authHmacKey_(): Promise<CryptoKey> {
  if (!AUTH_HMAC_KEY_PROMISE_) {
    AUTH_HMAC_KEY_PROMISE_ = crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(AUTH_PEPPER!),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
  }
  return AUTH_HMAC_KEY_PROMISE_;
}

async function hashPrivateValue(value: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await authHmacKey_();

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(String(value)),
  );

  return Array.from(new Uint8Array(signature))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ============================================================================
// CONCURSO GRATUITO / TABLA ANUAL
// ============================================================================

const FREE_CONTEST_TOP_PERCENT = 0.60;

function computeFreeContestQualifiers(sortedStandings: any[]) {
  const total = sortedStandings.length;

  if (total === 0) {
    return {
      qualifiedCount: 0,
      qualifiedKeys: {} as Record<string, boolean>,
    };
  }

  let cutoffCount = Math.round(total * FREE_CONTEST_TOP_PERCENT);

  if (cutoffCount < 1) cutoffCount = 1;
  if (cutoffCount > total) cutoffCount = total;

  const boundaryPoints =
    Number(sortedStandings[cutoffCount - 1].totalPoints) || 0;

  const qualifiedKeys: Record<string, boolean> = {};
  let qualifiedCount = 0;

  for (const s of sortedStandings) {
    if (Number(s.totalPoints) >= boundaryPoints) {
      qualifiedKeys[normalizeName(s.name)] = true;
      qualifiedCount++;
    }
  }

  return {
    qualifiedCount,
    qualifiedKeys,
  };
}

async function getSeasonStart(): Promise<string> {
  const { data, error } = await supabase
    .from("temporadas")
    .select("closed_at")
    .order("closed_at", { ascending: false })
    .limit(1)
    .maybeSingle();

  if (error) throw error;

  return data?.closed_at ?? "1970-01-01T00:00:00Z";
}

async function computeYearlyStandings() {
  // C3: primero pedimos a Postgres el resumen anual ya agregado. Esto evita
  // descargar a la Edge Function todas las participaciones, partidos y
  // pronósticos de la temporada solo para volver a sumarlos en JavaScript.
  // Si la RPC aún no existe o falla, conservamos el cálculo anterior como
  // fallback para que un despliegue parcial no rompa la tabla anual.
  try {
    const { data: yearlyRpc, error: yearlyRpcError } = await supabase.rpc(
      "get_yearly_standings_summary_tico",
    );

    if (!yearlyRpcError && Array.isArray(yearlyRpc)) {
      const normalized = yearlyRpc.map((row: any) => ({
        name: String(row?.name || "").trim(),
        totalPoints: Number(row?.totalPoints ?? row?.total_points ?? 0),
        matchesScored: Number(row?.matchesScored ?? row?.matches_scored ?? 0),
        exactCount: Number(row?.exactCount ?? row?.exact_count ?? 0),
        mvpCount: Number(row?.mvpCount ?? row?.mvp_count ?? 0),
      })).filter((row: any) => row.name);

      return assignRanks(normalized.sort(
        (a: any, z: any) => z.totalPoints - a.totalPoints,
      ));
    }
  } catch (_) {
    // Fallback V19/C2 debajo.
  }

  const seasonStart = await getSeasonStart();

  // ------------------------------------------------------------------------
  // 1) SEMBRAR TODOS LOS PARTICIPANTES DE LA TEMPORADA, AUNQUE TENGAN 0 PTS
  //
  // Antes la tabla anual nacía únicamente de pronósticos + arrastre histórico.
  // Eso hacía que alguien agregado desde Admin no apareciera hasta guardar al
  // menos un pronóstico. Ahora cualquier participante inscrito durante la
  // temporada actual entra inmediatamente con 0 puntos.
  // ------------------------------------------------------------------------
  const totals: Record<string, any> = {};

  const { data: seasonPollas = [], error: seasonPollasErr } = await supabase
    .from("pollas")
    .select("id")
    .gte("season_started_at", seasonStart);
  if (seasonPollasErr) throw seasonPollasErr;
  const seasonPollaIds = seasonPollas.map((p:any)=>p.id);

  let participantesTemporada:any[] = [];
  if (seasonPollaIds.length) {
    participantesTemporada = await fetchAllPages<any>((from, to) =>
      supabase
        .from("participantes")
        .select("jugador_id, jugadores(name)")
        .in("polla_id", seasonPollaIds)
        .range(from, to)
    );
  }

  for (const p of participantesTemporada) {
    const name = relatedName(p.jugadores);
    if (!name) continue;

    const key = normalizeName(name);
    if (!key) continue;

    if (!totals[key]) {
      totals[key] = {
        name,
        totalPoints: 0,
        matchesScored: 0,
        exactCount: 0,
        mvpCount: 0,
      };
    } else {
      // Si el jugador fue renombrado, usamos siempre el nombre actual.
      totals[key].name = name;
    }
  }

  // ------------------------------------------------------------------------
  // 2) PARTIDOS Y PRONÓSTICOS DE LA TEMPORADA
  // ------------------------------------------------------------------------
  let partidos:any[] = [];
  if (seasonPollaIds.length) {
    partidos = await fetchAllPages<any>((from, to) =>
      supabase
        .from("partidos")
        .select("id, result_submitted, actual_home, actual_away, is_canceled")
        .eq("is_canceled", false)
        .eq("result_submitted", true)
        .in("polla_id", seasonPollaIds)
        .range(from, to)
    );
  }

  const matchInfo: Record<string, any> = {};

  for (const m of partidos) {
    matchInfo[m.id] = {
      resultSubmitted: m.result_submitted,
      actualHome: m.actual_home,
      actualAway: m.actual_away,
    };
  }

  const matchIds = partidos.map((m) => m.id);

  let pronosticos: any[] = [];

  if (matchIds.length) {
    pronosticos = await fetchAllPages<any>((from, to) =>
      supabase
        .from("pronosticos")
        .select(
          "partido_id, jugador_id, home, away, points, jugadores(name)",
        )
        .in("partido_id", matchIds)
        .range(from, to)
    );
  }

  // Máximo de puntos por partido para contar MVP.
  const matchMax: Record<string, number> = {};

  for (const pr of pronosticos) {
    if (!matchInfo[pr.partido_id]?.resultSubmitted) continue;
    if (pr.points === null || pr.points === undefined) continue;

    const pts = Number(pr.points);

    if (
      matchMax[pr.partido_id] === undefined ||
      pts > matchMax[pr.partido_id]
    ) {
      matchMax[pr.partido_id] = pts;
    }
  }

  for (const pr of pronosticos) {
    const info = matchInfo[pr.partido_id];
    if (!info) continue;

    const name = relatedName(pr.jugadores);
    if (!name) continue;

    const key = normalizeName(name);
    if (!key) continue;

    if (!totals[key]) {
      totals[key] = {
        name,
        totalPoints: 0,
        matchesScored: 0,
        exactCount: 0,
        mvpCount: 0,
      };
    } else {
      totals[key].name = name;
    }

    // Pronóstico todavía sin resultado: no cuenta como partido puntuado.
    if (pr.points === null || pr.points === undefined) continue;

    totals[key].totalPoints += Number(pr.points);
    totals[key].matchesScored += 1;

    if (
      info.resultSubmitted &&
      Number(pr.home) === Number(info.actualHome) &&
      Number(pr.away) === Number(info.actualAway)
    ) {
      totals[key].exactCount += 1;
    }

    if (
      matchMax[pr.partido_id] !== undefined &&
      matchMax[pr.partido_id] > 0 &&
      Number(pr.points) === matchMax[pr.partido_id]
    ) {
      totals[key].mvpCount += 1;
    }
  }

  // ------------------------------------------------------------------------
  // 3) ARRASTRE BASE HISTÓRICO
  //
  // Una persona puede existir en la tabla histórica ANTES de tener una cuenta
  // real en jugadores. Por eso tabla_acumulada_base conserva name + name_key
  // y jugador_id es opcional.
  // ------------------------------------------------------------------------
  const base = await fetchAllPages<any>((from, to) =>
    supabase
      .from("tabla_acumulada_base")
      .select("jugador_id, name, name_key, base_points, base_matches_scored, base_exact_count, base_mvp_count, jugadores(name)")
      .range(from, to)
  );

  for (const b of base) {
    const basePoints = Number(b.base_points) || 0;
    const baseMatches = Number(b.base_matches_scored) || 0;
    const baseExacts = Number(b.base_exact_count) || 0;
    const baseMvps = Number(b.base_mvp_count) || 0;

    const linkedName = relatedName(b.jugadores);
    const name = linkedName || String(b.name || "").trim();
    if (!name) continue;

    const key = String(b.name_key || normalizeName(name));
    if (!key) continue;

    if (!totals[key]) {
      totals[key] = {
        name,
        totalPoints: 0,
        matchesScored: 0,
        exactCount: 0,
        mvpCount: 0,
      };
    } else if (linkedName) {
      // Cuando ya existe identidad real, usamos su nombre actual en pantalla.
      totals[key].name = linkedName;
    }

    totals[key].totalPoints += basePoints;
    totals[key].matchesScored += baseMatches;
    totals[key].exactCount += baseExacts;
    totals[key].mvpCount += baseMvps;
  }

  return assignRanks(
    Object.values(totals).sort(
      (a: any, b: any) => b.totalPoints - a.totalPoints,
    ) as any[],
  );
}

// ============================================================================
// HELPERS DE IDENTIDAD / PARTICIPACIÓN
// ============================================================================

async function findJugador(name: string) {
  const nameKey = normalizeName(name);
  if (!nameKey) return null;

  const { data, error } = await supabase
    .from("jugadores")
    .select(
      `
      id,
      name,
      name_key,
      pin_hash,
      failed_attempts,
      security_answer_hash,
      whatsapp,
      activation_code_hash,
      activation_code_enc,
      activation_purpose,
      activation_created_at,
      created_at
      `,
    )
    .eq("name_key", nameKey)
    .maybeSingle();

  if (error) throw error;
  return data;
}

async function findParticipant(
  pollaId: string,
  jugadorId: string,
) {
  const { data, error } = await supabase
    .from("participantes")
    .select(
      `
      id,
      polla_id,
      jugador_id,
      paid,
      referral_code,
      referred_by_code,
      created_at
      `,
    )
    .eq("polla_id", pollaId)
    .eq("jugador_id", jugadorId)
    .maybeSingle();

  if (error) throw error;
  return data;
}

async function assertCanEnroll(
  pollaId: string,
  jugadorId: string | null,
  name: string,
) {
  // G2: ciclo de vida centralizado.
  // ACTIVA: acceso/alta normal.
  // FINAL_REVIEW: solo participantes existentes pueden iniciar sesión y consultar.
  // COMPACTED: histórico protegido; no existe sesión de jugador ni escrituras.
  const { data: polla, error } = await supabase
    .from("pollas")
    .select("id, start_date, is_free_polla, status, is_archived, compacted_at")
    .eq("id", pollaId)
    .maybeSingle();

  if (error) throw error;
  if (!polla) return { ok:false, error:"POLLA_NO_ENCONTRADA", lifecycle:"NONE" };

  if (polla.compacted_at) {
    return { ok:false, error:"POLLA_COMPACTADA", lifecycle:"COMPACTED" };
  }

  let existingParticipant:any = null;
  if (jugadorId) existingParticipant = await findParticipant(pollaId, jugadorId);

  const finished = polla.status === "finalizada" || !!polla.is_archived;
  if (finished) {
    if (existingParticipant) {
      return { ok:true, existingParticipant, readOnly:true, lifecycle:"FINAL_REVIEW" };
    }
    return { ok:false, error:"POLLA_FINALIZADA", readOnly:true, lifecycle:"FINAL_REVIEW" };
  }

  if (existingParticipant) {
    return { ok:true, existingParticipant, readOnly:false, lifecycle:"ACTIVE" };
  }

  // La fecha de inicio es el cierre de nuevas inscripciones.
  if (polla.start_date) {
    const start = new Date(polla.start_date).getTime();
    if (Date.now() >= start) return { ok:false, error:"INSCRIPCIONES_CERRADAS", lifecycle:"ACTIVE" };
  }

  if (polla.is_free_polla) {
    const standings = await computeYearlyStandings();
    const qualifiers = computeFreeContestQualifiers(standings);
    if (!qualifiers.qualifiedKeys[normalizeName(name)]) {
      return { ok:false, error:"NOT_QUALIFIED", lifecycle:"ACTIVE" };
    }
  }

  return { ok:true, readOnly:false, lifecycle:"ACTIVE" };
}

async function referralCodeIsValid(
  pollaId: string,
  code: string,
) {
  if (!code) return true;

  const { data, error } = await supabase
    .from("participantes")
    .select("id")
    .eq("polla_id", pollaId)
    .eq("referral_code", code.toUpperCase())
    .limit(1);

  if (error) throw error;

  return !!data?.length;
}


let activationCryptoKeyPromise_: Promise<CryptoKey> | null = null;
async function activationCryptoKey_(): Promise<CryptoKey> {
  if(!activationCryptoKeyPromise_){
    activationCryptoKeyPromise_ = (async()=>{
      const material = new TextEncoder().encode(`tico:activation-code:v1:${AUTH_PEPPER}`);
      const digest = await crypto.subtle.digest('SHA-256', material);
      return await crypto.subtle.importKey('raw', digest, {name:'AES-GCM'}, false, ['encrypt','decrypt']);
    })();
  }
  return activationCryptoKeyPromise_;
}
function activationB64_(bytes:Uint8Array){
  let bin=''; for(const x of bytes) bin+=String.fromCharCode(x);
  return btoa(bin).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'');
}
function activationUnb64_(value:string){
  const base64=value.replace(/-/g,'+').replace(/_/g,'/')+'==='.slice((value.length+3)%4);
  const bin=atob(base64); return Uint8Array.from(bin,c=>c.charCodeAt(0));
}
async function encryptActivationCode_(code:string):Promise<string>{
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const cipher=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv},await activationCryptoKey_(),new TextEncoder().encode(code)));
  return `v1.${activationB64_(iv)}.${activationB64_(cipher)}`;
}
async function decryptActivationCode_(value:unknown):Promise<string>{
  const raw=String(value||''); if(!raw)return '';
  try{
    const [v,ivRaw,cipherRaw]=raw.split('.'); if(v!=='v1'||!ivRaw||!cipherRaw)return '';
    const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:activationUnb64_(ivRaw)},await activationCryptoKey_(),activationUnb64_(cipherRaw));
    return new TextDecoder().decode(plain);
  }catch(_){ return ''; }
}

function makeActivationCode(): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = new Uint32Array(4);
  crypto.getRandomValues(bytes);
  let result = "TICO-";
  for (let i = 0; i < bytes.length; i++) {
    result += chars[bytes[i] % chars.length];
  }
  return result;
}

async function setActivationCode(
  jugadorId: string,
  purpose: "FIRST" | "RESET" | "SPLIT" = "FIRST",
) {
  const code = makeActivationCode();
  const [codeHash, codeEncrypted] = await Promise.all([
    hashPrivateValue(code.toUpperCase()),
    encryptActivationCode_(code.toUpperCase()),
  ]);
  const { error } = await supabase
    .from("jugadores")
    .update({
      activation_code_hash: codeHash,
      activation_code_enc: codeEncrypted,
      activation_purpose: purpose,
      activation_created_at: new Date().toISOString(),
    })
    .eq("id", jugadorId);
  if (error) throw error;
  return code;
}

async function activateWithCode(
  jugador: any,
  codeInput: unknown,
  newPinInput: unknown,
) {
  const code = String(codeInput || "").trim().toUpperCase();
  const newPin = cleanPin(newPinInput);
  if (!code || !jugador?.activation_code_hash) {
    return { ok: false, error: "CODIGO_ACTIVACION_INVALIDO" };
  }
  if (!validNewPin(newPin)) {
    return { ok: false, error: "PIN_INVALIDO" };
  }
  const incoming = await hashPrivateValue(code);
  if (incoming !== jugador.activation_code_hash) {
    // El código tiene un espacio de búsqueda mucho mayor que el PIN y solo se
    // usa una vez. Una demora breve frena intentos automáticos sin dejar al
    // jugador legítimo bloqueado cerca de la hora de cierre.
    await new Promise((resolve) => setTimeout(resolve, 650));
    return { ok: false, error: "CODIGO_ACTIVACION_INVALIDO" };
  }
  const pinHash = await hashPrivateValue(newPin);
  const { error } = await supabase
    .from("jugadores")
    .update({
      pin_hash: pinHash,
      failed_attempts: 0,
      activation_code_hash: null,
      activation_code_enc: null,
      activation_purpose: null,
      activation_created_at: null,
    })
    .eq("id", jugador.id);
  if (error) throw error;
  return { ok: true };
}

async function registerReferralHistory(
  pollaId: string,
  invitedJugadorId: string,
  referredByCode: string,
) {
  const code = String(referredByCode || "").trim().toUpperCase();
  if (!code) return;
  const { data: inviter, error } = await supabase
    .from("participantes")
    .select("jugador_id")
    .eq("polla_id", pollaId)
    .eq("referral_code", code)
    .maybeSingle();
  if (error) throw error;
  if (!inviter?.jugador_id || inviter.jugador_id === invitedJugadorId) return;
  const ins = await supabase
    .from("referidos")
    .upsert({
      polla_id: pollaId,
      invitador_jugador_id: inviter.jugador_id,
      invitado_jugador_id: invitedJugadorId,
    }, { onConflict: "polla_id,invitado_jugador_id" });
  if (ins.error) throw ins.error;
}

async function hasHistoricalIdentity(jugador: any): Promise<boolean> {
  const jugadorId = jugador.id;
  const key = normalizeName(jugador.name);
  const [parts, preds, base, wins, seasons] = await Promise.all([
    supabase.from("participantes").select("id", { count: "exact", head: true }).eq("jugador_id", jugadorId),
    supabase.from("pronosticos").select("id", { count: "exact", head: true }).eq("jugador_id", jugadorId),
    supabase.from("tabla_acumulada_base").select("base_points").or(`jugador_id.eq.${jugadorId},name_key.eq.${key}`),
    supabase.from("ganadores").select("wins").eq("name", jugador.name),
    supabase.from("temporadas").select("standings_json, qualified_names"),
  ]);
  for (const r of [parts, preds, base, wins, seasons]) if (r.error) throw r.error;
  if ((parts.count || 0) > 0 || (preds.count || 0) > 0) return true;
  if ((base.data || []).length > 0) return true;
  if ((wins.data || []).some((x:any)=>Number(x.wins || 0) > 0)) return true;
  for (const s of seasons.data || []) {
    const standings = Array.isArray(s.standings_json) ? s.standings_json : [];
    if (standings.some((x:any)=>normalizeName(x?.name || "") === key)) return true;
    const q = Array.isArray(s.qualified_names) ? s.qualified_names : [];
    if (q.some((n:any)=>normalizeName(String(n || "")) === key)) return true;
  }
  return false;
}

async function willRemainHistoricalAfterPollaRemoval(jugador: any, pollaId: string): Promise<boolean> {
  const jugadorId = jugador.id;
  const key = normalizeName(jugador.name);

  const { data: currentMatches = [], error: cmErr } = await supabase
    .from("partidos")
    .select("id")
    .eq("polla_id", pollaId);
  if (cmErr) throw cmErr;
  const currentMatchIds = new Set((currentMatches || []).map((m:any) => m.id));

  const [otherParts, allPreds, base, wins, seasons] = await Promise.all([
    supabase.from("participantes").select("id", { count: "exact", head: true })
      .eq("jugador_id", jugadorId).neq("polla_id", pollaId),
    fetchAllPages<any>((from,to)=>supabase.from("pronosticos")
      .select("id, partido_id").eq("jugador_id", jugadorId).range(from,to)),
    supabase.from("tabla_acumulada_base").select("base_points")
      .or(`jugador_id.eq.${jugadorId},name_key.eq.${key}`),
    supabase.from("ganadores").select("wins").eq("name", jugador.name),
    supabase.from("temporadas").select("standings_json, qualified_names"),
  ]);

  for (const r of [otherParts, base, wins, seasons]) if ((r as any).error) throw (r as any).error;
  if ((otherParts.count || 0) > 0) return true;
  if ((allPreds || []).some((x:any)=>!currentMatchIds.has(x.partido_id))) return true;
  if ((base.data || []).length > 0) return true;
  if ((wins.data || []).some((x:any)=>Number(x.wins || 0) > 0)) return true;
  for (const season of seasons.data || []) {
    const standings = Array.isArray(season.standings_json) ? season.standings_json : [];
    if (standings.some((x:any)=>normalizeName(x?.name || "") === key)) return true;
    const qualified = Array.isArray(season.qualified_names) ? season.qualified_names : [];
    if (qualified.some((n:any)=>normalizeName(String(n || "")) === key)) return true;
  }
  return false;
}

async function cleanupOrphanPlayer(jugador: any) {
  if (await hasHistoricalIdentity(jugador)) {
    return { deletedGlobally: false };
  }
  // Si la cuenta realmente queda huérfana, se puede borrar su identidad global.
  // IMPORTANTE: si esta persona había sido INVITADA por otro jugador, ese
  // referido histórico debe seguir contando aunque el invitado se retire.
  // Por eso solo retiramos relaciones donde esta persona era el INVITADOR;
  // las filas donde era invitado sobreviven gracias al FK ON DELETE SET NULL.
  const rd = await supabase.from("referidos").delete()
    .eq("invitador_jugador_id", jugador.id);
  if (rd.error) throw rd.error;
  const d = await supabase.from("jugadores").delete().eq("id", jugador.id);
  if (d.error) throw d.error;
  return { deletedGlobally: true };
}

function makeReferralCode(): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = new Uint32Array(4);
  crypto.getRandomValues(bytes);
  let result = "TICO";

  for (let i = 0; i < bytes.length; i++) {
    result += chars[bytes[i] % chars.length];
  }

  return result;
}

async function ensureEnrolled(
  pollaId: string,
  jugadorId: string,
  referredByCodeInput = "",
) {
  const existing =
    await findParticipant(pollaId, jugadorId);

  if (existing) {
    return {
      isNew: false,
      referralCode: existing.referral_code,
    };
  }

  const referredByCode =
    String(referredByCodeInput || "")
      .trim()
      .toUpperCase();

  for (let attempt = 0; attempt < 12; attempt++) {
    const referralCode = makeReferralCode();

    const { data, error } = await supabase
      .from("participantes")
      .insert({
        polla_id: pollaId,
        jugador_id: jugadorId,
        paid: false,
        referral_code: referralCode,
        referred_by_code: referredByCode || null,
      })
      .select("id, referral_code")
      .single();

    if (!error) {
      await registerReferralHistory(
        pollaId,
        jugadorId,
        referredByCode,
      );
      return {
        isNew: true,
        referralCode: data.referral_code,
      };
    }

    // UNIQUE violation. Puede ser:
    // - mismo código aleatorio
    // - otro request inscribió al jugador simultáneamente
    if (error.code === "23505") {
      const maybeExisting =
        await findParticipant(pollaId, jugadorId);

      if (maybeExisting) {
        return {
          isNew: false,
          referralCode:
            maybeExisting.referral_code,
        };
      }

      continue;
    }

    throw error;
  }

  throw new Error(
    "No se pudo generar un código de invitación único.",
  );
}

async function resolveIdentity(
  jugador: any,
  pin: string,
) {
  // Una identidad pendiente de activación/reset NUNCA puede apropiarse
  // escribiendo un PIN cualquiera. Debe usar su código temporal.
  if (!jugador.pin_hash) {
    return { status: "NEEDS_ACTIVATION" };
  }

  const incomingHash = await hashPrivateValue(pin);
  if (jugador.pin_hash === incomingHash) {
    if (Number(jugador.failed_attempts || 0) !== 0) {
      const { error } = await supabase
        .from("jugadores")
        .update({ failed_attempts: 0 })
        .eq("id", jugador.id);
      if (error) throw error;
    }
    return { status: "OK", jugadorName: jugador.name, wasReset: false };
  }

  // No bloqueamos globalmente al jugador: un tercero no puede impedirle
  // pronosticar a tiempo. Solo añadimos una pequeña demora anti-ráfaga.
  await new Promise((resolve) => setTimeout(resolve, 450));
  return { status: "WRONG_PIN" };
}

async function checkPredictionPin(
  jugador: any,
  pin: string,
) {
  if (!jugador.pin_hash) return { status: "NEEDS_ACTIVATION" };
  const hash = await hashPrivateValue(pin);
  if (jugador.pin_hash === hash) return { status: "OK" };
  await new Promise((resolve) => setTimeout(resolve, 450));
  return { status: "WRONG_PIN" };
}


// ============================================================================
// HELPERS ADMIN / STORAGE / PUNTUACIÓN
// ============================================================================

const ADMIN_PIN = Deno.env.get("ADMIN_PIN");
const ADMIN_MAX_ATTEMPTS = 5;
const ADMIN_SESSION_TTL_MS = 30 * 60 * 1000;
const ADMIN_SESSION_SECRET = Deno.env.get("ADMIN_SESSION_SECRET") || `${ADMIN_PIN}:${AUTH_PEPPER}`;

function bytesToBase64Url_(bytes: Uint8Array){
  let bin = "";
  for(const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
}
function textToBase64Url_(text: string){
  return bytesToBase64Url_(new TextEncoder().encode(text));
}
function base64UrlToText_(value: string){
  const base64 = value.replace(/-/g,"+").replace(/_/g,"/") + "===".slice((value.length + 3) % 4);
  const bin = atob(base64);
  const bytes = Uint8Array.from(bin, c => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}
let ADMIN_SESSION_KEY_PROMISE_: Promise<CryptoKey> | null = null;
async function adminSessionKey_(){
  if(!ADMIN_SESSION_KEY_PROMISE_){
    ADMIN_SESSION_KEY_PROMISE_ = crypto.subtle.importKey(
      "raw", new TextEncoder().encode(ADMIN_SESSION_SECRET),
      {name:"HMAC", hash:"SHA-256"}, false, ["sign","verify"]
    );
  }
  return await ADMIN_SESSION_KEY_PROMISE_;
}
async function createAdminSession_(originHash: string){
  const now = Date.now();
  const payload = {v:1, iat:now, exp:now + ADMIN_SESSION_TTL_MS};
  const encoded = textToBase64Url_(JSON.stringify(payload));
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", await adminSessionKey_(), new TextEncoder().encode(encoded)));
  return {token:`${encoded}.${bytesToBase64Url_(sig)}`, expiresAt:new Date(payload.exp).toISOString()};
}
async function verifyAdminSession_(token: unknown, originHash: string){
  try{
    const raw = String(token || "");
    const [encoded, signature] = raw.split(".");
    if(!encoded || !signature) return {ok:false, error:"ADMIN_SESSION_INVALID"};
    const expected = new Uint8Array(await crypto.subtle.sign("HMAC", await adminSessionKey_(), new TextEncoder().encode(encoded)));
    if(bytesToBase64Url_(expected) !== signature) return {ok:false, error:"ADMIN_SESSION_INVALID"};
    const payload = JSON.parse(base64UrlToText_(encoded));
    if(!payload.exp || Date.now() >= Number(payload.exp)) return {ok:false, error:"ADMIN_SESSION_EXPIRED"};
    return {ok:true, payload};
  }catch(_){
    return {ok:false, error:"ADMIN_SESSION_INVALID"};
  }
}

const ADMIN_CONFIRM_TTL_MS = 2 * 60 * 1000;
async function createAdminConfirm_(purpose: string, originHash: string){
  const now = Date.now();
  const payload = {v:1, kind:"admin-confirm", purpose, originHash, iat:now, exp:now + ADMIN_CONFIRM_TTL_MS};
  const encoded = textToBase64Url_(JSON.stringify(payload));
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", await adminSessionKey_(), new TextEncoder().encode(encoded)));
  return {token:`${encoded}.${bytesToBase64Url_(sig)}`, expiresAt:new Date(payload.exp).toISOString()};
}
async function verifyAdminConfirm_(token: unknown, purpose: string, originHash: string){
  try{
    const raw = String(token || "");
    const [encoded, signature] = raw.split(".");
    if(!encoded || !signature) return {ok:false, error:"ADMIN_CONFIRM_REQUIRED"};
    const expected = new Uint8Array(await crypto.subtle.sign("HMAC", await adminSessionKey_(), new TextEncoder().encode(encoded)));
    if(bytesToBase64Url_(expected) !== signature) return {ok:false, error:"ADMIN_CONFIRM_INVALID"};
    const payload = JSON.parse(base64UrlToText_(encoded));
    if(payload.kind !== "admin-confirm" || payload.purpose !== purpose || payload.originHash !== originHash) return {ok:false, error:"ADMIN_CONFIRM_INVALID"};
    if(!payload.exp || Date.now() >= Number(payload.exp)) return {ok:false, error:"ADMIN_CONFIRM_EXPIRED"};
    return {ok:true, payload};
  }catch(_){
    return {ok:false, error:"ADMIN_CONFIRM_INVALID"};
  }
}
const ADMIN_LOCK_MINUTES = 15;
const STORAGE_BUCKET = "tico-images";

if (!ADMIN_PIN) {
  throw new Error("Falta ADMIN_PIN en Edge Function Secrets.");
}

function boolParam(v: unknown): boolean {
  return String(v ?? "").toLowerCase() === "true";
}

function intParam(v: unknown, fallback = 0): number {
  const n = Number(v);
  return Number.isInteger(n) ? n : fallback;
}

function validDateParam_(v: unknown): boolean {
  if (v === null || v === undefined || String(v).trim() === "") return false;
  return Number.isFinite(new Date(String(v)).getTime());
}

async function requestOriginHash(req: Request): Promise<string> {
  const raw =
    req.headers.get("cf-connecting-ip") ||
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    req.headers.get("x-real-ip") ||
    req.headers.get("user-agent") ||
    "unknown";
  return (await hashPrivateValue("origin:" + raw)).slice(0, 32);
}

async function getRateLimit(kind: string, targetKey: string, originHash: string) {
  const { data, error } = await supabase
    .from("auth_rate_limits")
    .select("failed_attempts, lock_until")
    .eq("kind", kind)
    .eq("target_key", targetKey)
    .eq("origin_hash", originHash)
    .maybeSingle();
  if (error) throw error;
  return data;
}

async function clearRateLimit(kind: string, targetKey: string, originHash: string) {
  const { error } = await supabase.from("auth_rate_limits").delete()
    .eq("kind", kind).eq("target_key", targetKey).eq("origin_hash", originHash);
  if (error) throw error;
}

async function failRateLimit(
  kind: string,
  targetKey: string,
  originHash: string,
  maxAttempts: number,
  lockMinutes: number,
) {
  const current = await getRateLimit(kind, targetKey, originHash);
  const next = Number(current?.failed_attempts || 0) + 1;
  const lockUntil = next >= maxAttempts
    ? new Date(Date.now() + lockMinutes * 60000).toISOString()
    : null;
  const { error } = await supabase.from("auth_rate_limits").upsert({
    kind,
    target_key: targetKey,
    origin_hash: originHash,
    failed_attempts: lockUntil ? 0 : next,
    lock_until: lockUntil,
    updated_at: new Date().toISOString(),
  });
  if (error) throw error;
  return { locked: !!lockUntil, attemptsLeft: Math.max(0, maxAttempts - next), lockMinutes };
}

async function verifyAdminPin(pinAttempt: unknown, originHash: string) {
  const row = await getRateLimit("ADMIN_LOGIN", "admin", originHash);
  const lockUntil = row?.lock_until ? new Date(row.lock_until).getTime() : 0;
  if (lockUntil && Date.now() < lockUntil) {
    return { ok: false, error: "LOCKED", minutesLeft: Math.max(1, Math.ceil((lockUntil-Date.now())/60000)) };
  }
  if (String(pinAttempt || "") === ADMIN_PIN) {
    await clearRateLimit("ADMIN_LOGIN", "admin", originHash);
    return { ok: true };
  }
  const failed = await failRateLimit("ADMIN_LOGIN", "admin", originHash, ADMIN_MAX_ATTEMPTS, ADMIN_LOCK_MINUTES);
  if (failed.locked) return { ok: false, error: "LOCKED", minutesLeft: ADMIN_LOCK_MINUTES };
  return { ok: false, error: "WRONG_PIN", attemptsLeft: failed.attemptsLeft };
}

function describeAdminAction(
  action: string,
  p: Record<string, any>,
) {
  const bits: string[] = [];

  if (p.id) bits.push("id=" + p.id);
  if (p.name) bits.push("nombre=" + p.name);

  if (p.oldName) {
    bits.push(
      "de=" +
        p.oldName +
        " a=" +
        p.newName,
    );
  }

  if (p.number) {
    bits.push(
      "numero=" + p.number,
    );
  }

  if (p.totalMatches) {
    bits.push(
      "totalPartidosMeta=" +
        p.totalMatches,
    );
  }

  if (p.matchNumber) {
    bits.push(
      "partido=" + p.matchNumber,
    );
  }

  if (p.pollaId) {
    bits.push(
      "pollaId=" + p.pollaId,
    );
  }

  if (p.status) {
    bits.push(
      "estado=" + p.status,
    );
  }

  if (p.paid !== undefined) {
    bits.push(
      "paid=" + p.paid,
    );
  }

  if (p.seasonLabel) {
    bits.push(
      "temporada=" +
        p.seasonLabel,
    );
  }

  if (p.isFreePolla !== undefined) {
    bits.push(
      "isFreePolla=" +
        p.isFreePolla,
    );
  }

  if (
    p.actualHome !== undefined &&
    p.actualAway !== undefined
  ) {
    bits.push(
      "resultado=" +
        p.actualHome +
        "-" +
        p.actualAway,
    );
  }

  return bits.join(", ");
}

async function logAdminAction(
  action: string,
  adminName: unknown,
  details = "",
) {
  try {
    await supabase
      .from("admin_log")
      .insert({
        admin_name:
          String(
            adminName ||
              "Sin nombre",
          ).trim(),
        action,
        details:
          String(details || ""),
      });
  } catch (_) {
    // La auditoría nunca debe tumbar la acción real.
  }
}

let STORAGE_BUCKET_READY_PROMISE_: Promise<void> | null = null;
async function ensureStorageBucket() {
  if (STORAGE_BUCKET_READY_PROMISE_) return await STORAGE_BUCKET_READY_PROMISE_;

  STORAGE_BUCKET_READY_PROMISE_ = (async () => {
    const { data, error } = await supabase.storage.getBucket(STORAGE_BUCKET);
    if (!error && data) return;

    const created = await supabase.storage.createBucket(
      STORAGE_BUCKET,
      {
        public: true,
        allowedMimeTypes: ["image/jpeg","image/png","image/webp"],
        fileSizeLimit: "5MB",
      },
    );

    if (
      created.error &&
      !String(created.error.message || "").toLowerCase().includes("already")
    ) {
      STORAGE_BUCKET_READY_PROMISE_ = null;
      throw created.error;
    }
  })();

  return await STORAGE_BUCKET_READY_PROMISE_;
}

function base64ToBytes(
  base64: string,
): Uint8Array {
  const cleaned =
    String(base64 || "")
      .replace(
        /^data:[^;]+;base64,/,
        "",
      );

  const binary =
    atob(cleaned);

  const bytes =
    new Uint8Array(
      binary.length,
    );

  for (
    let i = 0;
    i < binary.length;
    i++
  ) {
    bytes[i] =
      binary.charCodeAt(i);
  }

  return bytes;
}

async function uploadImageBase64(
  base64: unknown,
  mime: unknown,
  folder: string,
  objectId: string,
): Promise<string> {
  const raw =
    String(base64 || "");

  if (!raw) return "";

  await ensureStorageBucket();

  const contentType =
    String(
      mime || "image/jpeg",
    ).toLowerCase();

  const ext =
    contentType.includes("png")
      ? "png"
      : contentType.includes("webp")
        ? "webp"
        : "jpg";

  const path =
    `${folder}/${objectId}-${Date.now()}.${ext}`;

  const bytes =
    base64ToBytes(raw);

  const { error } =
    await supabase.storage
      .from(STORAGE_BUCKET)
      .upload(
        path,
        bytes,
        {
          contentType,
          upsert: false,
          cacheControl:
            "31536000",
        },
      );

  if (error) throw error;

  return supabase.storage
    .from(STORAGE_BUCKET)
    .getPublicUrl(path)
    .data.publicUrl;
}

async function getPollaRow(
  id: string,
) {
  const { data, error } =
    await supabase
      .from("pollas")
      .select("*")
      .eq("id", id)
      .maybeSingle();

  if (error) throw error;

  return data;
}

async function assertPollaEditable(
  id: string,
  allowFinalized = false,
) {
  const polla =
    await getPollaRow(id);

  if (!polla) {
    return {
      ok: false,
      error:
        "Polla no encontrada.",
    };
  }

  if (polla.compacted_at) {
    return {
      ok: false,
      error:
        "Esta Polla ya está compactada y protegida. Su histórico es inmutable.",
    };
  }

  if (polla.is_archived) {
    return {
      ok: false,
      error:
        "Esta Polla está archivada. Desarchívala primero para poder editarla.",
    };
  }

  if (
    !allowFinalized &&
    polla.status === "finalizada"
  ) {
    return {
      ok: false,
      error:
        "Esta Polla está finalizada. Reábrela cambiando su estado antes de modificar participantes, partidos o resultados.",
    };
  }

  return {
    ok: true,
    polla,
  };
}

// Misma fórmula exacta del Code.gs.
function calcPointsBase(
  predHome: number,
  predAway: number,
  actualHome: number,
  actualAway: number,
) {
  if (
    predHome === actualHome &&
    predAway === actualAway
  ) {
    return {
      points: 5,
      isExact: true,
    };
  }

  let points = 0;

  if (predHome === actualHome) {
    points += 1;
  }

  if (predAway === actualAway) {
    points += 1;
  }

  const predOutcome =
    predHome > predAway
      ? "L"
      : predHome < predAway
        ? "V"
        : "E";

  const actualOutcome =
    actualHome > actualAway
      ? "L"
      : actualHome < actualAway
        ? "V"
        : "E";

  if (
    predOutcome === actualOutcome
  ) {
    points += 2;
  }

  const actualDiff =
    actualHome - actualAway;

  const predDiff =
    predHome - predAway;

  // Igual que el Code.gs: un empate NO recibe +2 por diferencia 0.
  if (
    actualDiff !== 0 &&
    predDiff === actualDiff
  ) {
    points += 2;
  }

  return {
    points,
    isExact: false,
  };
}

async function recalculateSubmittedMatchPoints(
  matchId: string,
  _actualHome: number,
  _actualAway: number,
  _isStarMatch: boolean,
) {
  const { data, error } = await supabase.rpc(
    "recalculate_match_points_tico",
    { p_match_id: matchId },
  );
  if (error) throw error;
  if (data && data.ok === false) {
    throw new Error(String(data.error || "No se pudieron recalcular los puntos."));
  }
}

async function registrarGanadores(
  names: string[],
) {
  for (const rawName of names || []) {
    const name =
      cleanName(rawName);

    if (!name) continue;

    const { data: all = [], error } =
      await supabase
        .from("ganadores")
        .select("id, name, wins");

    if (error) throw error;

    const found =
      all.find(
        (r: any) =>
          normalizeName(r.name) ===
          normalizeName(name),
      );

    if (found) {
      const u =
        await supabase
          .from("ganadores")
          .update({
            wins:
              Number(
                found.wins || 0,
              ) + 1,
          })
          .eq(
            "id",
            found.id,
          );

      if (u.error) throw u.error;
    } else {
      const i =
        await supabase
          .from("ganadores")
          .insert({
            name,
            wins: 1,
          });

      if (i.error) throw i.error;
    }
  }
}

async function descontarGanadores(
  names: string[],
) {
  const { data: all = [], error } =
    await supabase
      .from("ganadores")
      .select("id, name, wins");

  if (error) throw error;

  for (const rawName of names || []) {
    const found =
      all.find(
        (r: any) =>
          normalizeName(r.name) ===
          normalizeName(rawName),
      );

    if (!found) continue;

    const next =
      Number(
        found.wins || 0,
      ) - 1;

    if (next <= 0) {
      const d =
        await supabase
          .from("ganadores")
          .delete()
          .eq(
            "id",
            found.id,
          );

      if (d.error) throw d.error;
    } else {
      const u =
        await supabase
          .from("ganadores")
          .update({
            wins: next,
          })
          .eq(
            "id",
            found.id,
          );

      if (u.error) throw u.error;
    }
  }
}

async function agregarPuntosBase(
  standings: any[],
) {
  for (const s of standings || []) {
    const pts = Number(s.totalPoints ?? s.total_points ?? 0) || 0;
    const matches = Number(s.matchesScored ?? s.matches_scored ?? 0) || 0;
    const exacts = Number(s.exactCount ?? s.exact_count ?? 0) || 0;
    const mvps = Number(s.mvpCount ?? s.mvp_count ?? 0) || 0;

    const name = cleanName(s.name);
    const key = normalizeName(name);
    if (!name || !key) continue;

    const jugador = await findJugador(name);
    const { data: current, error: readError } = await supabase
      .from("tabla_acumulada_base")
      .select("jugador_id, name, name_key, base_points, base_matches_scored, base_exact_count, base_mvp_count")
      .eq("name_key", key)
      .maybeSingle();
    if (readError) throw readError;

    const payload = {
      name: jugador?.name || current?.name || name,
      name_key: key,
      jugador_id: jugador?.id || current?.jugador_id || null,
      base_points: Number(current?.base_points || 0) + pts,
      base_matches_scored: Number(current?.base_matches_scored || 0) + matches,
      base_exact_count: Number(current?.base_exact_count || 0) + exacts,
      base_mvp_count: Number(current?.base_mvp_count || 0) + mvps,
    };

    const { error } = await supabase
      .from("tabla_acumulada_base")
      .upsert(payload, { onConflict: "name_key" });
    if (error) throw error;
  }
}

async function computePollaStandingsForAdmin(
  pollaId: string,
) {
  const [
    partsR,
    matchesR,
  ] =
    await Promise.all([
      supabase
        .from("participantes")
        .select(
          "jugador_id, jugadores(name)",
        )
        .eq(
          "polla_id",
          pollaId,
        ),

      supabase
        .from("partidos")
        .select(
          "id, result_submitted, actual_home, actual_away, is_canceled",
        )
        .eq(
          "polla_id",
          pollaId,
        ),
    ]);

  if (partsR.error) {
    throw partsR.error;
  }

  if (matchesR.error) {
    throw matchesR.error;
  }

  const totals:
    Record<string, any> = {};

  for (
    const p of
      partsR.data || []
  ) {
    totals[p.jugador_id] = {
      name:
        relatedName(
          p.jugadores,
        ),
      totalPoints: 0,
      matchesScored: 0,
      exactCount: 0,
      mvpCount: 0,
    };
  }

  const active =
    (matchesR.data || [])
      .filter(
        (m) =>
          !m.is_canceled,
      );

  const mids =
    active.map(
      (m) => m.id,
    );

  let prs: any[] = [];

  if (mids.length) {
    const r =
      await supabase
        .from("pronosticos")
        .select(
          "partido_id, jugador_id, home, away, points",
        )
        .in(
          "partido_id",
          mids,
        );

    if (r.error) {
      throw r.error;
    }

    prs = r.data || [];
  }

  const info:
    Record<string, any> = {};

  for (
    const m of active
  ) {
    info[m.id] = m;
  }

  const max:
    Record<string, number> = {};

  for (const pr of prs) {
    if (
      pr.points === null ||
      pr.points === undefined
    ) {
      continue;
    }

    if (
      !info[
        pr.partido_id
      ]?.result_submitted
    ) {
      continue;
    }

    const pts =
      Number(pr.points);

    max[pr.partido_id] =
      Math.max(
        max[pr.partido_id] ??
          -Infinity,
        pts,
      );
  }

  for (const pr of prs) {
    const t =
      totals[
        pr.jugador_id
      ];

    if (!t) continue;

    if (
      pr.points === null ||
      pr.points === undefined
    ) {
      continue;
    }

    const m =
      info[pr.partido_id];

    t.totalPoints +=
      Number(pr.points);

    t.matchesScored++;

    if (
      m?.result_submitted &&
      Number(pr.home) ===
        Number(
          m.actual_home,
        ) &&
      Number(pr.away) ===
        Number(
          m.actual_away,
        )
    ) {
      t.exactCount++;
    }

    if (
      (
        max[
          pr.partido_id
        ] ?? 0
      ) > 0 &&
      Number(pr.points) ===
        max[
          pr.partido_id
        ]
    ) {
      t.mvpCount++;
    }
  }

  return assignRanks(
    Object.values(totals)
      .sort(
        (
          a: any,
          b: any,
        ) =>
          b.totalPoints -
          a.totalPoints,
      ) as any[],
  );
}

async function deletePollaData(
  pollaId: string,
) {
  const {
    data: matches = [],
    error: readError,
  } =
    await supabase
      .from("partidos")
      .select("id")
      .eq(
        "polla_id",
        pollaId,
      );

  if (readError) {
    throw readError;
  }

  const matchIds =
    matches.map(
      (m) => m.id,
    );

  if (matchIds.length) {
    const d =
      await supabase
        .from("pronosticos")
        .delete()
        .in(
          "partido_id",
          matchIds,
        );

    if (d.error) {
      throw d.error;
    }
  }

  let d =
    await supabase
      .from("participantes")
      .delete()
      .eq(
        "polla_id",
        pollaId,
      );

  if (d.error) throw d.error;

  d =
    await supabase
      .from("partidos")
      .delete()
      .eq(
        "polla_id",
        pollaId,
      );

  if (d.error) throw d.error;

  d =
    await supabase
      .from("pollas")
      .delete()
      .eq("id", pollaId);

  if (d.error) throw d.error;
}


function requestIdFrom_(req: Request): string {
  const incoming = String(req.headers.get("x-request-id") || "").trim();
  if (/^[A-Za-z0-9_-]{6,64}$/.test(incoming)) return incoming;
  return `TICO-${crypto.randomUUID().replaceAll("-", "").slice(0, 10).toUpperCase()}`;
}

// ============================================================================
// SERVIDOR
// ============================================================================

Deno.serve(async (req) => {
  const requestStartedAt = performance.now();
  const requestId = requestIdFrom_(req);
  let requestAction = "";
  if (req.method === "OPTIONS") {
    return new Response("ok", {
      headers: corsHeaders,
    });
  }

  try {
    let params: Record<string, any>;

    if (req.method === "GET") {
      params = Object.fromEntries(
        new URL(req.url).searchParams.entries(),
      );
    } else if (req.method === "POST") {
      const contentType =
        req.headers.get("content-type") || "";

      if (contentType.includes("application/json")) {
        params = await req.json();
      } else {
        const form = await req.formData();
        params = Object.fromEntries(form.entries());
      }
    } else {
      return jsonOut(
        {
          ok: false,
          error: "METHOD_NOT_ALLOWED",
        },
        405,
      );
    }

    const action =
      String(params.action || "").trim();
    requestAction = action;

    let originHashMemo_: string | null = null;
    const getOriginHash_ = async () => {
      if(originHashMemo_) return originHashMemo_;
      originHashMemo_ = await requestOriginHash(req);
      return originHashMemo_;
    };

    if (!action) {
      return jsonOut(
        {
          ok: false,
          error: "ACTION_REQUIRED",
        },
        400,
      );
    }

    // ========================================================================
    // GATE ADMIN — cada request administrativo valida nuevamente la clave.
    // 5 intentos por origen; el bloqueo temporal afecta solo a ese origen.
    // ========================================================================

    const ADMIN_ACTIONS =
      new Set([
        "addPolla",
        "editPolla",
        "deletePolla",
        "addMatch",
        "editMatch",
        "deleteMatch",
        "cancelAndReplaceMatch",
        "addParticipants",
        "setParticipantPaid",
        "deleteParticipantFull",
        "previewParticipantDeletion",
        "renameParticipant",
        "splitParticipantIdentity",
        "resetPin",
        "regenerateActivationCode",
        "getParticipantsAdmin",
        "getActivationCodesAdmin",
        "getHistoricalPlayersAdmin",
        "previewHistoricalPlayerDeletion",
        "deleteHistoricalPlayer",
        "submitResult",
        "getAdminLog",
        "getGlobalBackup",
        "getPollaBackup",
        "createSecurePollaBackup",
        "getSecurePollaBackupStatus",
        "getCompactionPrecheck",
        "getCompactionSealStatus",
        "prepareCompactionSeal",
        "compactPollaV2",
        "getStorageCleanupStatus",
        "cleanupCompactedPollaStorage",
        "getFinalArchiveAuditStatus",
        "runFinalArchiveAudit",
        "closeSeason",
        "clearSeasonData",
        "archivePolla",
        "desarchivarPolla",
        "editArchivedPremios",
        "getAdminMatchPredictions",
        "getAdminAllPredictions",
        "getAdminPredictionSummary",
        "setAppConfig",
        "getSystemHealth",
      ]);

    if (
      action === "authAdmin"
    ) {
      const check =
        await verifyAdminPin(
          params.pin,
          await getOriginHash_(),
        );

      if (check.ok) {
        const session = await createAdminSession_(await getOriginHash_());
        return jsonOut({
          ok: true,
          adminSession: session.token,
          expiresAt: session.expiresAt,
        });
      }

      if (
        check.error ===
        "LOCKED"
      ) {
        return jsonOut({
          ok: false,
          error: "LOCKED",
          minutesLeft:
            check.minutesLeft,
        });
      }

      return jsonOut({
        ok: false,
        error: "PIN incorrecto",
        attemptsLeft:
          check.attemptsLeft,
      });
    }

    if (action === "authAdminConfirm") {
      const sessionToken = req.headers.get("x-admin-session");
      const sessionCheck = await verifyAdminSession_(sessionToken, '');
      if (!sessionCheck.ok) {
        return jsonOut({ok:false, error:sessionCheck.error}, 401);
      }
      const purpose = String(params.confirmAction || "").trim();
      const allowedPurposes = new Set(["deletePolla","deleteMatch","deleteParticipantFull","deleteHistoricalPlayer","closeSeason","clearSeasonData","reopenPolla","compactPollaV2","cleanupCompactedPollaStorage"]);
      if (!allowedPurposes.has(purpose)) return jsonOut({ok:false, error:"CONFIRM_ACTION_INVALID"}, 400);
      const pinCheck = await verifyAdminPin(params.pin, await getOriginHash_());
      if (!pinCheck.ok) {
        if(pinCheck.error === "LOCKED") return jsonOut({ok:false,error:"LOCKED",minutesLeft:pinCheck.minutesLeft});
        return jsonOut({ok:false,error:"WRONG_PIN",attemptsLeft:pinCheck.attemptsLeft});
      }
      const confirm = await createAdminConfirm_(purpose, await getOriginHash_());
      return jsonOut({ok:true, confirmToken:confirm.token, expiresAt:confirm.expiresAt});
    }

    if (
      ADMIN_ACTIONS.has(
        action,
      )
    ) {
      const sessionToken = req.headers.get("x-admin-session");
      let check: any = sessionToken
        ? await verifyAdminSession_(sessionToken, '')
        : await verifyAdminPin(params.pin, await getOriginHash_());

      if (!check.ok) {
        if (check.error === "ADMIN_SESSION_EXPIRED" || check.error === "ADMIN_SESSION_INVALID") {
          return jsonOut({ ok:false, error:check.error }, 401);
        }
        if (check.error === "LOCKED") {
          return jsonOut({
            ok: false,
            error: "LOCKED",
            minutesLeft: check.minutesLeft,
          });
        }

        return jsonOut({
          ok: false,
          error:
            "No autorizado. PIN de administrador inválido o ausente.",
        });
      }

      let sensitivePurpose: string | null = null;
      if (action === "deletePolla") sensitivePurpose = "deletePolla";
      else if (action === "deleteMatch") sensitivePurpose = "deleteMatch";
      else if (action === "deleteParticipantFull") sensitivePurpose = "deleteParticipantFull";
      else if (action === "deleteHistoricalPlayer") sensitivePurpose = "deleteHistoricalPlayer";
      else if (action === "closeSeason") sensitivePurpose = "closeSeason";
      else if (action === "clearSeasonData") sensitivePurpose = "clearSeasonData";
      else if (action === "compactPollaV2") sensitivePurpose = "compactPollaV2";
      else if (action === "cleanupCompactedPollaStorage") sensitivePurpose = "cleanupCompactedPollaStorage";
      else if (action === "editPolla" && params.status !== undefined) {
        const targetStatus=String(params.status || "").trim().toLowerCase();
        const targetId = String(params.id || "");
        if (targetId && targetStatus !== "finalizada") {
          const { data: currentPollaForConfirm, error: confirmReadError } = await supabase
            .from("pollas")
            .select("status")
            .eq("id", targetId)
            .maybeSingle();
          if (confirmReadError) throw confirmReadError;
          if (currentPollaForConfirm?.status === "finalizada") sensitivePurpose = "reopenPolla";
        }
      }
      if (sensitivePurpose) {
        const strongCheck = await verifyAdminConfirm_(
          req.headers.get("x-admin-confirm"),
          sensitivePurpose,
          await getOriginHash_(),
        );
        if (!strongCheck.ok) {
          return jsonOut({
            ok: false,
            error: strongCheck.error,
            confirmAction: sensitivePurpose,
          }, 403);
        }
      }

      // Igual que Apps Script: getAdminLog no se registra a sí mismo.
      if (
        action !== "getAdminLog" &&
        action !== "getParticipantsAdmin" &&
        action !== "getAdminMatchPredictions" &&
        action !== "getAdminAllPredictions" &&
        action !== "getAdminPredictionSummary" &&
        action !== "getSystemHealth"
      ) {
        await logAdminAction(
          action,
          params.adminName,
          describeAdminAction(
            action,
            params,
          ),
        );
      }
    }

    // ========================================================================
    // LECTURAS PÚBLICAS
    // ========================================================================

    // ------------------------------------------------------------------------
    // getPollas / getArchivedPollas / getPollaSummary
    // C2: la portada ya no necesita descargar el histórico completo. Las Pollas
    // finalizadas se consultan paginadas solo cuando el usuario abre "Anteriores".
    // El modo legacy/admin conserva el array completo por compatibilidad.
    // ------------------------------------------------------------------------
    const mapPollaSummary_ = (p: any) => ({
      id: p.id,
      number: p.number,
      status: p.status,
      createdAt: p.created_at,
      startDate: p.start_date,
      premio1: p.premio1 ?? "",
      premio2: p.premio2 ?? "",
      premio3: p.premio3 ?? "",
      imageUrl: p.image_url ?? "",
      isFreePolla: !!p.is_free_polla,
      showWinnersLive: !!p.show_winners_live,
      isArchived: !!p.is_archived,
      compactedAt: p.compacted_at ?? null,
      totalMatches: p.total_matches ?? 0,
      matchCount: Number(p.match_count || 0),
      participantCount: Number(p.participant_count || 0),
    });

    if (action === "getLandingBootstrap") {
      const [cfg, rpc] = await Promise.all([
        getAppConfig_(),
        supabase.rpc("get_pollas_summary_page_tico", {
          p_mode: "landing",
          p_limit: 100,
          p_offset: 0,
        }),
      ]);
      if (rpc.error || !rpc.data || !Array.isArray(rpc.data.items)) {
        const full = await supabase.rpc("get_pollas_summary_tico");
        if (full.error || !Array.isArray(full.data)) {
          throw rpc.error || full.error || new Error("LANDING_BOOTSTRAP_INVALID_RESPONSE");
        }
        return jsonOut({
          ok:true,
          config:cfg,
          pollas:full.data
            .filter((x:any)=>x.status==="actual"||x.status==="proximamente")
            .map(mapPollaSummary_),
        });
      }
      return jsonOut({
        ok:true,
        config:cfg,
        pollas:rpc.data.items.map(mapPollaSummary_),
      });
    }

    if (action === "getSystemHealth") {
      const dbStarted = performance.now();
      const { data: healthConfig, error: healthError } = await supabase
        .from("app_config")
        .select("id,schema_version,updated_at")
        .eq("id", 1)
        .maybeSingle();
      const dbLatencyMs = Math.max(0, Math.round(performance.now() - dbStarted));
      if (healthError) {
        return jsonOut({
          ok: true,
          backendVersion: BACKEND_VERSION,
          dbSchemaVersion: "Desconocida",
          dbOk: false,
          dbLatencyMs,
          dbError: String(healthError.message || "DB_ERROR").slice(0, 160),
          serverTime: new Date().toISOString(),
          edgeRegion: String(Deno.env.get("SB_REGION") || "unknown"),
          serverProcessingMs: Math.max(0, Math.round(performance.now() - requestStartedAt)),
        });
      }
      return jsonOut({
        ok: true,
        backendVersion: BACKEND_VERSION,
        dbSchemaVersion: String(healthConfig?.schema_version || "Sin versión"),
        dbOk: true,
        dbLatencyMs,
        configUpdatedAt: healthConfig?.updated_at || null,
        serverTime: new Date().toISOString(),
        edgeRegion: String(Deno.env.get("SB_REGION") || "unknown"),
        serverProcessingMs: Math.max(0, Math.round(performance.now() - requestStartedAt)),
      });
    }

    if (action === "getAppConfig") {
      const cfg = await getAppConfig_();
      return jsonOut({ ok: true, ...cfg, backendVersion: BACKEND_VERSION });
    }

    if (action === "setAppConfig") {
      const maintenanceEnabled = params.maintenanceEnabled === true || String(params.maintenanceEnabled) === "true";
      const predictionsEnabled = params.predictionsEnabled === true || String(params.predictionsEnabled) === "true";
      const registrationsEnabled = params.registrationsEnabled === true || String(params.registrationsEnabled) === "true";
      const maintenanceMessage = String(params.maintenanceMessage || "").trim().slice(0, 180);
      const updatedBy = cleanName(params.adminName || "Admin").slice(0, 80) || "Admin";
      const { error } = await supabase
        .from("app_config")
        .upsert({
          id: 1,
          maintenance_enabled: maintenanceEnabled,
          maintenance_message: maintenanceMessage,
          predictions_enabled: predictionsEnabled,
          registrations_enabled: registrationsEnabled,
          updated_at: new Date().toISOString(),
          updated_by: updatedBy,
        }, { onConflict: "id" });
      if (error) throw error;
      const previousCfg = await getAppConfig_();
      const cfg: AppConfig = {
        maintenanceEnabled, maintenanceMessage, predictionsEnabled, registrationsEnabled,
        tutorialUrl: previousCfg.tutorialUrl,
        updateCheckSeconds: previousCfg.updateCheckSeconds,
      };
      appConfigCache_ = { data: cfg, at: Date.now() };
      return jsonOut({ ok: true, config: cfg, backendVersion: BACKEND_VERSION });
    }

    if (action === "getPollas") {
      const scope = String(params.scope || "legacy").trim().toLowerCase();

      // Portada: solo activas/próximas. Evita arrastrar todo el histórico en
      // cada apertura de la app.
      if (scope === "landing") {
        const rpc = await supabase.rpc("get_pollas_summary_page_tico", {
          p_mode: "landing",
          p_limit: 100,
          p_offset: 0,
        });
        if (!rpc.error && rpc.data && Array.isArray(rpc.data.items)) {
          return jsonOut(rpc.data.items.map(mapPollaSummary_));
        }
        console.warn("C2 landing RPC no disponible; usando resumen completo como fallback", rpc.error?.message || "");
      }

      // Admin/legacy: conserva la forma histórica (array completo).
      const rpc = await supabase.rpc("get_pollas_summary_tico");
      if (!rpc.error && Array.isArray(rpc.data)) {
        return jsonOut(rpc.data.map(mapPollaSummary_));
      }

      console.warn("C2 getPollas RPC no disponible; usando fallback compatible", rpc.error?.message || "");

      const [pollasRows, partidosRows, participantesRows] = await Promise.all([
        fetchAllPages<any>((from,to)=>supabase.from("pollas").select("id, number, status, created_at, start_date, premio1, premio2, premio3, image_url, is_free_polla, show_winners_live, is_archived, compacted_at, total_matches").order("created_at", { ascending:false }).range(from,to)),
        fetchAllPages<any>((from,to)=>supabase.from("partidos").select("polla_id, is_canceled").range(from,to)),
        fetchAllPages<any>((from,to)=>supabase.from("participantes").select("polla_id").range(from,to)),
      ]);

      const matchCounts: Record<string, number> = {};
      const participantCounts: Record<string, number> = {};
      for (const m of partidosRows) {
        if (m.is_canceled) continue;
        matchCounts[m.polla_id] = (matchCounts[m.polla_id] || 0) + 1;
      }
      for (const p of participantesRows) {
        participantCounts[p.polla_id] = (participantCounts[p.polla_id] || 0) + 1;
      }

      return jsonOut(pollasRows.map((p) => mapPollaSummary_({
        ...p,
        match_count: matchCounts[p.id] || 0,
        participant_count: participantCounts[p.id] || 0,
      })));
    }

    if (action === "getArchivedPollas") {
      const limit = Math.max(1, Math.min(20, Number(params.limit || 5)));
      const offset = Math.max(0, Number(params.offset || 0));
      const rpc = await supabase.rpc("get_pollas_summary_page_tico", {
        p_mode: "archived",
        p_limit: limit,
        p_offset: offset,
      });
      if (rpc.error || !rpc.data || !Array.isArray(rpc.data.items)) {
        throw rpc.error || new Error("ARCHIVED_POLLAS_INVALID_RESPONSE");
      }
      return jsonOut({
        items: rpc.data.items.map(mapPollaSummary_),
        total: Number(rpc.data.total || 0),
        hasMore: !!rpc.data.has_more,
        nextOffset: offset + rpc.data.items.length,
      });
    }

    if (action === "getPollaSummary") {
      const pollaId = String(params.pollaId || "").trim();
      if (!pollaId) return jsonOut({ ok:false, error:"POLLA_ID_REQUIRED" }, 400);

      const rpc = await supabase.rpc("get_polla_summary_by_id_tico", { p_polla_id: pollaId });
      if (rpc.error) throw rpc.error;
      if (!rpc.data) return jsonOut({ ok:false, error:"POLLA_NOT_FOUND" }, 404);
      // H4: compacted_at ya viene en la RPC; evitamos una segunda consulta DB.
      return jsonOut(mapPollaSummary_(rpc.data));
    }

    // ------------------------------------------------------------------------
    // getMatches
    // ------------------------------------------------------------------------
    if (action === "getMatches") {
      const pollaId =
        String(params.pollaId || "").trim();

      const data = await fetchAllPages<any>((from,to)=>
        supabase
          .from("partidos")
          .select("id, polla_id, match_number, home, away, close_at, image_url, result_submitted, actual_home, actual_away, created_at, is_star_match, is_canceled, cancel_reason")
          .eq("polla_id", pollaId)
          .order("match_number", { ascending: true })
          .range(from,to)
      );

      let hist:any = null;
      let sourceMatches = data;
      if (!sourceMatches.length) {
        hist = await getCompactedHistory_(pollaId);
        sourceMatches = Array.isArray(hist?.snapshot_json?.matches) ? hist.snapshot_json.matches : [];
      }
      const historicalStorageCleaned = !data.length && !!hist?.storage_cleaned_at;
      const matches = sourceMatches.map((m:any) => ({
        id: m.id,
        pollaId: m.polla_id,
        matchNumber: m.match_number,
        home: m.home,
        away: m.away,
        closeAt: m.close_at,
        imageUrl: historicalStorageCleaned ? "" : (m.image_url ?? ""),
        resultSubmitted: !!m.result_submitted,
        actualHome: m.actual_home,
        actualAway: m.actual_away,
        createdAt: m.created_at,
        isStarMatch: !!m.is_star_match,
        isCanceled: !!m.is_canceled,
        cancelReason: m.cancel_reason ?? "",
      }));

      return jsonOut(matches);
    }

    // ------------------------------------------------------------------------
    // getParticipants (PÚBLICO: solo datos necesarios para la experiencia jugador)
    // ------------------------------------------------------------------------
    if (action === "getParticipants") {
      const pollaId = String(params.pollaId || "").trim();
      const data = await fetchAllPages<any>((from,to)=>supabase
        .from("participantes")
        .select("jugadores(name)")
        .eq("polla_id", pollaId)
        .range(from,to));
      if (data.length) return jsonOut(data.map((row:any) => ({ name: relatedName(row.jugadores) })));
      const hist = await getCompactedHistory_(pollaId);
      const participants = Array.isArray(hist?.snapshot_json?.participants) ? hist.snapshot_json.participants : [];
      const erasures=participants.length ? await getHistoricalErasureMaps_() : {byId:new Map(),byKey:new Map()};
      return jsonOut(participants.map((row:any)=>({name:historicalVisibleName_(row,erasures)})).filter((x:any)=>x.name));
    }

    // ------------------------------------------------------------------------
    // getParticipantsAdmin
    // ------------------------------------------------------------------------
    if (action === "getParticipantsAdmin") {
      const pollaId = String(params.pollaId || "").trim();
      const [participantsRes, refsRes] = await Promise.all([
        supabase
          .from("participantes")
          .select(`id, jugador_id, paid, referral_code, referred_by_code, created_at,
                   jugadores(name, whatsapp, pin_hash, activation_code_hash, activation_purpose)`)
          .eq("polla_id", pollaId),
        supabase
          .from("referidos")
          .select("invitador_jugador_id")
          .eq("polla_id", pollaId),
      ]);
      if (participantsRes.error) throw participantsRes.error;
      if (refsRes.error) throw refsRes.error;
      const data = participantsRes.data || [];
      const refs = refsRes.data || [];
      const counts: Record<string,number> = {};
      for (const r of refs) counts[r.invitador_jugador_id] = (counts[r.invitador_jugador_id] || 0) + 1;

      return jsonOut(data.map((row:any) => {
        const j = Array.isArray(row.jugadores) ? row.jugadores[0] : row.jugadores;
        return {
          name: j?.name || "",
          whatsapp: j?.whatsapp || "",
          paid: !!row.paid,
          referralCode: row.referral_code || "",
          referredByCode: row.referred_by_code || "",
          referredCount: counts[row.jugador_id] || 0,
          activationStatus: j?.pin_hash ? "ACTIVE" : "PENDING_ACTIVATION",
          activationPurpose: j?.activation_purpose || null,
        };
      }));
    }

    // ------------------------------------------------------------------------
    // getActivationCodesAdmin: muestra al Admin los códigos PENDIENTES actuales
    // de esta Polla. Se guardan cifrados en reposo y siguen siendo de un solo uso.
    // ------------------------------------------------------------------------
    if (action === "getActivationCodesAdmin") {
      const pollaId = String(params.pollaId || "").trim();
      if(!pollaId) return jsonOut({ok:false,error:"Falta pollaId."},400);
      const rows = await fetchAllPages<any>((from,to)=>supabase
        .from("participantes")
        .select(`jugador_id, jugadores(name,pin_hash,activation_code_hash,activation_code_enc,activation_purpose,activation_created_at)`)
        .eq("polla_id", pollaId)
        .range(from,to));
      const pending=(await Promise.all(rows.map(async(row:any)=>{
        const j=Array.isArray(row.jugadores)?row.jugadores[0]:row.jugadores;
        if(!j || j.pin_hash) return null;
        const code = j.activation_code_enc ? await decryptActivationCode_(j.activation_code_enc) : "";
        const purpose=String(j.activation_purpose||"FIRST");
        return {
          name:String(j.name||""),
          code,
          purpose,
          purposeLabel: purpose==='RESET' ? 'Restablecimiento de PIN' : (purpose==='SPLIT' ? 'Nueva identidad separada' : 'Primera activación'),
          createdAt:j.activation_created_at||null,
        };
      }))).filter(Boolean) as any[];
      pending.sort((a,b)=>a.name.localeCompare(b.name,'es',{sensitivity:'base'}));
      return jsonOut({ok:true,items:pending});
    }

    // ------------------------------------------------------------------------
    // getAdminMatchPredictions: Admin autenticado puede ver los marcadores
    // individuales aun antes del cierre. La validación del PIN ya ocurrió en
    // ADMIN_ACTIONS, por lo que esta información nunca sale por la ruta pública.
    // ------------------------------------------------------------------------
    if (action === "getAdminMatchPredictions") {
      const matchId = String(params.matchId || "").trim();
      if (!matchId) return jsonOut({ ok:false, error:"Falta matchId" }, 400);
      const data = await fetchAllPages<any>((from,to)=>
        supabase.from("pronosticos")
          .select(`home, away, edit_count, points, updated_at, jugadores(name)`)
          .eq("partido_id", matchId)
          .range(from,to)
      );
      return jsonOut({ok:true,predictions:data.map((pr:any)=>({
        name:relatedName(pr.jugadores), home:pr.home, away:pr.away,
        editCount:pr.edit_count, points:pr.points, ts:pr.updated_at,
      }))});
    }

    // ------------------------------------------------------------------------
    // getAdminAllPredictions: fuente única para los contadores del panel Admin.
    // Evita que el resumen diga 4/4 mientras el modal vea 0/4.
    // ------------------------------------------------------------------------
    if (action === "getAdminAllPredictions") {
      const pollaId = String(params.pollaId || "").trim();
      if (!pollaId) return jsonOut({ ok:false, error:"Falta pollaId" }, 400);
      const {data:ms=[],error:me}=await supabase.from("partidos").select("id").eq("polla_id",pollaId);
      if(me) throw me;
      const ids=ms.map((m:any)=>m.id);
      if(!ids.length) return jsonOut({ok:true,predictions:{}});
      const data=await fetchAllPages<any>((from,to)=>
        supabase.from("pronosticos")
          .select(`partido_id, home, away, edit_count, points, updated_at, jugadores(name)`)
          .in("partido_id",ids)
          .range(from,to)
      );
      const byMatch:Record<string,any[]>={};
      for(const pr of data){
        (byMatch[pr.partido_id] ||= []).push({
          name:relatedName(pr.jugadores), home:pr.home, away:pr.away,
          editCount:pr.edit_count, points:pr.points, ts:pr.updated_at,
        });
      }
      return jsonOut({ok:true,predictions:byMatch});
    }

    // ------------------------------------------------------------------------
    // getAdminPredictionSummary: lectura liviana para el panel Admin.
    // Devuelve únicamente el conteo por partido. Los nombres/marcadores se
    // solicitan por partido cuando el Admin toca 📋.
    // ------------------------------------------------------------------------
    if (action === "getAdminPredictionSummary") {
      const pollaId = String(params.pollaId || "").trim();
      if (!pollaId) return jsonOut({ ok:false, error:"Falta pollaId" }, 400);

      try{
        const {data:rpcCounts,error:rpcErr}=await supabase.rpc(
          "get_admin_prediction_counts_tico",
          {p_polla_id:pollaId},
        );
        if(!rpcErr && rpcCounts && typeof rpcCounts==="object" && !Array.isArray(rpcCounts)){
          return jsonOut({ok:true,counts:rpcCounts});
        }
      }catch(_){}

      const {data:ms=[],error:me}=await supabase.from("partidos").select("id").eq("polla_id",pollaId);
      if(me) throw me;
      const ids=ms.map((m:any)=>m.id);
      const counts:Record<string,number>={};
      for(const id of ids) counts[id]=0;
      if(!ids.length) return jsonOut({ok:true,counts});

      // V19: COUNT exacto en servidor. Evita descargar una fila por cada
      // pronóstico solo para contarla (gran diferencia con cientos/miles de jugadores).
      const counted = await Promise.all(ids.map(async (id:string) => {
        const { count, error } = await supabase
          .from("pronosticos")
          .select("partido_id", { count:"exact", head:true })
          .eq("partido_id", id);
        if(error) throw error;
        return [id, Number(count || 0)] as const;
      }));
      for(const [id,count] of counted) counts[id]=count;
      return jsonOut({ok:true,counts});
    }

    // ------------------------------------------------------------------------
    // ------------------------------------------------------------------------
    // getPredictions: pronósticos individuales SOLO al cierre/resultado.
    // ------------------------------------------------------------------------
    if (action === "getPredictions") {
      const matchId = String(params.matchId || "").trim();
      const { data: match, error: me } = await supabase
        .from("partidos").select("id, close_at, result_submitted").eq("id", matchId).maybeSingle();
      if (me) throw me;
      if (!match) {
        const pollaId=String(params.pollaId || '').trim();
        if(!pollaId) return jsonOut([]);
        const hist=await getCompactedHistory_(pollaId);
        const hMatches=Array.isArray(hist?.snapshot_json?.matches) ? hist.snapshot_json.matches : [];
        const exists=hMatches.some((m:any)=>String(m?.id||'')===matchId);
        if(!exists) return jsonOut([]);
        const hPreds=Array.isArray(hist?.snapshot_json?.predictions) ? hist.snapshot_json.predictions : [];
        const rows=hPreds.filter((pr:any)=>String(pr?.partido_id ?? pr?.matchId ?? '')===matchId);
        const erasures=rows.length ? await getHistoricalErasureMaps_() : {byId:new Map(),byKey:new Map()};
        return jsonOut(rows.map((pr:any)=>{
          const out=snapshotPredictionPublic_(pr);
          out.name=historicalVisibleName_(pr,erasures);
          return out;
        }));
      }
      const isClosed = !!match.result_submitted || (match.close_at && Date.now() >= new Date(match.close_at).getTime());
      if (!isClosed) return jsonOut([]);
      const data = await fetchAllPages<any>((from, to) =>
        supabase.from("pronosticos")
          .select(`home, away, edit_count, points, updated_at, jugadores(name)`)
          .eq("partido_id", matchId)
          .range(from, to)
      );
      return jsonOut(data.map((pr:any)=>({
        name: relatedName(pr.jugadores), home: pr.home, away: pr.away,
        editCount: pr.edit_count, points: pr.points, ts: pr.updated_at,
      })));
    }

    // ------------------------------------------------------------------------
    // getAllPredictions: cache público solo de partidos ya cerrados.
    // ------------------------------------------------------------------------
    if (action === "getAllPredictions") {
      const pollaId = String(params.pollaId || "").trim();
      const { data: matches = [], error: me } = await supabase.from("partidos")
        .select("id, close_at, result_submitted").eq("polla_id", pollaId);
      if (me) throw me;
      const closedIds = matches.filter((m:any)=>m.result_submitted || (m.close_at && Date.now() >= new Date(m.close_at).getTime())).map((m:any)=>m.id);
      if (!closedIds.length) {
        const hist = await getCompactedHistory_(pollaId);
        const hMatches = Array.isArray(hist?.snapshot_json?.matches) ? hist.snapshot_json.matches : [];
        const hPreds = Array.isArray(hist?.snapshot_json?.predictions) ? hist.snapshot_json.predictions : [];
        if (!hMatches.length) return jsonOut({});
        const closed = new Set(hMatches.map((m:any)=>String(m.id)));
        const byMatch:Record<string,any[]> = {};
        const erasures=hPreds.length ? await getHistoricalErasureMaps_() : {byId:new Map(),byKey:new Map()};
        for (const pr of hPreds) {
          const mid=String(pr?.partido_id ?? pr?.matchId ?? "");
          if (!mid || !closed.has(mid)) continue;
          const pub=snapshotPredictionPublic_(pr);
          pub.name=historicalVisibleName_(pr,erasures);
          (byMatch[mid] ||= []).push(pub);
        }
        return jsonOut(byMatch);
      }
      const data = await fetchAllPages<any>((from, to) =>
        supabase.from("pronosticos")
          .select(`partido_id, home, away, edit_count, points, updated_at, jugadores(name)`)
          .in("partido_id", closedIds)
          .range(from, to)
      );
      const byMatch: Record<string,any[]> = {};
      for (const pr of data) {
        (byMatch[pr.partido_id] ||= []).push({
          name: relatedName(pr.jugadores), home: pr.home, away: pr.away,
          editCount: pr.edit_count, points: pr.points, ts: pr.updated_at,
        });
      }
      return jsonOut(byMatch);
    }

    // C5: bootstrap privado del jugador. Reúne en una sola petición lo que el
    // frontend necesita inmediatamente después del login: sus pronósticos y
    // el estado mínimo de su inscripción. Así nombre/PIN y participación se
    // verifican una sola vez en vez de repetir el mismo recorrido.
    if (action === "getPlayerBootstrap") {
      const pollaId = String(params.pollaId || "").trim();
      const name = cleanName(params.name);
      const pin = cleanPin(params.pin);
      const jugador = await findJugador(name);
      if (!jugador) return jsonOut({ ok: false, error: "IDENTIDAD_INVALIDA" });

      const pinCheck = await checkPredictionPin(jugador, pin);
      if (pinCheck.status !== "OK") {
        return jsonOut({
          ok: false,
          error: pinCheck.status === "NEEDS_ACTIVATION" ? "NEEDS_ACTIVATION" : "WRONG_PIN",
        });
      }

      const [part, matchesRes] = await Promise.all([
        findParticipant(pollaId, jugador.id),
        supabase
          .from("partidos")
          .select("id")
          .eq("polla_id", pollaId),
      ]);
      if (!part) return jsonOut({ ok: false, error: "NOT_A_PARTICIPANT" });
      if (matchesRes.error) throw matchesRes.error;

      const ids = (matchesRes.data || []).map((m: any) => m.id);
      const out: Record<string, any> = {};
      if (ids.length) {
        const prs = await fetchAllPages<any>((from, to) =>
          supabase
            .from("pronosticos")
            .select("partido_id,home,away,edit_count,points,updated_at")
            .eq("jugador_id", jugador.id)
            .in("partido_id", ids)
            .range(from, to)
        );
        for (const pr of prs) {
          out[pr.partido_id] = {
            name: jugador.name,
            home: pr.home,
            away: pr.away,
            editCount: pr.edit_count,
            points: pr.points,
            ts: pr.updated_at,
          };
        }
      }

      return jsonOut({
        ok: true,
        paid: !!part.paid,
        referralCode: part.referral_code || "",
        referredByCode: part.referred_by_code || "",
        whatsapp: jugador.whatsapp || "",
        predictions: out,
      });
    }

    // getMyParticipantStatus: datos privados mínimos de SU participación.
    // Evita exponer pago/código de invitación de todos por la ruta pública.
    if (action === "getMyParticipantStatus") {
      const pollaId=String(params.pollaId||"").trim();
      const name=cleanName(params.name); const pin=cleanPin(params.pin);
      const jugador=await findJugador(name);
      if(!jugador) return jsonOut({ok:false,error:"IDENTIDAD_INVALIDA"});
      const pinCheck=await checkPredictionPin(jugador,pin);
      if(pinCheck.status!=="OK") return jsonOut({ok:false,error:pinCheck.status==="NEEDS_ACTIVATION"?"NEEDS_ACTIVATION":"WRONG_PIN"});
      const part=await findParticipant(pollaId,jugador.id);
      if(!part) return jsonOut({ok:false,error:"NOT_A_PARTICIPANT"});
      return jsonOut({ok:true, paid:!!part.paid, referralCode:part.referral_code||"", referredByCode:part.referred_by_code||"", whatsapp:jugador.whatsapp||""});
    }

    // getMyPredictions: devuelve únicamente los pronósticos del jugador autenticado.
    if (action === "getMyPredictions") {
      const pollaId=String(params.pollaId||"").trim();
      const name=cleanName(params.name); const pin=cleanPin(params.pin);
      const jugador=await findJugador(name);
      if(!jugador) return jsonOut({ok:false,error:"IDENTIDAD_INVALIDA"});
      const pinCheck=await checkPredictionPin(jugador,pin);
      if(pinCheck.status!=="OK") return jsonOut({ok:false,error:pinCheck.status==="NEEDS_ACTIVATION"?"NEEDS_ACTIVATION":"WRONG_PIN"});
      const part=await findParticipant(pollaId,jugador.id);
      if(!part) return jsonOut({ok:false,error:"NOT_A_PARTICIPANT"});
      const {data:ms=[],error:me}=await supabase.from("partidos").select("id").eq("polla_id",pollaId); if(me) throw me;
      const ids=ms.map((m:any)=>m.id); if(!ids.length) return jsonOut({ok:true,predictions:{}});
      const prs=await fetchAllPages<any>((from,to)=>supabase.from("pronosticos").select("partido_id,home,away,edit_count,points,updated_at").eq("jugador_id",jugador.id).in("partido_id",ids).range(from,to));
      const out:Record<string,any>={};
      for(const pr of prs) out[pr.partido_id]={name:jugador.name,home:pr.home,away:pr.away,editCount:pr.edit_count,points:pr.points,ts:pr.updated_at};
      return jsonOut({ok:true,predictions:out});
    }

    // ------------------------------------------------------------------------
    // getPredictionTrendsForMatches: misma información agregada que
    // getPredictionTrends, pero solo para los partidos visibles solicitados.
    // Reduce trabajo y tráfico cuando las demás jornadas están retraídas.
    // ------------------------------------------------------------------------
    if (action === "getPredictionTrendsForMatches") {
      const pollaId=String(params.pollaId||"").trim();
      let requested:any[]=[];
      try {
        requested=Array.isArray(params.matchIds)?params.matchIds:JSON.parse(String(params.matchIds||"[]"));
      } catch { requested=[]; }
      requested=[...new Set(requested.map((x:any)=>String(x||"").trim()).filter(Boolean))].slice(0,100);
      if(!pollaId || !requested.length) return jsonOut({ok:true,trends:{}});

      // C3: Postgres devuelve únicamente los porcentajes finales por partido.
      // Ya no trasladamos todas las filas de pronósticos a la Edge Function.
      try {
        const { data: trendRpc, error: trendRpcError } = await supabase.rpc(
          "get_prediction_trends_summary_tico",
          { p_polla_id: pollaId, p_match_ids: requested },
        );
        if (!trendRpcError && trendRpc && typeof trendRpc === "object" && !Array.isArray(trendRpc)) {
          return jsonOut({ok:true,trends:trendRpc});
        }
      } catch (_) {
        // Si la migración C3 todavía no llegó, seguimos con el camino anterior.
      }

      const {data:allowed=[],error:ae}=await supabase.from("partidos")
        .select("id").eq("polla_id",pollaId).in("id",requested);
      if(ae) throw ae;
      const ids=allowed.map((m:any)=>m.id);
      if(!ids.length) return jsonOut({ok:true,trends:{}});

      const prs=await fetchAllPages<any>((from,to)=>supabase.from("pronosticos")
        .select("partido_id,home,away").in("partido_id",ids).range(from,to));
      const agg:Record<string,any>={};
      for(const p of prs){
        const a=agg[p.partido_id] ||= {local:0,draw:0,away:0,total:0};
        a.total++;
        if(Number(p.home)>Number(p.away)) a.local++;
        else if(Number(p.home)<Number(p.away)) a.away++;
        else a.draw++;
      }
      const trends:Record<string,any>={};
      for(const id of ids){
        const x=agg[id] || {local:0,draw:0,away:0,total:0};
        if(!x.total) continue;
        trends[id]={
          total:x.total,
          localPct:Math.round(x.local*100/x.total),
          drawPct:Math.round(x.draw*100/x.total),
          awayPct:Math.round(x.away*100/x.total),
        };
      }
      return jsonOut({ok:true,trends});
    }

    // ------------------------------------------------------------------------
    // ------------------------------------------------------------------------
    // getPredictionTrends: porcentajes agregados, seguros incluso en abierto.
    // ------------------------------------------------------------------------
    if (action === "getPredictionTrends") {
      const pollaId = String(params.pollaId || "").trim();
      try {
        const { data: trendRpc, error: trendRpcError } = await supabase.rpc(
          "get_prediction_trends_summary_tico",
          { p_polla_id: pollaId, p_match_ids: null },
        );
        if (!trendRpcError && trendRpc && typeof trendRpc === "object" && !Array.isArray(trendRpc)) {
          return jsonOut(trendRpc);
        }
      } catch (_) {
        // Fallback compatible con C2.
      }
      const { data: ms = [], error: me } = await supabase.from("partidos").select("id").eq("polla_id", pollaId);
      if (me) throw me;
      const ids = ms.map((m:any)=>m.id);
      if (!ids.length) return jsonOut({});
      const prs = await fetchAllPages<any>((from,to)=>supabase.from("pronosticos").select("partido_id, home, away").in("partido_id", ids).range(from,to));
      const agg: Record<string,any> = {};
      for (const p of prs) {
        const a = agg[p.partido_id] ||= { local:0, draw:0, away:0, total:0 };
        a.total++;
        if (Number(p.home)>Number(p.away)) a.local++;
        else if (Number(p.home)<Number(p.away)) a.away++;
        else a.draw++;
      }
      const out: Record<string,any> = {};
      for (const [id,a] of Object.entries(agg)) {
        const x:any=a; const t=x.total || 1;
        out[id]={ total:x.total, localPct:Math.round(x.local*100/t), drawPct:Math.round(x.draw*100/t), awayPct:Math.round(x.away*100/t) };
      }
      return jsonOut(out);
    }

    // ------------------------------------------------------------------------
    // ------------------------------------------------------------------------
    // getStandings
    // ------------------------------------------------------------------------
    if (action === "getStandings") {
      const pollaId = String(params.pollaId || "").trim();

      // H4.6: la Polla operativa normal sale en UNA consulta RPC. Solo buscamos
      // histórico compacto si la RPC no tiene filas o falla.
      let standingsRpcCache:any[] | null = null;
      try {
        const { data: standingsRpc, error: standingsRpcError } = await supabase.rpc(
          "get_polla_standings_summary_tico",
          { p_polla_id: pollaId },
        );
        if (!standingsRpcError && Array.isArray(standingsRpc)) {
          standingsRpcCache = standingsRpc;
          if (standingsRpc.length) {
            const normalized = standingsRpc.map((row: any) => ({
              name: String(row?.name || "").trim(),
              totalPoints: Number(row?.totalPoints ?? row?.total_points ?? 0),
              matchesScored: Number(row?.matchesScored ?? row?.matches_scored ?? 0),
              exactCount: Number(row?.exactCount ?? row?.exact_count ?? 0),
              mvpCount: Number(row?.mvpCount ?? row?.mvp_count ?? 0),
            })).filter((row: any) => row.name);
            return jsonOut(assignRanks(normalized.sort(
              (a: any, z: any) => z.totalPoints - a.totalPoints,
            )));
          }
        }
      } catch (_) {}

      const compacted = await getCompactedHistory_(pollaId);
      if (compacted && Array.isArray(compacted.standings_json)) {
        const erasures=await getHistoricalErasureMaps_();
        return jsonOut(compacted.standings_json.map((row:any)=>historicalStandingVisible_(row,erasures)));
      }

      if (Array.isArray(standingsRpcCache)) return jsonOut([]);

      const [participantesRes, partidosRes] = await Promise.all([
        supabase
          .from("participantes")
          .select("jugador_id, jugadores(name)")
          .eq("polla_id", pollaId),
        supabase
          .from("partidos")
          .select("id, result_submitted, actual_home, actual_away, is_canceled")
          .eq("polla_id", pollaId),
      ]);

      if (participantesRes.error) throw participantesRes.error;
      if (partidosRes.error) throw partidosRes.error;

      const participantes = participantesRes.data ?? [];
      const partidos = partidosRes.data ?? [];
      const activeMatches = partidos.filter((m) => !m.is_canceled && m.result_submitted);
      const matchIds = activeMatches.map((m) => m.id);
      const matchInfo: Record<string, any> = {};
      for (const m of activeMatches) {
        matchInfo[m.id] = {
          resultSubmitted: m.result_submitted,
          actualHome: m.actual_home,
          actualAway: m.actual_away,
        };
      }

      let pronosticos: any[] = [];
      if (matchIds.length) {
        pronosticos = await fetchAllPages<any>((from, to) =>
          supabase
            .from("pronosticos")
            .select("partido_id, jugador_id, home, away, points")
            .in("partido_id", matchIds)
            .range(from, to)
        );
      }

      const matchMax: Record<string, number> = {};
      for (const pr of pronosticos) {
        if (!matchInfo[pr.partido_id]?.resultSubmitted || pr.points === null || pr.points === undefined) continue;
        const pts = Number(pr.points);
        if (matchMax[pr.partido_id] === undefined || pts > matchMax[pr.partido_id]) matchMax[pr.partido_id] = pts;
      }

      const totals: Record<string, any> = {};
      for (const p of participantes) {
        totals[p.jugador_id] = {
          name: relatedName(p.jugadores), totalPoints: 0, matchesScored: 0, exactCount: 0, mvpCount: 0,
        };
      }
      for (const pr of pronosticos) {
        const info = matchInfo[pr.partido_id];
        if (!info || !totals[pr.jugador_id] || pr.points === null || pr.points === undefined) continue;
        totals[pr.jugador_id].totalPoints += Number(pr.points);
        totals[pr.jugador_id].matchesScored += 1;
        if (Number(pr.home) === Number(info.actualHome) && Number(pr.away) === Number(info.actualAway)) totals[pr.jugador_id].exactCount += 1;
        if (matchMax[pr.partido_id] !== undefined && matchMax[pr.partido_id] > 0 && Number(pr.points) === matchMax[pr.partido_id]) totals[pr.jugador_id].mvpCount += 1;
      }

      return jsonOut(assignRanks(Object.values(totals).sort(
        (a: any, b: any) => b.totalPoints - a.totalPoints,
      ) as any[]));
    }

    // ------------------------------------------------------------------------
    // getStreak
    // ------------------------------------------------------------------------
    if (action === "getStreak") {
      const pollaId = String(params.pollaId || "").trim();
      const name = cleanName(params.name);
      if (!pollaId || !name) return jsonOut({ streak: 0 });

      const jugador = await findJugador(name);
      if (!jugador) return jsonOut({ streak: 0 });

      // C4: la racha se calcula en SQL y vuelve como un solo entero.
      try {
        const { data: streakRpc, error: streakRpcError } = await supabase.rpc(
          "get_player_streak_tico",
          { p_polla_id: pollaId, p_jugador_id: String(jugador.id) },
        );
        if (!streakRpcError && streakRpc !== null && streakRpc !== undefined) {
          return jsonOut({ streak: Math.max(0, Number(streakRpc) || 0) });
        }
        if (streakRpcError) {
          console.warn("C4 streak RPC no disponible; usando fallback compatible", streakRpcError.message || "");
        }
      } catch (_) {
        // fallback debajo
      }

      const { data: partidos = [], error: errM } = await supabase
        .from("partidos")
        .select("id, close_at")
        .eq("polla_id", pollaId)
        .eq("result_submitted", true)
        .eq("is_canceled", false)
        .order("close_at", { ascending: false });
      if (errM) throw errM;
      if (!partidos.length) return jsonOut({ streak: 0 });

      const ids = partidos.map((m) => m.id);
      const { data: pronosticos = [], error: errPr } = await supabase
        .from("pronosticos")
        .select("partido_id, points")
        .eq("jugador_id", jugador.id)
        .in("partido_id", ids);
      if (errPr) throw errPr;

      const byMatch = Object.fromEntries(pronosticos.map((p) => [p.partido_id, p.points]));
      let streak = 0;
      for (const m of partidos) {
        const pts = byMatch[m.id];
        if (pts === undefined || pts === null || Number(pts) <= 0) break;
        streak++;
      }
      return jsonOut({ streak });
    }

    // ------------------------------------------------------------------------
    // getGanadores
    // ------------------------------------------------------------------------
    if (action === "getGanadores") {
      const { data = [], error } = await supabase
        .from("ganadores")
        .select("name, wins")
        .order("wins", { ascending: false })
        .order("name", { ascending: true });

      if (error) throw error;

      return jsonOut(data);
    }

    // ------------------------------------------------------------------------
    // getYearlyStandings
    // ------------------------------------------------------------------------
    if (action === "getYearlyStandings") {
      const list =
        await computeYearlyStandings();

      const qualifiers =
        computeFreeContestQualifiers(list);

      const withFlag =
        list.map((s: any) => ({
          ...s,
          qualifiesFreeContest:
            !!qualifiers.qualifiedKeys[
              normalizeName(s.name)
            ],
        }));

      return jsonOut(withFlag);
    }

    // ------------------------------------------------------------------------
    // getFreeContestStats
    // ------------------------------------------------------------------------
    if (action === "getFreeContestStats") {
      const list =
        await computeYearlyStandings();

      const qualifiers =
        computeFreeContestQualifiers(list);

      const qualifiedNames =
        list
          .filter(
            (s: any) =>
              qualifiers.qualifiedKeys[
                normalizeName(s.name)
              ],
          )
          .map((s: any) => s.name);

      return jsonOut({
        totalParticipants: list.length,
        qualifiedCount:
          qualifiers.qualifiedCount,
        qualifiedNames,
      });
    }

    // ------------------------------------------------------------------------
    // getSeasonInfo
    // ------------------------------------------------------------------------
    if (action === "getSeasonInfo") {
      const list =
        await computeYearlyStandings();

      const qualifiers =
        computeFreeContestQualifiers(list);

      const { data: lastRows = [], error: errT } =
        await supabase
          .from("temporadas")
          .select(
            `
            season_label,
            closed_at,
            closed_by,
            total_participants,
            qualified_count
            `,
          )
          .order("closed_at", { ascending: false })
          .limit(1);

      if (errT) throw errT;

      const last = lastRows[0];

      return jsonOut({
        liveTotalParticipants: list.length,
        liveQualifiedCount:
          qualifiers.qualifiedCount,

        lastClosedSeason: last
          ? {
              seasonLabel:
                last.season_label,

              closedAt:
                last.closed_at,

              closedBy:
                last.closed_by,

              totalParticipants:
                last.total_participants,

              qualifiedCount:
                last.qualified_count,
            }
          : null,
      });
    }

    // ========================================================================
    // AUTH / JUGADOR
    // ========================================================================

    // ------------------------------------------------------------------------
    // checkName: primer paso contextual del nuevo flujo de acceso.
    if (action === "checkName") {
      const pollaId = String(params.pollaId || "").trim();
      const name = cleanName(params.name);
      if (!pollaId || !name) return jsonOut({ ok:false, error:"DATOS_INVALIDOS" });

      const jugador = await findJugador(name);
      const part = jugador ? await findParticipant(pollaId, jugador.id) : null;
      const accessGate = await assertCanEnroll(pollaId, jugador?.id ?? null, jugador?.name ?? name);

      if (accessGate.lifecycle === "COMPACTED") {
        return jsonOut({ok:false,error:"POLLA_COMPACTADA"});
      }

      // Finalizada sin compactar: solo quien YA participaba puede abrir sesión.
      if (accessGate.lifecycle === "FINAL_REVIEW" && !part) {
        return jsonOut({ok:true,state:"NEW",canRegister:false,reason:"POLLA_FINALIZADA"});
      }

      if (!jugador) {
        return jsonOut({ ok:true, state:"NEW", canRegister:accessGate.ok, reason:accessGate.ok?null:accessGate.error });
      }
      if (!jugador.pin_hash) {
        // No activamos cuentas por primera vez después de finalizar la Polla.
        if (accessGate.lifecycle === "FINAL_REVIEW") {
          return jsonOut({ok:true,state:"NEW",canRegister:false,reason:"POLLA_FINALIZADA"});
        }
        return jsonOut({ ok:true, state:"PENDING_ACTIVATION", realName:jugador.name, inThisPolla:!!part, activationPurpose:jugador.activation_purpose || "FIRST" });
      }
      return jsonOut({ ok:true, state:"EXISTING", realName:jugador.name, inThisPolla:!!part, readOnly:accessGate.readOnly===true, hasSecurityAnswer:!!jugador.security_answer_hash });
    }

    if (action === "activatePlayer") {
      const pollaId = String(params.pollaId || "").trim();
      const name = cleanName(params.name);
      const jugador = await findJugador(name);
      if (!jugador) return jsonOut({ ok:false, error:"NOT_A_PARTICIPANT" });
      const pollaGate = await assertCanEnroll(pollaId, jugador.id, jugador.name);
      if (!pollaGate.ok) return jsonOut({ok:false,error:pollaGate.error});
      if (pollaGate.readOnly) return jsonOut({ok:false,error:"POLLA_FINALIZADA"});
      const existingPart = await findParticipant(pollaId, jugador.id);
      if (!existingPart) {
        const gate = await assertCanEnroll(pollaId, jugador.id, jugador.name);
        if (!gate.ok) return jsonOut({ok:false,error:gate.error});
      }
      const activationKey=String(jugador.id);
      const activationOrigin=await getOriginHash_();
      const activationRl=await getRateLimit('ACTIVATION_CODE',activationKey,activationOrigin);
      const activationUntil=activationRl?.lock_until ? new Date(activationRl.lock_until).getTime() : 0;
      if(activationUntil && Date.now()<activationUntil){
        return jsonOut({ok:false,error:'ACTIVATION_LOCKED',minutesLeft:Math.max(1,Math.ceil((activationUntil-Date.now())/60000))});
      }
      const result = await activateWithCode(jugador, params.activationCode, params.newPin);
      if (!result.ok) {
        if(result.error==='CODIGO_ACTIVACION_INVALIDO'){
          const failed=await failRateLimit('ACTIVATION_CODE',activationKey,activationOrigin,8,10);
          return jsonOut({ok:false,error:failed.locked?'ACTIVATION_LOCKED':result.error,attemptsLeft:failed.attemptsLeft,minutesLeft:failed.locked?10:undefined});
        }
        return jsonOut(result);
      }
      await clearRateLimit('ACTIVATION_CODE',activationKey,activationOrigin);
      const enroll = await ensureEnrolled(pollaId, jugador.id, "");
      return jsonOut({ ok:true, realName:jugador.name, referralCode:enroll.referralCode, needsSecurityAnswer:!jugador.security_answer_hash });
    }

    // ------------------------------------------------------------------------
    // authName
    // ------------------------------------------------------------------------
    if (action === "authName") {
      const pollaId =
        String(params.pollaId || "").trim();

      const name =
        cleanName(params.name);

      const pin =
        cleanPin(params.pin);

      if (!pollaId || !name) {
        return jsonOut({
          ok: false,
          error: "DATOS_INVALIDOS",
        });
      }

      const jugador =
        await findJugador(name);

      // Si el admin pre-agrega a alguien en Fase Admin,
      // addParticipants creará una identidad jugadores con pin_hash=null.
      // Por eso si NO existe jugador acá, es una persona totalmente nueva.
      if (!jugador) {
        return jsonOut({
          ok: false,
          error: "NOT_A_PARTICIPANT",
        });
      }

      if (!jugador.pin_hash) {
        return jsonOut({
          ok: false,
          error: "NEEDS_ACTIVATION",
          realName: jugador.name,
          activationPurpose: jugador.activation_purpose || "FIRST",
        });
      }

      if (!validExistingPin(pin)) {
        return jsonOut({ ok: false, error: "PIN_INVALIDO" });
      }

      // Gate antes de verificar PIN.
      const gate =
        await assertCanEnroll(
          pollaId,
          jugador.id,
          jugador.name,
        );

      if (!gate.ok) {
        return jsonOut({
          ok: false,
          error: gate.error,
        });
      }

      const resolved =
        await resolveIdentity(
          jugador,
          pin,
        );

      if (resolved.status === "WRONG_PIN") {
        return jsonOut({ ok: false, error: "WRONG_PIN", hasSecurityAnswer: !!jugador.security_answer_hash });
      }

      const enroll = gate.readOnly
        ? gate.existingParticipant
        : await ensureEnrolled(
            pollaId,
            jugador.id,
            "",
          );

      return jsonOut({
        ok: true,
        readOnly: gate.readOnly === true,

        registered:
          resolved.wasReset === true,

        realName:
          jugador.name,

        newInThisPolla:
          gate.readOnly ? false : !!enroll?.isNew,

        needsSecurityAnswer:
          gate.readOnly ? false : !jugador.security_answer_hash,

        referralCode:
          enroll?.referralCode ?? enroll?.referral_code ?? null,
      });
    }

    // ------------------------------------------------------------------------
    // selfRegister
    // ------------------------------------------------------------------------
    if (action === "selfRegister") {
      const cfg = await getAppConfig_();
      if (maintenanceBlocked_(cfg)) return jsonOut({ok:false, code:"MAINTENANCE_MODE", error: cfg.maintenanceMessage || "Estamos haciendo una mejora rápida. Intenta nuevamente en unos minutos."});
      if (!cfg.registrationsEnabled) return jsonOut({ok:false, code:"REGISTRATIONS_DISABLED", error:"Las inscripciones están pausadas temporalmente."});
      const pollaId =
        String(params.pollaId || "").trim();

      const name =
        cleanName(params.name);

      const pin =
        cleanPin(params.pin);

      const referredByCode =
        String(
          params.referredByCode || "",
        )
          .trim()
          .toUpperCase();

      const whatsapp = normalizeWhatsapp(params.whatsapp);
      if (whatsapp === "__INVALID__") {
        return jsonOut({ ok:false, error:"WHATSAPP_INVALIDO" });
      }

      if (!pollaId) {
        return jsonOut({
          ok: false,
          error: "POLLA_NO_ENCONTRADA",
        });
      }

      if (!name) {
        return jsonOut({
          ok: false,
          error: "Nombre inválido.",
        });
      }

      if (name.length > 60) {
        return jsonOut({
          ok: false,
          error:
            "El nombre es demasiado largo (máx. 60 caracteres).",
        });
      }

      if (!validNewPin(pin)) {
        return jsonOut({
          ok: false,
          error: "PIN_INVALIDO",
        });
      }

      let jugador =
        await findJugador(name);

      // Ya inscrito con esa identidad en esa Polla.
      if (jugador) {
        const already =
          await findParticipant(
            pollaId,
            jugador.id,
          );

        if (already) {
          return jsonOut({
            ok: false,
            error: "DUPLICATE_NAME",
          });
        }
      }

      const gate =
        await assertCanEnroll(
          pollaId,
          jugador?.id ?? null,
          jugador?.name ?? name,
        );

      if (!gate.ok) {
        return jsonOut({
          ok: false,
          error: gate.error,
        });
      }

      if (
        referredByCode &&
        !(await referralCodeIsValid(
          pollaId,
          referredByCode,
        ))
      ) {
        return jsonOut({
          ok: false,
          error: "CODIGO_INVALIDO",
        });
      }

      // ----------------------------------------------------
      // Identidad completamente nueva.
      // ----------------------------------------------------
      if (!jugador) {
        const pinHash =
          await hashPrivateValue(pin);

        const nameKey =
          normalizeName(name);

        const { data: created, error } =
          await supabase
            .from("jugadores")
            .insert({
              name,
              name_key: nameKey,
              pin_hash: pinHash,
              failed_attempts: 0,
              security_answer_hash: null,
              whatsapp,
            })
            .select(
              `
              id,
              name,
              name_key,
              pin_hash,
              failed_attempts,
              security_answer_hash,
              whatsapp
              `,
            )
            .single();

        if (error) {
          // Carrera: otro request pudo crear el nombre.
          if (error.code === "23505") {
            jugador =
              await findJugador(name);

            if (!jugador) throw error;
          } else {
            throw error;
          }
        } else {
          jugador = created;

          const enroll =
            await ensureEnrolled(
              pollaId,
              jugador.id,
              referredByCode,
            );

          return jsonOut({
            ok: true,
            realName: jugador.name,
            referralCode:
              enroll.referralCode,
            registered: true,
            needsSecurityAnswer: true,
            whatsapp: jugador.whatsapp || "",
          });
        }
      }

      // ----------------------------------------------------
      // Nombre existente globalmente: si está pendiente de activación,
      // no puede apropiarse del nombre creando un PIN cualquiera.
      // ----------------------------------------------------
      if (!jugador.pin_hash) {
        return jsonOut({ ok:false, error:"NEEDS_ACTIVATION", realName:jugador.name });
      }

      const resolved =
        await resolveIdentity(
          jugador,
          pin,
        );

      if (resolved.status === "WRONG_PIN") {
        return jsonOut({ ok:false, error:"WRONG_PIN", hasSecurityAnswer:!!jugador.security_answer_hash });
      }

      if (whatsapp) {
        const { error: whatsappUpdateError } = await supabase
          .from("jugadores")
          .update({ whatsapp })
          .eq("id", jugador.id);
        if (whatsappUpdateError) throw whatsappUpdateError;
        jugador.whatsapp = whatsapp;
      }

      const enroll =
        await ensureEnrolled(
          pollaId,
          jugador.id,
          referredByCode,
        );

      return jsonOut({
        ok: true,
        realName:
          jugador.name,
        referralCode:
          enroll.referralCode,
        registered:
          resolved.wasReset === true,
        needsSecurityAnswer:
          !jugador.security_answer_hash,
        whatsapp: jugador.whatsapp || "",
      });
    }

    // ------------------------------------------------------------------------
    // updateMyWhatsapp — dato global opcional del jugador autenticado.
    // ------------------------------------------------------------------------
    if (action === "updateMyWhatsapp") {
      const cfg = await getAppConfig_();
      if (maintenanceBlocked_(cfg)) return jsonOut({ok:false, code:"MAINTENANCE_MODE", error: cfg.maintenanceMessage || "La app está temporalmente en modo solo lectura."});

      const name = cleanName(params.name);
      const pin = cleanPin(params.pin);
      const whatsapp = normalizeWhatsapp(params.whatsapp);
      if (whatsapp === "__INVALID__") return jsonOut({ok:false,error:"WHATSAPP_INVALIDO"});

      const jugador = await findJugador(name);
      if (!jugador) return jsonOut({ok:false,error:"IDENTIDAD_INVALIDA"});

      const pinCheck = await checkPredictionPin(jugador, pin);
      if (pinCheck.status !== "OK") {
        return jsonOut({ok:false,error:pinCheck.status === "NEEDS_ACTIVATION" ? "NEEDS_ACTIVATION" : "WRONG_PIN"});
      }

      const { error } = await supabase
        .from("jugadores")
        .update({ whatsapp })
        .eq("id", jugador.id);
      if (error) throw error;

      return jsonOut({ok:true, whatsapp: whatsapp || ""});
    }

    // ------------------------------------------------------------------------
    // setSecurityAnswer
    // ------------------------------------------------------------------------
    if (action === "setSecurityAnswer") {
      const cfg = await getAppConfig_();
      if (maintenanceBlocked_(cfg)) return jsonOut({ok:false, code:"MAINTENANCE_MODE", error: cfg.maintenanceMessage || "La app está temporalmente en modo solo lectura."});
      const name =
        cleanName(params.name);

      const pin =
        cleanPin(params.pin);

      const securityAnswer =
        String(
          params.securityAnswer || "",
        ).trim();

      if (!securityAnswer) {
        return jsonOut({
          ok: false,
          error: "Respuesta vacía.",
        });
      }

      if (!validExistingPin(pin)) {
        return jsonOut({
          ok: false,
          error:
            "No se pudo verificar tu cuenta.",
        });
      }

      const jugador =
        await findJugador(name);

      if (!jugador || !jugador.pin_hash) {
        return jsonOut({
          ok: false,
          error:
            "No se pudo verificar tu cuenta.",
        });
      }

      const pinHash =
        await hashPrivateValue(pin);

      if (pinHash !== jugador.pin_hash) {
        return jsonOut({
          ok: false,
          error:
            "No se pudo verificar tu cuenta.",
        });
      }

      const answerHash =
        await hashPrivateValue(
          normalizeName(securityAnswer),
        );

      const { error } = await supabase
        .from("jugadores")
        .update({
          security_answer_hash:
            answerHash,
        })
        .eq("id", jugador.id);

      if (error) throw error;

      return jsonOut({
        ok: true,
      });
    }

    // ------------------------------------------------------------------------
    // selfResetPin: 5 respuestas erróneas / 5 min por origen y jugador.
    // ------------------------------------------------------------------------
    if (action === "selfResetPin") {
      const cfg = await getAppConfig_();
      if (maintenanceBlocked_(cfg)) return jsonOut({ok:false, code:"MAINTENANCE_MODE", error: cfg.maintenanceMessage || "La app está temporalmente en modo solo lectura."});
      const name = cleanName(params.name);
      const securityAnswer = String(params.securityAnswer || "").trim();
      const newPin = cleanPin(params.newPin);
      if (!validNewPin(newPin)) return jsonOut({ ok:false, error:"PIN_INVALIDO" });
      const jugador = await findJugador(name);
      if (!jugador) return jsonOut({ ok:false, error:"No se encontró a esa persona." });
      if (!jugador.security_answer_hash) return jsonOut({ ok:false, error:"NO_SECURITY_ANSWER" });
      const targetKey = normalizeName(jugador.name);
      const rl = await getRateLimit("PIN_RECOVERY", targetKey, await getOriginHash_());
      const until = rl?.lock_until ? new Date(rl.lock_until).getTime() : 0;
      if (until && Date.now() < until) {
        return jsonOut({ ok:false, error:"RECOVERY_LOCKED", minutesLeft:Math.max(1,Math.ceil((until-Date.now())/60000)) });
      }
      const incoming = await hashPrivateValue(normalizeName(securityAnswer));
      if (incoming !== jugador.security_answer_hash) {
        const f = await failRateLimit("PIN_RECOVERY", targetKey, await getOriginHash_(), 5, 5);
        return jsonOut({ ok:false, error:f.locked?"RECOVERY_LOCKED":"RESPUESTA_INCORRECTA", attemptsLeft:f.attemptsLeft, minutesLeft:f.locked?5:undefined });
      }
      await clearRateLimit("PIN_RECOVERY", targetKey, await getOriginHash_());
      const newPinHash = await hashPrivateValue(newPin);
      const { error } = await supabase.from("jugadores").update({ pin_hash:newPinHash, failed_attempts:0 }).eq("id",jugador.id);
      if (error) throw error;
      return jsonOut({ ok:true });
    }

    // ------------------------------------------------------------------------
    // savePredictionsBulk — B2
    // Guarda varios pronósticos con una sola autenticación y una sola petición.
    // ------------------------------------------------------------------------
    if (action === "savePredictionsBulk") {
      const cfg = await getAppConfig_();
      if (maintenanceBlocked_(cfg)) return jsonOut({ok:false, code:"MAINTENANCE_MODE", error: cfg.maintenanceMessage || "La app está temporalmente en modo solo lectura."});
      if (!cfg.predictionsEnabled) return jsonOut({ok:false, code:"PREDICTIONS_DISABLED", error:"Los pronósticos están pausados temporalmente."});
      const pollaId = String(params.pollaId || "").trim();
      const name = cleanName(params.name);
      const pin = cleanPin(params.pin);
      const rawPredictions = Array.isArray(params.predictions) ? params.predictions : [];

      if (!pollaId || !name || rawPredictions.length === 0 || rawPredictions.length > 100) {
        return jsonOut({ ok:false, error:"Datos incompletos." });
      }

      const parsed:any[] = [];
      const seen = new Set<string>();
      for (const raw of rawPredictions) {
        const matchId = String(raw?.matchId || "").trim();
        const home = Number(raw?.home);
        const away = Number(raw?.away);
        if (!matchId || seen.has(matchId) || !Number.isInteger(home) || !Number.isInteger(away) || home < 0 || away < 0 || home > 20 || away > 20) {
          return jsonOut({ ok:false, error:"Hay un marcador inválido en el envío múltiple." });
        }
        seen.add(matchId);
        parsed.push({matchId, home, away});
      }

      const jugador = await findJugador(name);
      if (!jugador) return jsonOut({ ok:false, error:"No se pudo verificar tu identidad. Vuelve a confirmar tu nombre." });

      const pinCheck = await checkPredictionPin(jugador, pin);
      if (pinCheck.status === "NEEDS_ACTIVATION") return jsonOut({ ok:false, error:"Debes activar o restablecer tu PIN antes de pronosticar." });
      if (pinCheck.status === "WRONG_PIN") return jsonOut({ ok:false, error:"No se pudo verificar tu identidad. Vuelve a confirmar tu nombre." });

      const { data: polla, error: pollaErr } = await supabase
        .from("pollas")
        .select("id,status,is_archived,compacted_at")
        .eq("id", pollaId)
        .maybeSingle();
      if (pollaErr) throw pollaErr;
      if (!polla || polla.compacted_at || polla.is_archived || polla.status === "finalizada") {
        return jsonOut({ ok:false, error:"Esta Polla ya no admite pronósticos." });
      }

      const participant = await findParticipant(pollaId, jugador.id);
      if (!participant) return jsonOut({ ok:false, error:"No estás inscrito en esta Polla. Vuelve a confirmar tu nombre." });

      const ids = parsed.map(p=>p.matchId);
      const { data: matches = [], error: matchesErr } = await supabase
        .from("partidos")
        .select("id,polla_id,close_at,result_submitted,is_canceled")
        .in("id", ids);
      if (matchesErr) throw matchesErr;

      const matchById = new Map((matches || []).map((m:any)=>[String(m.id),m]));
      const failed:any[] = [];
      const valid:any[] = [];
      const nowMs = Date.now();

      for (const p of parsed) {
        const m:any = matchById.get(p.matchId);
        let error = "";
        if (!m || String(m.polla_id) !== pollaId) error = "Partido no encontrado.";
        else if (m.is_canceled) error = "Este partido está cancelado.";
        else if (m.result_submitted) error = "Este partido ya tiene un resultado registrado.";
        else if (m.close_at && nowMs >= new Date(m.close_at).getTime()) error = "Demasiado tarde. El partido ya cerró.";
        if (error) failed.push({matchId:p.matchId,error});
        else valid.push(p);
      }

      if (!valid.length) return jsonOut({ok:true,savedIds:[],unchangedIds:[],failed,serverNow:new Date().toISOString()});

      // H4: una sola RPC transaccional serializa cada jugador+partido.
      // Evita carreras de edit_count entre dispositivos y reduce viajes a DB.
      const atomicPayload = valid.map((p:any)=>({matchId:p.matchId, home:p.home, away:p.away}));
      const { data: atomic, error: atomicErr } = await supabase.rpc("save_predictions_atomic_tico", {
        p_jugador_id: jugador.id,
        p_predictions: atomicPayload,
      });
      if (atomicErr) throw atomicErr;
      const atomicResult:any = atomic || {};
      const atomicFailed = Array.isArray(atomicResult.failed) ? atomicResult.failed : [];
      return jsonOut({
        ok:true,
        savedIds:Array.isArray(atomicResult.savedIds) ? atomicResult.savedIds.map(String) : [],
        unchangedIds:Array.isArray(atomicResult.unchangedIds) ? atomicResult.unchangedIds.map(String) : [],
        failed:[...failed, ...atomicFailed],
        serverNow:String(atomicResult.serverNow || new Date().toISOString()),
      });
    }

    // ------------------------------------------------------------------------
    // ------------------------------------------------------------------------
    // savePrediction
    // ------------------------------------------------------------------------
    if (action === "savePrediction") {
      const cfg = await getAppConfig_();
      if (maintenanceBlocked_(cfg)) return jsonOut({ok:false, code:"MAINTENANCE_MODE", error: cfg.maintenanceMessage || "La app está temporalmente en modo solo lectura."});
      if (!cfg.predictionsEnabled) return jsonOut({ok:false, code:"PREDICTIONS_DISABLED", error:"Los pronósticos están pausados temporalmente."});
      const matchId =
        String(params.matchId || "").trim();

      const name =
        cleanName(params.name);

      const pin =
        cleanPin(params.pin);

      const home =
        Number(params.home);

      const away =
        Number(params.away);

      if (!matchId || !name) {
        return jsonOut({
          ok: false,
          error: "Datos incompletos.",
        });
      }

      const { data: match, error: matchError } =
        await supabase
          .from("partidos")
          .select(
            `
            id,
            polla_id,
            close_at,
            result_submitted,
            is_canceled
            `,
          )
          .eq("id", matchId)
          .maybeSingle();

      if (matchError) throw matchError;

      if (!match) {
        return jsonOut({
          ok: false,
          error: "Partido no encontrado.",
        });
      }

      if (match.is_canceled) {
        return jsonOut({
          ok: false,
          error:
            "Este partido está cancelado.",
        });
      }

      const { data: predictionPolla, error: predictionPollaErr } = await supabase
        .from("pollas")
        .select("status, is_archived, compacted_at")
        .eq("id", match.polla_id)
        .maybeSingle();
      if (predictionPollaErr) throw predictionPollaErr;
      if (!predictionPolla || predictionPolla.compacted_at || predictionPolla.is_archived || predictionPolla.status === "finalizada") {
        return jsonOut({ ok:false, error:"Esta Polla ya no admite pronósticos." });
      }

      if (match.result_submitted) {
        return jsonOut({
          ok: false,
          error:
            "Este partido ya tiene un resultado registrado, no se puede pronosticar.",
        });
      }

      // Mismo criterio que Apps Script: después del límite, rechazar.
      if (
        match.close_at &&
        Date.now() >=
          new Date(match.close_at).getTime()
      ) {
        return jsonOut({
          ok: false,
          error:
            "Demasiado tarde. El partido ya cerró y no se aceptan más pronósticos.",
        });
      }

      if (
        !Number.isInteger(home) ||
        !Number.isInteger(away) ||
        home < 0 ||
        away < 0 ||
        home > 20 ||
        away > 20
      ) {
        return jsonOut({
          ok: false,
          error:
            "Marcador inválido. Debe ser un número entero entre 0 y 20.",
        });
      }

      const jugador =
        await findJugador(name);

      if (!jugador) {
        return jsonOut({
          ok: false,
          error:
            "No se pudo verificar tu identidad. Vuelve a confirmar tu nombre.",
        });
      }

      const pinCheck =
        await checkPredictionPin(
          jugador,
          pin,
        );

      if (pinCheck.status === "NEEDS_ACTIVATION") {
        return jsonOut({ ok:false, error:"Debes activar o restablecer tu PIN antes de pronosticar." });
      }

      if (pinCheck.status === "WRONG_PIN") {
        return jsonOut({
          ok: false,
          error:
            "No se pudo verificar tu identidad. Vuelve a confirmar tu nombre.",
        });
      }

      const participant =
        await findParticipant(
          match.polla_id,
          jugador.id,
        );

      if (!participant) {
        return jsonOut({
          ok: false,
          error:
            "No estás inscrito en esta Polla. Vuelve a confirmar tu nombre.",
        });
      }

      // H4: guardado atómico en PostgreSQL. La validación de identidad, Polla y
      // cierre se mantiene aquí; solo la escritura/edit_count se serializa en DB.
      const { data: atomic, error: atomicErr } = await supabase.rpc("save_predictions_atomic_tico", {
        p_jugador_id: jugador.id,
        p_predictions: [{matchId, home, away}],
      });
      if (atomicErr) throw atomicErr;
      const atomicResult:any = atomic || {};
      const atomicFailed = Array.isArray(atomicResult.failed) ? atomicResult.failed : [];
      const raceFailure = atomicFailed.find((x:any)=>String(x?.matchId||"")===matchId);
      if (raceFailure) {
        return jsonOut({
          ok:false,
          error:String(raceFailure.error || "No se pudo guardar el pronóstico."),
          serverNow:String(atomicResult.serverNow || new Date().toISOString()),
        });
      }
      const editCounts = atomicResult.editCounts && typeof atomicResult.editCounts === "object"
        ? atomicResult.editCounts : {};
      return jsonOut({
        ok:true,
        editCount:Number(editCounts[matchId] || 1),
        unchanged:Array.isArray(atomicResult.unchangedIds) && atomicResult.unchangedIds.map(String).includes(matchId),
      });
    }


    // ========================================================================
    // ACCIONES ADMIN
    // ========================================================================

    if (
      action ===
      "getAdminLog"
    ) {
      const {
        data = [],
        error,
      } =
        await supabase
          .from("admin_log")
          .select(
            "ts, admin_name, action, details",
          )
          .order(
            "ts",
            {
              ascending: false,
            },
          )
          .limit(300);

      if (error) throw error;

      return jsonOut(
        data.map((r) => ({
          timestamp: r.ts,
          adminName:
            r.admin_name,
          action:
            r.action,
          details:
            r.details,
        })),
      );
    }

    if (action === "getSecurePollaBackupStatus") {
      const pollaId = String(params.pollaId || "").trim();
      const { data, error } = await supabase
        .from("polla_backup_receipts")
        .select("id, polla_id, created_at, created_by, backend_version, object_path, sha256, size_bytes, participant_count, match_count, prediction_count, image_count, snapshot_sha256, snapshot_version, status")
        .eq("polla_id", pollaId)
        .eq("status", "verified")
        .order("created_at", { ascending: false })
        .limit(1)
        .maybeSingle();
      if (error) throw error;
      if (!data) return jsonOut({ ok: true, hasBackup: false });
      await ensureBackupBucket_();
      const signed = await supabase.storage.from(BACKUP_BUCKET).createSignedUrl(data.object_path, 600, { download: true });
      if (signed.error) throw signed.error;
      return jsonOut({ ok: true, hasBackup: true, receipt: data, signedUrl: signed.data?.signedUrl || "" });
    }


    if (action === "getCompactionSealStatus") {
      const pollaId = String(params.pollaId || "").trim();
      const { data, error } = await supabase
        .from("polla_compaction_seals")
        .select("id,polla_id,backup_receipt_id,created_at,created_by,backend_version,backup_sha256,snapshot_sha256,participant_count,match_count,prediction_count,image_count,status")
        .eq("polla_id", pollaId)
        .eq("status", "prepared")
        .order("created_at", { ascending:false })
        .limit(1)
        .maybeSingle();
      if (error) throw error;
      if (!data) return jsonOut({ ok:true, hasSeal:false });
      return jsonOut({
        ok:true,
        hasSeal:true,
        seal:{
          id:data.id,
          createdAt:data.created_at,
          backupReceiptId:data.backup_receipt_id,
          backupSha256:data.backup_sha256,
          snapshotSha256:data.snapshot_sha256,
          counts:{participants:data.participant_count,matches:data.match_count,predictions:data.prediction_count,images:data.image_count},
          status:data.status,
        },
      });
    }

    if (action === "prepareCompactionSeal") {
      const pollaId = String(params.pollaId || "").trim();
      const current = await loadPollaCompactionData_(pollaId);
      if (!current) return jsonOut({ ok:false, error:"Polla no encontrada." });
      if (current.polla.status !== "finalizada" || !current.polla.is_archived) {
        return jsonOut({ ok:false, error:"La Polla debe estar finalizada y archivada antes de preparar el sello." });
      }
      const { data: receipt, error: receiptErr } = await supabase
        .from("polla_backup_receipts")
        .select("id,object_path,sha256,size_bytes,participant_count,match_count,prediction_count,image_count,snapshot_sha256,snapshot_version,status")
        .eq("polla_id", pollaId)
        .eq("status", "verified")
        .order("created_at", { ascending:false })
        .limit(1)
        .maybeSingle();
      if (receiptErr) throw receiptErr;
      if (!receipt) return jsonOut({ ok:false, error:"No existe un respaldo seguro verificado." });
      if (Number(receipt.snapshot_version || 0) < 2 || String(receipt.snapshot_sha256 || "") !== current.snapshotSha256) {
        return jsonOut({ ok:false, error:"El respaldo ya no representa exactamente el estado actual. Genera un respaldo nuevo." });
      }
      const countsOk =
        Number(receipt.participant_count) === current.counts.participants &&
        Number(receipt.match_count) === current.counts.matches &&
        Number(receipt.prediction_count) === current.counts.predictions &&
        Number(receipt.image_count) === current.counts.images;
      if (!countsOk) return jsonOut({ ok:false, error:"Los conteos actuales no coinciden con el respaldo. Genera uno nuevo." });

      await ensureBackupBucket_();
      const downloaded = await supabase.storage.from(BACKUP_BUCKET).download(receipt.object_path);
      if (downloaded.error || !downloaded.data) return jsonOut({ ok:false, error:"No se pudo verificar el ZIP privado del respaldo." });
      const bytes = new Uint8Array(await downloaded.data.arrayBuffer());
      if (bytes.byteLength !== Number(receipt.size_bytes) || (await sha256Hex_(bytes)) !== String(receipt.sha256 || "")) {
        return jsonOut({ ok:false, error:"El ZIP del respaldo no coincide con su recibo. Compactación bloqueada." });
      }

      const sealPayload = {
        polla_id:pollaId,
        backup_receipt_id:receipt.id,
        created_by:String(params.adminName || "Admin"),
        backend_version:BACKEND_VERSION,
        backup_sha256:String(receipt.sha256),
        snapshot_sha256:current.snapshotSha256,
        snapshot_version:3,
        participant_count:current.counts.participants,
        match_count:current.counts.matches,
        prediction_count:current.counts.predictions,
        image_count:current.counts.images,
        snapshot_json:current.snapshot,
        standings_json:current.standings,
        status:"prepared",
      };
      const { data: existing, error: existingErr } = await supabase
        .from("polla_compaction_seals")
        .select("id,created_at")
        .eq("backup_receipt_id", receipt.id)
        .eq("snapshot_sha256", current.snapshotSha256)
        .eq("status", "prepared")
        .limit(1)
        .maybeSingle();
      if (existingErr) throw existingErr;
      let sealRow:any = existing;
      if (!sealRow) {
        const inserted = await supabase.from("polla_compaction_seals").insert(sealPayload).select("id,created_at").single();
        if (inserted.error) throw inserted.error;
        sealRow = inserted.data;
        await logAdminAction("prepareCompactionSeal", params.adminName, `Polla ${current.polla.number} · ${current.snapshotSha256.slice(0,12)}`);
      }
      return jsonOut({
        ok:true,
        seal:{
          id:sealRow.id,
          createdAt:sealRow.created_at,
          backupReceiptId:receipt.id,
          backupSha256:String(receipt.sha256),
          snapshotSha256:current.snapshotSha256,
          counts:{participants:current.counts.participants,matches:current.counts.matches,predictions:current.counts.predictions,images:current.counts.images},
          status:"prepared",
        },
      });
    }

    if (action === "getCompactionPrecheck") {
      const pollaId = String(params.pollaId || "").trim();
      const current = await loadPollaCompactionData_(pollaId);
      if (!current) return jsonOut({ ok:false, error:"Polla no encontrada." });

      const { data: receipt, error: receiptErr } = await supabase
        .from("polla_backup_receipts")
        .select("id, created_at, backend_version, object_path, sha256, size_bytes, participant_count, match_count, prediction_count, image_count, snapshot_sha256, snapshot_version, status")
        .eq("polla_id", pollaId)
        .eq("status", "verified")
        .order("created_at", { ascending:false })
        .limit(1)
        .maybeSingle();
      if (receiptErr) throw receiptErr;

      const checks:any[] = [];
      checks.push({ key:"finalized", label:"Polla finalizada", ok:current.polla.status === "finalizada" });
      checks.push({ key:"archived", label:"Polla archivada", ok:!!current.polla.is_archived });
      if (!receipt) {
        checks.push({ key:"backup", label:"Respaldo seguro verificado", ok:false, detail:"No existe un respaldo seguro." });
        return jsonOut({ ok:true, ready:false, needsNewBackup:true, checks, current:{ counts:current.counts, snapshotSha256:current.snapshotSha256 } });
      }

      const snapshotCompatible = Number(receipt.snapshot_version || 0) >= 2 && /^[0-9a-f]{64}$/.test(String(receipt.snapshot_sha256 || ""));
      checks.push({ key:"backup", label:"Respaldo seguro verificado", ok:true, detail:`${String(receipt.sha256||"").slice(0,12)}…` });
      checks.push({ key:"snapshot", label:"Respaldo compatible con compactación V2", ok:snapshotCompatible, detail:snapshotCompatible?"Huella de datos disponible":"Este respaldo es anterior a F2; genera uno nuevo." });

      let storageOk=false, hashOk=false, sizeOk=false;
      try {
        await ensureBackupBucket_();
        const downloaded = await supabase.storage.from(BACKUP_BUCKET).download(receipt.object_path);
        if (!downloaded.error && downloaded.data) {
          const bytes = new Uint8Array(await downloaded.data.arrayBuffer());
          storageOk = bytes.length > 0;
          sizeOk = Number(receipt.size_bytes) === bytes.byteLength;
          hashOk = (await sha256Hex_(bytes)) === String(receipt.sha256 || "");
        }
      } catch (_) {}
      checks.push({ key:"storage", label:"ZIP disponible en Storage privado", ok:storageOk });
      checks.push({ key:"zipSize", label:"Tamaño del ZIP coincide con el recibo", ok:sizeOk });
      checks.push({ key:"zipHash", label:"SHA-256 del ZIP intacto", ok:hashOk });

      const countChecks = [
        ["participants","Participantes",Number(receipt.participant_count),current.counts.participants],
        ["matches","Partidos",Number(receipt.match_count),current.counts.matches],
        ["predictions","Pronósticos",Number(receipt.prediction_count),current.counts.predictions],
        ["images","Imágenes respaldadas",Number(receipt.image_count),current.counts.images],
      ];
      for (const [key,label,backed,currentCount] of countChecks as any[]) {
        checks.push({ key, label, ok:backed===currentCount, detail:`Respaldo ${backed} · Actual ${currentCount}` });
      }
      const snapshotOk = snapshotCompatible && String(receipt.snapshot_sha256) === current.snapshotSha256;
      checks.push({ key:"dataHash", label:"Datos actuales idénticos al respaldo", ok:snapshotOk, detail:snapshotCompatible ? (snapshotOk?"Sin cambios desde el respaldo":"La Polla cambió después del respaldo.") : "Genera un respaldo nuevo en F2." });

      const ready = checks.every((c:any)=>c.ok);
      return jsonOut({
        ok:true, ready, needsNewBackup:!snapshotCompatible || !snapshotOk, checks,
        receipt:{ id:receipt.id, createdAt:receipt.created_at, sha256:receipt.sha256, snapshotSha256:receipt.snapshot_sha256 },
        current:{ counts:current.counts, snapshotSha256:current.snapshotSha256 },
      });
    }


    if (action === "compactPollaV2") {
      const pollaId=String(params.pollaId||"").trim();
      const sealId=String(params.sealId||"").trim();
      if(!pollaId || !sealId) return jsonOut({ok:false,error:"Faltan pollaId o sealId."},400);

      // Última verificación en Edge: el hash completo actual todavía debe ser
      // idéntico al sello. La RPC repite dentro de Postgres conteos + tabla final.
      const current=await loadPollaCompactionData_(pollaId);
      if(!current) return jsonOut({ok:false,error:"Polla no encontrada."});
      const {data:seal,error:sealErr}=await supabase
        .from("polla_compaction_seals")
        .select("id,status,snapshot_sha256,backup_receipt_id,snapshot_json")
        .eq("id",sealId).eq("polla_id",pollaId).maybeSingle();
      if(sealErr) throw sealErr;
      if(!seal || seal.status!=="prepared") return jsonOut({ok:false,error:"El sello no está preparado o ya fue consumido."});
      if(String(seal.snapshot_sha256||"")!==current.snapshotSha256){
        const sealedSemantic = await compactionSemanticSha256_(seal.snapshot_json || {});
        const currentSemantic = await compactionSemanticSha256_(current.snapshot || {});
        if (sealedSemantic !== currentSemantic) {
          const changed = await compactionChangedSections_(seal.snapshot_json || {}, current.snapshot || {});
          const labels:any={polla:"Polla",matches:"partidos",participants:"participantes",predictions:"pronósticos",referidos:"referidos",standings:"tabla final"};
          const detail=changed.map((x)=>labels[x]||x).join(", ");
          return jsonOut({ok:false,error:`Los datos deportivos sí cambiaron después de preparar el sello${detail?`: ${detail}`:""}. Genera respaldo y sello nuevos.`,changedSections:changed});
        }
        // Solo cambiaron metadatos técnicos/temporales. No invalida el sello.
        await logAdminAction("compactionSemanticMatch",String(params.adminName||"Admin"),`Polla ${current.polla.number} · diferencia técnica ignorada`);
      }

      const rpc=await supabase.rpc("compact_polla_v2_tico",{
        p_polla_id:pollaId,
        p_seal_id:sealId,
        p_admin_name:String(params.adminName||"Admin"),
      });
      if(rpc.error) return jsonOut({ok:false,error:rpc.error.message||"La transacción de compactación fue cancelada."});
      const out=rpc.data||{};
      await logAdminAction("compactPollaV2",String(params.adminName||"Admin"),`Polla ${current.polla.number} · sello ${sealId}`);
      return jsonOut({ok:true,...out});
    }

    if (action === "getStorageCleanupStatus") {
      const pollaId = String(params.pollaId || "").trim();
      const hist = await getCompactedHistory_(pollaId);
      if (!hist) return jsonOut({ok:true, compacted:false, cleaned:false, status:"not_compacted"});
      return jsonOut({
        ok:true,
        compacted:true,
        cleaned:!!hist.storage_cleaned_at,
        status:hist.storage_cleanup_status || (hist.storage_cleaned_at ? "completed" : "pending"),
        cleanedAt:hist.storage_cleaned_at || null,
        cleanedBy:hist.storage_cleaned_by || null,
        removedCount:Number(hist.storage_removed_count || 0),
        skippedCount:Number(hist.storage_skipped_count || 0),
        manifest:hist.storage_cleanup_manifest || null,
      });
    }

    if (action === "cleanupCompactedPollaStorage") {
      const pollaId = String(params.pollaId || "").trim();
      if (!pollaId) return jsonOut({ok:false,error:"Falta pollaId."},400);

      const { data: hist, error: histErr } = await supabase
        .from("polla_compacted_history")
        .select("id,polla_id,backup_receipt_id,snapshot_json,storage_cleaned_at,storage_cleanup_status")
        .eq("polla_id", pollaId)
        .maybeSingle();
      if (histErr) throw histErr;
      if (!hist) return jsonOut({ok:false,error:"La Polla todavía no tiene histórico compacto protegido."});
      if (hist.storage_cleaned_at) {
        return jsonOut({ok:true,alreadyCleaned:true,message:"Las imágenes de Storage ya fueron limpiadas para esta Polla."});
      }

      const { data: receipt, error: receiptErr } = await supabase
        .from("polla_backup_receipts")
        .select("id,status,object_path,sha256,size_bytes,image_count,manifest")
        .eq("id", hist.backup_receipt_id)
        .eq("polla_id", pollaId)
        .maybeSingle();
      if (receiptErr) throw receiptErr;
      if (!receipt || receipt.status !== "verified") {
        return jsonOut({ok:false,error:"El histórico compacto ya no tiene un respaldo seguro verificado vinculado."});
      }

      // F5 exige volver a descargar y verificar el ZIP completo ANTES de borrar
      // una sola imagen del bucket operativo.
      const verified = await verifySecureBackupZip_(receipt);
      if (!verified.ok) return jsonOut({ok:false,error:verified.error || "El ZIP seguro no superó la verificación."});

      const snapshot:any = hist.snapshot_json || {};
      const candidates:Array<{kind:string,id:string,url:string,path:string|null}> = [];
      const pollaSnap = snapshot?.polla || {};
      if (pollaSnap?.image_url) {
        const url=String(pollaSnap.image_url);
        candidates.push({kind:"polla",id:String(pollaSnap.id || pollaId),url,path:storageObjectPathFromPublicUrl_(url)});
      }
      for (const m of (Array.isArray(snapshot?.matches) ? snapshot.matches : [])) {
        if (!m?.image_url) continue;
        const url=String(m.image_url);
        candidates.push({kind:"partido",id:String(m.id || ""),url,path:storageObjectPathFromPublicUrl_(url)});
      }

      const managed = candidates.filter((x)=>!!x.path);
      const skipped = candidates.filter((x)=>!x.path);
      const uniquePaths = Array.from(new Set(managed.map((x)=>String(x.path))));

      const startMark = await supabase.from("polla_compacted_history").update({
        storage_cleanup_status:"running",
        storage_cleanup_manifest:{
          startedAt:new Date().toISOString(),
          verifiedBackupSha256:String(receipt.sha256),
          managedPaths:uniquePaths,
          skippedExternal:skipped.map((x)=>({kind:x.kind,id:x.id,url:x.url})),
        },
      }).eq("id",hist.id);
      if (startMark.error) throw startMark.error;

      try {
        if (uniquePaths.length) {
          // Storage remove admite lotes; fragmentamos por seguridad.
          for (let i=0;i<uniquePaths.length;i+=100) {
            const batch=uniquePaths.slice(i,i+100);
            const removed=await supabase.storage.from(STORAGE_BUCKET).remove(batch);
            if (removed.error) throw removed.error;
          }
        }

        // Si la portada estaba en tico-images ya fue eliminada; evitamos que la
        // Landing conserve una URL rota. El snapshot histórico permanece intacto.
        if (pollaSnap?.image_url && storageObjectPathFromPublicUrl_(pollaSnap.image_url)) {
          const pu=await supabase.from("pollas").update({image_url:null}).eq("id",pollaId);
          if (pu.error) throw pu.error;
        }

        const cleanedAt=new Date().toISOString();
        const finalManifest={
          completedAt:cleanedAt,
          verifiedBackupSha256:String(receipt.sha256),
          removedPaths:uniquePaths,
          skippedExternal:skipped.map((x)=>({kind:x.kind,id:x.id,url:x.url})),
          note:"Solo se eliminaron objetos del bucket tico-images pertenecientes a esta Polla. El ZIP privado y el snapshot protegido no se tocaron.",
        };
        const done=await supabase.from("polla_compacted_history").update({
          storage_cleaned_at:cleanedAt,
          storage_cleaned_by:String(params.adminName || "Admin"),
          storage_cleanup_status:"completed",
          storage_removed_count:uniquePaths.length,
          storage_skipped_count:skipped.length,
          storage_cleanup_manifest:finalManifest,
        }).eq("id",hist.id);
        if (done.error) throw done.error;

        await logAdminAction("cleanupCompactedPollaStorage",String(params.adminName||"Admin"),`Polla ${pollaId} · ${uniquePaths.length} objetos eliminados · ${skipped.length} externos conservados`);
        return jsonOut({
          ok:true,
          removedCount:uniquePaths.length,
          skippedCount:skipped.length,
          cleanedAt,
          backupSha256:String(receipt.sha256),
        });
      } catch (e) {
        await supabase.from("polla_compacted_history").update({
          storage_cleanup_status:"partial",
          storage_cleanup_manifest:{
            failedAt:new Date().toISOString(),
            verifiedBackupSha256:String(receipt.sha256),
            attemptedPaths:uniquePaths,
            error:String((e as any)?.message || e),
          },
        }).eq("id",hist.id);
        return jsonOut({ok:false,error:`La limpieza no pudo completarse: ${String((e as any)?.message || e)}. El ZIP seguro y el histórico protegido permanecen intactos.`});
      }
    }


    if (action === "getFinalArchiveAuditStatus") {
      const pollaId=String(params.pollaId||"").trim();
      const { data: hist, error }=await supabase.from("polla_compacted_history")
        .select("final_audit_at,final_audit_status,final_audit_report")
        .eq("polla_id",pollaId).maybeSingle();
      if(error) throw error;
      if(!hist) return jsonOut({ok:true,audited:false,status:"not_compacted"});
      return jsonOut({ok:true,audited:!!hist.final_audit_at,status:hist.final_audit_status||"pending",auditedAt:hist.final_audit_at||null,report:hist.final_audit_report||null});
    }

    if (action === "runFinalArchiveAudit") {
      const pollaId=String(params.pollaId||"").trim();
      if(!pollaId) return jsonOut({ok:false,error:"Falta pollaId."},400);
      const checks:any[]=[];
      const add=(key:string,label:string,ok:boolean,detail:string)=>checks.push({key,label,ok:!!ok,detail});

      const { data:polla, error:pollaErr }=await supabase.from("pollas").select("id,number,status,is_archived,image_url").eq("id",pollaId).maybeSingle();
      if(pollaErr) throw pollaErr;
      if(!polla) return jsonOut({ok:false,error:"Polla no encontrada."});
      add("polla","Polla cerrada y archivada",polla.status==="finalizada" && !!polla.is_archived,`Estado: ${polla.status || "—"} · archivada: ${polla.is_archived ? "sí" : "no"}`);

      const { data:hist, error:histErr }=await supabase.from("polla_compacted_history")
        .select("id,polla_id,backup_receipt_id,snapshot_json,standings_json,participant_count,match_count,prediction_count,image_count,storage_cleaned_at,storage_cleanup_status,storage_removed_count,storage_skipped_count")
        .eq("polla_id",pollaId).maybeSingle();
      if(histErr) throw histErr;
      if(!hist) return jsonOut({ok:false,error:"No existe histórico compacto protegido para esta Polla."});
      const snap:any=hist.snapshot_json||{};
      const snapParticipants=Array.isArray(snap.participants)?snap.participants:[];
      const snapMatches=Array.isArray(snap.matches)?snap.matches:[];
      const snapPredictions=Array.isArray(snap.predictions)?snap.predictions:[];
      const snapRefs=Array.isArray(snap.referidos)?snap.referidos:[];
      const snapStandings=Array.isArray(hist.standings_json)?hist.standings_json:(Array.isArray(snap.standings)?snap.standings:[]);
      const snapshotCountsOk=snapParticipants.length===Number(hist.participant_count||0) && snapMatches.length===Number(hist.match_count||0) && snapPredictions.length===Number(hist.prediction_count||0);
      add("history","Snapshot histórico completo",snapshotCountsOk,`${snapParticipants.length} participantes · ${snapMatches.length} partidos · ${snapPredictions.length} pronósticos · ${snapStandings.length} filas de tabla`);

      const [opParts,opMatches,opRefs]=await Promise.all([
        supabase.from("participantes").select("id",{count:"exact",head:true}).eq("polla_id",pollaId),
        supabase.from("partidos").select("id",{count:"exact",head:true}).eq("polla_id",pollaId),
        supabase.from("referidos").select("id",{count:"exact",head:true}).eq("polla_id",pollaId),
      ]);
      for(const r of [opParts,opMatches,opRefs]) if(r.error) throw r.error;
      const mids=snapMatches.map((m:any)=>m?.id).filter(Boolean);
      let residualPreds=0;
      if(mids.length){
        const pr=await supabase.from("pronosticos").select("id",{count:"exact",head:true}).in("partido_id",mids);
        if(pr.error) throw pr.error; residualPreds=Number(pr.count||0);
      }
      const residual=Number(opParts.count||0)+Number(opMatches.count||0)+Number(opRefs.count||0)+residualPreds;
      add("operational","Filas pesadas fuera de tablas operativas",residual===0,`Restantes: ${Number(opParts.count||0)} participantes · ${Number(opMatches.count||0)} partidos · ${residualPreds} pronósticos · ${Number(opRefs.count||0)} referidos`);

      const { data:receipt, error:receiptErr }=await supabase.from("polla_backup_receipts")
        .select("id,status,object_path,sha256,size_bytes,image_count,manifest")
        .eq("id",hist.backup_receipt_id).eq("polla_id",pollaId).maybeSingle();
      if(receiptErr) throw receiptErr;
      let zipOk=false, zipDetail="No existe recibo de respaldo verificado.";
      if(receipt && receipt.status==="verified"){
        const verified=await verifySecureBackupZip_(receipt);
        zipOk=!!verified.ok;
        zipDetail=zipOk?`ZIP íntegro · SHA-256 ${String(receipt.sha256||"").slice(0,12)}… · ${Number(receipt.size_bytes||0)} bytes`:(verified.error||"El ZIP no superó la verificación.");
      }
      add("backup","ZIP seguro íntegro",zipOk,zipDetail);

      const storageOk=hist.storage_cleanup_status==="completed" && !!hist.storage_cleaned_at;
      add("storage","Limpieza de imágenes terminada",storageOk,storageOk?`${Number(hist.storage_removed_count||0)} archivo(s) operativos eliminados · ${Number(hist.storage_skipped_count||0)} externo(s) conservados`:`Estado: ${hist.storage_cleanup_status||"pendiente"}`);

      const { data:ledger, error:ledgerErr }=await supabase.from("polla_yearly_rollup_ledger").select("polla_id,applied_at").eq("polla_id",pollaId).maybeSingle();
      if(ledgerErr) throw ledgerErr;
      add("yearly","Arrastre anual protegido",!!ledger,ledger?`Registrado ${ledger.applied_at?new Date(ledger.applied_at).toISOString():""}`:"No existe registro de traspaso anual para esta Polla.");

      const standingsOk=snapStandings.length>0 || Number(hist.participant_count||0)===0;
      add("standings","Tabla final disponible",standingsOk,standingsOk?`${snapStandings.length} registro(s) conservados en histórico.`:"La tabla final no está disponible en el snapshot.");

      const passed=checks.every((c:any)=>c.ok);
      const auditedAt=new Date().toISOString();
      const report={version:"V25G2",pollaId,pollaNumber:polla.number,passed,checks};
      const saved=await supabase.from("polla_compacted_history").update({final_audit_at:auditedAt,final_audit_status:passed?"passed":"failed",final_audit_report:report}).eq("id",hist.id);
      if(saved.error) throw saved.error;
      await logAdminAction("runFinalArchiveAudit",String(params.adminName||"Admin"),`Polla ${polla.number} · ${passed?"aprobada":"con observaciones"}`);
      return jsonOut({ok:true,audited:true,status:passed?"passed":"failed",auditedAt,report});
    }

    if (action === "createSecurePollaBackup") {
      const pollaId = String(params.pollaId || "").trim();
      const { data: polla, error: pollaErr } = await supabase
        .from("pollas")
        .select("*")
        .eq("id", pollaId)
        .maybeSingle();
      if (pollaErr) throw pollaErr;
      if (!polla) return jsonOut({ ok: false, error: "Polla no encontrada." });
      if (polla.status !== "finalizada" || !polla.is_archived) {
        return jsonOut({ ok: false, error: "El respaldo seguro para compactación solo se habilita cuando la Polla está finalizada y archivada." });
      }

      const compactionData = await loadPollaCompactionData_(pollaId);
      if (!compactionData) return jsonOut({ ok:false, error:"Polla no encontrada." });
      const { matches, participants, refs, predictions, standings, snapshotSha256 } = compactionData;

      const JSZip = await getJSZip_();
      const zip = new JSZip();
      const exportedAt = new Date().toISOString();
      const images: Array<{kind:string,id:string,path:string,sourceUrl:string}> = [];

      if (polla.image_url) {
        const img = await fetchBackupImage_(String(polla.image_url));
        const path = `images/polla/polla.${extFromContentType_(img.contentType)}`;
        zip.file(path, img.bytes);
        images.push({ kind: "polla", id: String(polla.id), path, sourceUrl: String(polla.image_url) });
      }
      for (const m of matches) {
        if (!m.image_url) continue;
        const img = await fetchBackupImage_(String(m.image_url));
        const path = `images/partidos/${safeFilePart_(m.match_number)}-${safeFilePart_(m.id)}.${extFromContentType_(img.contentType)}`;
        zip.file(path, img.bytes);
        images.push({ kind: "partido", id: String(m.id), path, sourceUrl: String(m.image_url) });
      }

      const counts = {
        participants: participants.length,
        matches: matches.length,
        predictions: predictions.length,
        referrals: refs.length,
        images: images.length,
      };
      const manifest = {
        format: "LaPollaTICO-secure-backup",
        version: 1,
        exportedAt,
        backendVersion: BACKEND_VERSION,
        pollaId: polla.id,
        pollaNumber: polla.number,
        counts,
        snapshotVersion: 2,
        snapshotSha256,
        images: images.map(({kind,id,path})=>({kind,id,path})),
        note: "ZIP autocontenido: JSON + imágenes reales. No incluye hashes de PIN, respuestas secretas ni códigos de activación.",
      };
      const backup = {
        ok: true,
        formatVersion: 1,
        exportedAt,
        manifest,
        polla,
        matches,
        participants,
        predictions,
        referidos: refs,
        standings,
      };
      zip.file("manifest.json", JSON.stringify(manifest, null, 2));
      zip.file("backup.json", JSON.stringify(backup, null, 2));
      const zipBytes = await zip.generateAsync({ type: "uint8array", compression: "DEFLATE", compressionOptions: { level: 6 } });
      const sha256 = await sha256Hex_(zipBytes);
      const stamp = exportedAt.replace(/[:.]/g, "-");
      const objectPath = `pollas/${safeFilePart_(pollaId)}/polla-${safeFilePart_(polla.number)}-${stamp}-${sha256.slice(0,12)}.zip`;

      await ensureBackupBucket_();
      const upload = await supabase.storage.from(BACKUP_BUCKET).upload(objectPath, zipBytes, {
        contentType: "application/zip",
        upsert: false,
        cacheControl: "3600",
      });
      if (upload.error) throw upload.error;

      const receiptPayload = {
        polla_id: pollaId,
        created_by: String(params.adminName || "Admin"),
        backend_version: BACKEND_VERSION,
        object_path: objectPath,
        sha256,
        size_bytes: zipBytes.byteLength,
        participant_count: counts.participants,
        match_count: counts.matches,
        prediction_count: counts.predictions,
        image_count: counts.images,
        snapshot_sha256: snapshotSha256,
        snapshot_version: 2,
        manifest,
        status: "verified",
      };
      const receiptInsert = await supabase.from("polla_backup_receipts").insert(receiptPayload).select("id, created_at").single();
      if (receiptInsert.error) {
        await supabase.storage.from(BACKUP_BUCKET).remove([objectPath]);
        throw receiptInsert.error;
      }
      const signed = await supabase.storage.from(BACKUP_BUCKET).createSignedUrl(objectPath, 600, { download: true });
      if (signed.error) throw signed.error;
      await logAdminAction("securePollaBackup", String(params.adminName || "Admin"), `Polla ${polla.number} · ${sha256.slice(0,12)} · ${zipBytes.byteLength} bytes`);
      return jsonOut({
        ok: true,
        receipt: { id: receiptInsert.data.id, createdAt: receiptInsert.data.created_at, sha256, sizeBytes: zipBytes.byteLength, counts },
        signedUrl: signed.data?.signedUrl || "",
      });
    }

    if (
      action ===
      "getPollaBackup"
    ) {
      const pollaId=String(params.pollaId||"").trim();
      const {data:polla,error:pollaErr}=await supabase.from("pollas").select("*").eq("id",pollaId).maybeSingle();
      if(pollaErr) throw pollaErr;
      if(!polla) return jsonOut({ok:false,error:"Polla no encontrada."});
      const [matches,participants,refs] = await Promise.all([
        fetchAllPages<any>((from,to)=>supabase.from("partidos").select("*").eq("polla_id",pollaId).range(from,to)),
        fetchAllPages<any>((from,to)=>supabase.from("participantes").select("*, jugadores(name)").eq("polla_id",pollaId).range(from,to)),
        fetchAllPages<any>((from,to)=>supabase.from("referidos").select("*").eq("polla_id",pollaId).range(from,to)),
      ]);
      const ids=matches.map((m:any)=>m.id);
      const predictions=ids.length ? await fetchAllPages<any>((from,to)=>supabase.from("pronosticos").select("*, jugadores(name)").in("partido_id",ids).range(from,to)) : [];
      return jsonOut({ok:true,version:2,exportedAt:new Date().toISOString(),polla,matches,participants,predictions,referidos:refs});
    }

    if (
      action ===
      "getGlobalBackup"
    ) {
      // Backup realmente completo: paginamos todas las tablas para no quedar
      // cortados por el límite REST de Supabase (normalmente 1000 filas).
      const [j,pollas,partidos,participantes,pronosticos,g,b,t,logs,refs,identityEvents,historyErasures] = await Promise.all([
        fetchAllPages<any>((from,to)=>supabase.from("jugadores").select("id, name, name_key, created_at").range(from,to)),
        fetchAllPages<any>((from,to)=>supabase.from("pollas").select("*").range(from,to)),
        fetchAllPages<any>((from,to)=>supabase.from("partidos").select("*").range(from,to)),
        fetchAllPages<any>((from,to)=>supabase.from("participantes").select("*").range(from,to)),
        fetchAllPages<any>((from,to)=>supabase.from("pronosticos").select("*").range(from,to)),
        fetchAllPages<any>((from,to)=>supabase.from("ganadores").select("id, name, wins").range(from,to)),
        fetchAllPages<any>((from,to)=>supabase.from("tabla_acumulada_base").select("id, jugador_id, name, name_key, base_points, base_matches_scored, base_exact_count, base_mvp_count").range(from,to)),
        fetchAllPages<any>((from,to)=>supabase.from("temporadas").select("*").range(from,to)),
        fetchAllPages<any>((from,to)=>supabase.from("admin_log").select("*").range(from,to)),
        fetchAllPages<any>((from,to)=>supabase.from("referidos").select("*").range(from,to)),
        fetchAllPages<any>((from,to)=>supabase.from("identity_events").select("*").range(from,to)),
        fetchAllPages<any>((from,to)=>supabase.from("player_history_erasure").select("*").range(from,to)),
      ]);
      return jsonOut({
        version: 4,
        exportedAt: new Date().toISOString(),
        note: "Backup funcional completo sin hashes de PIN, respuestas secretas ni códigos de activación.",
        jugadores:j, pollas, partidos, participantes, pronosticos,
        ganadores:g, tablaAcumuladaBase:b, temporadas:t,
        adminLog:logs, referidos:refs, identityEvents, playerHistoryErasure:historyErasures,
      });
    }

    if (
      action ===
      "closeSeason"
    ) {
      const seasonLabel =
        String(
          params.seasonLabel ||
            "",
        ).trim() ||
        (
          "Temporada cerrada " +
          new Date()
            .toISOString()
            .slice(0, 10)
        );

      const seasonStart = await getSeasonStart();
      const { data: openPollas = [], error: openErr } = await supabase
        .from("pollas")
        .select("id, number, status")
        .gte("season_started_at", seasonStart)
        .neq("status", "finalizada");
      if (openErr) throw openErr;
      if (openPollas.length) {
        return jsonOut({ ok:false, error:`No puedes cerrar la temporada: hay ${openPollas.length} Polla(s) aún sin finalizar.`, openPollas });
      }

      const { data: pendingMatches = [], error: pmErr } = await supabase
        .from("partidos")
        .select("id, match_number, polla_id, pollas!inner(season_started_at)")
        .eq("is_canceled", false)
        .eq("result_submitted", false)
        .gte("pollas.season_started_at", seasonStart);
      if (pmErr) throw pmErr;
      if (pendingMatches.length) {
        return jsonOut({ ok:false, error:`No puedes cerrar la temporada: quedan ${pendingMatches.length} partido(s) sin resultado.`, pendingMatches });
      }

      const finalStandings =
        await computeYearlyStandings();

      const qualifiers =
        computeFreeContestQualifiers(
          finalStandings,
        );

      const qualifiedNames =
        finalStandings
          .filter(
            (s: any) =>
              !!qualifiers
                .qualifiedKeys[
                  normalizeName(
                    s.name,
                  )
                ],
          )
          .map(
            (s: any) =>
              s.name,
          );

      const {
        error,
      } =
        await supabase
          .from("temporadas")
          .insert({
            season_label:
              seasonLabel,

            closed_at:
              new Date()
                .toISOString(),

            closed_by:
              String(
                params.adminName ||
                  "Admin",
              ).trim(),

            total_participants:
              finalStandings.length,

            qualified_count:
              qualifiers
                .qualifiedCount,

            standings_json:
              finalStandings,

            qualified_names:
              qualifiedNames,
          });

      if (error) throw error;

      // Igual que Code.gs:
      // al cerrar temporada se vacía el arrastre.
      const clearBase =
        await supabase
          .from(
            "tabla_acumulada_base",
          )
          .delete()
          .not(
            "name_key",
            "is",
            null,
          );

      if (clearBase.error) {
        throw clearBase.error;
      }

      return jsonOut({
        ok: true,
        seasonLabel,
        totalParticipants:
          finalStandings.length,
        qualifiedCount:
          qualifiers
            .qualifiedCount,
      });
    }

    if (
      action ===
      "clearSeasonData"
    ) {
      // H4.2: "Vaciar temporada" pasa a ser LIMPIEZA SEGURA.
      // Las Pollas compactadas conservan su fila mínima porque es el ancla FK
      // de snapshots, respaldos, sellos y auditoría. Solo limpiamos residuos
      // operativos de la última temporada cerrada.
      const { data:lastSeason, error:seasonErr } = await supabase
        .from("temporadas")
        .select("id, closed_at")
        .order("closed_at", { ascending:false })
        .limit(1)
        .maybeSingle();
      if (seasonErr) throw seasonErr;
      if (!lastSeason) {
        return jsonOut({
          ok:false,
          error:'Todavía no has cerrado ninguna temporada. Usa "🏁 Cerrar Temporada" antes de limpiar.',
        });
      }

      const { data:previousSeason, error:prevErr } = await supabase
        .from("temporadas")
        .select("closed_at")
        .lt("closed_at", lastSeason.closed_at)
        .order("closed_at", { ascending:false })
        .limit(1)
        .maybeSingle();
      if (prevErr) throw prevErr;
      const periodStart = previousSeason?.closed_at || "1970-01-01T00:00:00Z";

      const { data:finalizadas = [], error:pErr } = await supabase
        .from("pollas")
        .select("id, number, is_archived, compacted_at, season_started_at")
        .eq("status", "finalizada")
        .gte("season_started_at", periodStart)
        .lte("season_started_at", lastSeason.closed_at);
      if (pErr) throw pErr;

      if (!finalizadas.length) {
        return jsonOut({
          ok:true,
          pollasProtected:0,
          matchesDeleted:0,
          predictionsDeleted:0,
          participantsDeleted:0,
          referralsDeleted:0,
        });
      }

      const unprotected = finalizadas.filter((p:any)=>!p.compacted_at);
      if (unprotected.length) {
        return jsonOut({
          ok:false,
          error:`No se puede limpiar todavía: ${unprotected.length} Polla(s) de la temporada cerrada aún no están compactadas/protegidas.`,
          unprotectedPollas:unprotected.map((p:any)=>({id:p.id,number:p.number})),
        });
      }

      const ids = finalizadas.map((p:any)=>p.id);

      // Verificación adicional: cada cabecera compactada debe tener su snapshot.
      const histories = await fetchAllPages<any>((from,to)=>supabase
        .from("polla_compacted_history")
        .select("polla_id")
        .in("polla_id", ids)
        .range(from,to));
      const historyIds = new Set((histories || []).map((h:any)=>String(h.polla_id)));
      const missingHistory = finalizadas.filter((p:any)=>!historyIds.has(String(p.id)));
      if (missingHistory.length) {
        return jsonOut({
          ok:false,
          error:`Limpieza cancelada: ${missingHistory.length} Polla(s) marcan compactación pero no tienen snapshot histórico verificable.`,
          missingHistoryPollas:missingHistory.map((p:any)=>({id:p.id,number:p.number})),
        });
      }

      const matches = await fetchAllPages<any>((from,to)=>supabase
        .from("partidos")
        .select("id,polla_id")
        .in("polla_id", ids)
        .range(from,to));
      const matchIds = matches.map((m:any)=>m.id);

      let predictionsDeleted = 0;
      if (matchIds.length) {
        const predictionRows = await fetchAllPages<any>((from,to)=>supabase
          .from("pronosticos")
          .select("id")
          .in("partido_id", matchIds)
          .range(from,to));
        predictionsDeleted = predictionRows.length;
        if (predictionRows.length) {
          const d = await supabase.from("pronosticos").delete().in("id", predictionRows.map((x:any)=>x.id));
          if (d.error) throw d.error;
        }
      }

      const [participantsRows, referralRows] = await Promise.all([
        fetchAllPages<any>((from,to)=>supabase.from("participantes").select("id").in("polla_id",ids).range(from,to)),
        fetchAllPages<any>((from,to)=>supabase.from("referidos").select("id").in("polla_id",ids).range(from,to)),
      ]);

      if (referralRows.length) {
        const d = await supabase.from("referidos").delete().in("id", referralRows.map((x:any)=>x.id));
        if (d.error) throw d.error;
      }
      if (participantsRows.length) {
        const d = await supabase.from("participantes").delete().in("id", participantsRows.map((x:any)=>x.id));
        if (d.error) throw d.error;
      }
      if (matches.length) {
        const d = await supabase.from("partidos").delete().in("id", matchIds);
        if (d.error) throw d.error;
      }

      await logAdminAction(
        "clearSeasonData",
        String(params.adminName || "Admin"),
        `Limpieza segura · ${ids.length} Pollas protegidas conservadas · residuos: ${matches.length} partidos, ${predictionsDeleted} pronósticos, ${participantsRows.length} participantes, ${referralRows.length} referidos`,
      );

      return jsonOut({
        ok:true,
        pollasProtected:ids.length,
        matchesDeleted:matches.length,
        predictionsDeleted,
        participantsDeleted:participantsRows.length,
        referralsDeleted:referralRows.length,
      });
    }

    if (
      action ===
      "archivePolla"
    ) {
      const id =
        String(
          params.id || "",
        );

      const polla =
        await getPollaRow(id);

      if (!polla) {
        return jsonOut({
          ok: false,
          error:
            "Polla no encontrada.",
        });
      }

      if (
        polla.status !==
        "finalizada"
      ) {
        return jsonOut({
          ok: false,
          error:
            "Solo se pueden archivar Pollas ya finalizadas.",
        });
      }

      if (
        polla.is_archived
      ) {
        return jsonOut({
          ok: false,
          error:
            "Esta Polla ya está archivada.",
        });
      }

      const { error } =
        await supabase
          .from("pollas")
          .update({
            is_archived: true,
          })
          .eq("id", id);

      if (error) throw error;

      return jsonOut({
        ok: true,
      });
    }

    if (
      action ===
      "desarchivarPolla"
    ) {
      const id =
        String(
          params.id || "",
        );

      const polla =
        await getPollaRow(id);

      if (!polla) {
        return jsonOut({
          ok: false,
          error:
            "Polla no encontrada.",
        });
      }

      if (polla.compacted_at) {
        return jsonOut({
          ok:false,
          error:"Esta Polla ya está compactada y protegida. No se puede desarchivar ni reabrir.",
        });
      }

      if (
        !polla.is_archived
      ) {
        return jsonOut({
          ok: false,
          error:
            "Esta Polla no está archivada.",
        });
      }

      const { error } =
        await supabase
          .from("pollas")
          .update({
            is_archived: false,
          })
          .eq("id", id);

      if (error) throw error;

      return jsonOut({
        ok: true,
      });
    }

    if (
      action ===
      "editArchivedPremios"
    ) {
      const id =
        String(
          params.id || "",
        );

      const polla =
        await getPollaRow(id);

      if (!polla) {
        return jsonOut({
          ok: false,
          error:
            "Polla no encontrada.",
        });
      }

      if (polla.compacted_at) {
        return jsonOut({
          ok:false,
          error:"Esta Polla ya está compactada y protegida. Los datos sellados no se pueden modificar.",
        });
      }

      if (
        !polla.is_archived
      ) {
        return jsonOut({
          ok: false,
          error:
            'Esta Polla no está archivada; usa "Guardar premios" normal.',
        });
      }

      const { error } =
        await supabase
          .from("pollas")
          .update({
            premio1:
              String(
                params.premio1 ||
                  "",
              ),

            premio2:
              String(
                params.premio2 ||
                  "",
              ),

            premio3:
              String(
                params.premio3 ||
                  "",
              ),
          })
          .eq("id", id);

      if (error) throw error;

      return jsonOut({
        ok: true,
      });
    }

    if (
      action ===
      "addPolla"
    ) {
      const number =
        String(
          params.number || "",
        ).trim();

      const status=String(params.status || 'proximamente').trim().toLowerCase();
      const startDateRaw=String(params.startDate || '').trim();
      const totalMatchesRaw=params.totalMatches;
      const totalMatches=totalMatchesRaw === '' || totalMatchesRaw === undefined || totalMatchesRaw === null
        ? 0 : intParam(totalMatchesRaw,-1);
      if (!number || number.length > 40) {
        return jsonOut({ok:false,error:"Número/identificador de Polla inválido."});
      }
      if (!['actual','proximamente'].includes(status)) {
        return jsonOut({ok:false,error:"Estado inicial de Polla inválido."});
      }
      if (startDateRaw && !validDateParam_(startDateRaw)) {
        return jsonOut({ok:false,error:"Fecha/hora de inicio inválida."});
      }
      if (totalMatches < 0 || totalMatches > 1000) {
        return jsonOut({ok:false,error:"Total de partidos inválido."});
      }

      const {
        data: dup,
        error: dupErr,
      } =
        await supabase
          .from("pollas")
          .select("id")
          .eq(
            "number",
            number,
          )
          .maybeSingle();

      if (dupErr) {
        throw dupErr;
      }

      if (dup) {
        return jsonOut({
          ok: false,
          error:
            `Ya existe una Polla con el número ${number}.`,
        });
      }

      let imageUrl = "";

      if (params.imageBase64) {
        imageUrl =
          await uploadImageBase64(
            params.imageBase64,
            params.imageMime,
            "pollas",
            crypto.randomUUID(),
          );
      }

      const {
        data,
        error,
      } =
        await supabase
          .from("pollas")
          .insert({
            number,

            status,

            start_date:
              startDateRaw || null,
            season_started_at:
              startDateRaw || new Date().toISOString(),

            premio1:
              String(
                params.premio1 ||
                  "",
              ),

            premio2:
              String(
                params.premio2 ||
                  "",
              ),

            premio3:
              String(
                params.premio3 ||
                  "",
              ),

            image_url:
              imageUrl ||
              null,

            is_free_polla:
              boolParam(
                params.isFreePolla,
              ),

            show_winners_live:
              boolParam(
                params.showWinnersLive,
              ),

            is_archived:
              false,

            total_matches: totalMatches,
          })
          .select("id")
          .single();

      if (error) {
        if (
          error.code ===
          "23505"
        ) {
          return jsonOut({
            ok: false,
            error:
              `Ya existe una Polla con el número ${number}.`,
          });
        }

        throw error;
      }

      return jsonOut({
        ok: true,
        id: data.id,
      });
    }

    if (
      action ===
      "editPolla"
    ) {
      const id =
        String(
          params.id || "",
        );

      const editable =
        await assertPollaEditable(
          id,
          true,
        );

      if (!editable.ok) {
        return jsonOut(
          editable,
        );
      }

      const previousStatus =
        editable.polla.status;

      const update:
        Record<string, any> =
        {};

      if (params.number !== undefined) {
        const n=String(params.number || '').trim();
        if(!n || n.length>40) return jsonOut({ok:false,error:'Número/identificador de Polla inválido.'});
      }
      if (params.status !== undefined) {
        const st=String(params.status || '').trim().toLowerCase();
        if(!['actual','proximamente','finalizada'].includes(st)) return jsonOut({ok:false,error:'Estado de Polla inválido.'});
      }
      if (params.startDate !== undefined && String(params.startDate || '').trim() && !validDateParam_(params.startDate)) {
        return jsonOut({ok:false,error:'Fecha/hora de inicio inválida.'});
      }
      if (params.totalMatches !== undefined && params.totalMatches !== '') {
        const tm=intParam(params.totalMatches,-1);
        if(tm<0 || tm>1000) return jsonOut({ok:false,error:'Total de partidos inválido.'});
      }

      if (
        params.number !==
        undefined
      ) {
        update.number =
          String(
            params.number,
          ).trim();
      }

      if (
        params.status !==
        undefined
      ) {
        update.status = String(params.status).trim().toLowerCase();
      }

      if (
        params.startDate !==
        undefined
      ) {
        update.start_date =
          params.startDate ||
          null;
      }

      if (
        params.premio1 !==
        undefined
      ) {
        if (String(params.premio1 || '').length > 300) return jsonOut({ok:false,error:'El texto del premio es demasiado largo.'});
        update.premio1 =
          String(
            params.premio1 ||
              "",
          );
      }

      if (
        params.premio2 !==
        undefined
      ) {
        if (String(params.premio2 || '').length > 300) return jsonOut({ok:false,error:'El texto del premio es demasiado largo.'});
        update.premio2 =
          String(
            params.premio2 ||
              "",
          );
      }

      if (
        params.premio3 !==
        undefined
      ) {
        if (String(params.premio3 || '').length > 300) return jsonOut({ok:false,error:'El texto del premio es demasiado largo.'});
        update.premio3 =
          String(
            params.premio3 ||
              "",
          );
      }

      if (
        params.isFreePolla !==
        undefined
      ) {
        update.is_free_polla =
          boolParam(
            params.isFreePolla,
          );
      }

      if (
        params.showWinnersLive !==
        undefined
      ) {
        update.show_winners_live =
          boolParam(
            params.showWinnersLive,
          );
      }

      if (
        params.totalMatches !==
        undefined
      ) {
        update.total_matches = params.totalMatches === '' ? 0 : intParam(params.totalMatches,0);
      }

      if (params.imageBase64) {
        update.image_url =
          await uploadImageBase64(
            params.imageBase64,
            params.imageMime,
            "pollas",
            id,
          );
      }

      if (update.number) {
        const {
          data: dup,
          error,
        } =
          await supabase
            .from("pollas")
            .select("id")
            .eq(
              "number",
              update.number,
            )
            .neq(
              "id",
              id,
            )
            .limit(1);

        if (error) throw error;

        if (dup?.length) {
          return jsonOut({
            ok: false,
            error:
              `Ya existe otra Polla con el número ${update.number}.`,
          });
        }
      }

      const becomingFinal = update.status === "finalizada" && previousStatus !== "finalizada";
      const reopeningFinal = previousStatus === "finalizada" && update.status !== undefined && update.status !== "finalizada";
      const statusChanging = update.status !== undefined && update.status !== previousStatus;

      if (statusChanging) {
        const metadataKeys=Object.keys(update).filter((k)=>k!=="status");
        if(metadataKeys.length){
          return jsonOut({ok:false,error:"Cambia el estado de la Polla por separado de sus otros datos."});
        }

        let addChampions:string[]=[];
        let removeChampions:string[]=[];
        if(becomingFinal){
          const standingsFinal=await computePollaStandingsForAdmin(id);
          if(standingsFinal.length && Number(standingsFinal[0].totalPoints)>0){
            const top=Number(standingsFinal[0].totalPoints);
            addChampions=standingsFinal.filter((x:any)=>Number(x.totalPoints)===top).map((x:any)=>String(x.name||"")).filter(Boolean);
          }
        }else if(reopeningFinal){
          const previousStandings=await computePollaStandingsForAdmin(id);
          if(previousStandings.length && Number(previousStandings[0].totalPoints)>0){
            const top=Number(previousStandings[0].totalPoints);
            removeChampions=previousStandings.filter((x:any)=>Number(x.totalPoints)===top).map((x:any)=>String(x.name||"")).filter(Boolean);
          }
        }

        const {data:transition,error:transitionError}=await supabase.rpc(
          "transition_polla_status_tico",
          {
            p_polla_id:id,
            p_new_status:update.status,
            p_add_champions:addChampions,
            p_remove_champions:removeChampions,
          },
        );
        if(transitionError) throw transitionError;
        if(!transition?.ok){
          if(transition?.error==="PENDING_MATCHES"){
            return jsonOut({ok:false,error:`No puedes finalizar: faltan ${Number(transition.pendingCount||0)} partido(s) por resolver o cancelar.`});
          }
          return jsonOut({ok:false,error:String(transition?.error||"No se pudo cambiar el estado de la Polla.")});
        }
        return jsonOut({ok:true,status:update.status});
      }

      const { error } =
        await supabase
          .from("pollas")
          .update(update)
          .eq("id", id);

      if (error) {
        if (
          error.code ===
          "23505"
        ) {
          return jsonOut({
            ok: false,
            error:
              `Ya existe otra Polla con el número ${update.number}.`,
          });
        }

        throw error;
      }



      return jsonOut({
        ok: true,
      });
    }

    if (
      action ===
      "deletePolla"
    ) {
      const id =
        String(
          params.id || "",
        );

      const polla =
        await getPollaRow(id);

      if (!polla) {
        return jsonOut({
          ok: true,
        });
      }

      if (polla.compacted_at) {
        return jsonOut({
          ok:false,
          error:"Esta Polla ya está compactada y protegida. Su cabecera histórica, snapshot y respaldos deben conservarse.",
        });
      }

      const keepPoints =
        boolParam(
          params.keepPoints,
        );

      const keepTitle =
        params.keepTitle ===
        undefined
          ? true
          : boolParam(
              params.keepTitle,
            );

      let standings:any[]=[];
      if(polla.status === "finalizada"){
        standings=await computePollaStandingsForAdmin(id);
      }
      const {data:deleted,error:deleteError}=await supabase.rpc(
        "delete_polla_with_options_tico",
        {
          p_polla_id:id,
          p_keep_points:keepPoints,
          p_keep_title:keepTitle,
          p_standings:standings,
        },
      );
      if(deleteError) throw deleteError;
      if(!deleted?.ok) return jsonOut({ok:false,error:String(deleted?.error||"No se pudo eliminar la Polla.")});
      return jsonOut({ok:true,...deleted});
    }

    // ------------------------------------------------------------------------
    // G1 — Gestión histórica de jugadores (solo Admin)
    // ------------------------------------------------------------------------
    if (action === "getHistoricalPlayersAdmin") {
      const [players, erased] = await Promise.all([
        fetchAllPages<any>((from,to)=>supabase.from("jugadores").select("id,name,created_at").order("name",{ascending:true}).range(from,to)),
        fetchAllPages<any>((from,to)=>supabase.from("player_history_erasure").select("player_id").range(from,to)),
      ]);
      const gone=new Set((erased||[]).map((x:any)=>String(x.player_id)));
      return jsonOut({ok:true,players:(players||[]).filter((p:any)=>!gone.has(String(p.id))).map((p:any)=>({id:p.id,name:p.name,createdAt:p.created_at}))});
    }

    if (action === "previewHistoricalPlayerDeletion") {
      const playerId=String(params.playerId||"").trim();
      const {data:player,error:pe}=await supabase.from("jugadores").select("id,name,name_key,created_at").eq("id",playerId).maybeSingle();
      if(pe) throw pe;
      if(!player) return jsonOut({ok:false,error:"Jugador no encontrado."});
      const [parts,preds,base,wins,seasons,histories]=await Promise.all([
        fetchAllPages<any>((from,to)=>supabase.from("participantes").select("polla_id").eq("jugador_id",playerId).range(from,to)),
        supabase.from("pronosticos").select("id",{count:"exact",head:true}).eq("jugador_id",playerId),
        fetchAllPages<any>((from,to)=>supabase.from("tabla_acumulada_base").select("base_points,base_matches_scored,base_exact_count,base_mvp_count").or(`jugador_id.eq.${playerId},name_key.eq.${player.name_key}`).range(from,to)),
        supabase.from("ganadores").select("wins").eq("name",player.name),
        fetchAllPages<any>((from,to)=>supabase.from("temporadas").select("standings_json,qualified_names").range(from,to)),
        fetchAllPages<any>((from,to)=>supabase.from("polla_compacted_history").select("polla_id,snapshot_json").range(from,to)),
      ]);
      if((preds as any).error) throw (preds as any).error;
      if((wins as any).error) throw (wins as any).error;
      const pollaIds=[...new Set((parts||[]).map((x:any)=>String(x.polla_id)).filter(Boolean))];
      let pollaRows:any[]=[];
      if(pollaIds.length){
        const r=await supabase.from("pollas").select("id,number,status,is_archived").in("id",pollaIds);
        if(r.error) throw r.error; pollaRows=r.data||[];
      }
      const active=pollaRows.filter((p:any)=>String(p.status)!=="finalizada");
      const key=normalizeName(player.name);
      let seasonCount=0;
      for(const s of seasons||[]){
        const st=Array.isArray(s.standings_json)?s.standings_json:[];
        const q=Array.isArray(s.qualified_names)?s.qualified_names:[];
        if(st.some((x:any)=>normalizeName(x?.name||"")===key)||q.some((n:any)=>normalizeName(String(n||""))===key)) seasonCount++;
      }
      let compactedCount=0;
      for(const h of histories||[]){
        const snap:any=h?.snapshot_json||{};
        const ps=Array.isArray(snap.participants)?snap.participants:[];
        const ss=Array.isArray(snap.standings)?snap.standings:[];
        if(ps.some((x:any)=>String(x?.jugador_id||"")===playerId)||ss.some((x:any)=>normalizeName(x?.name||"")===key)) compactedCount++;
      }
      const baseTotals=(base||[]).reduce((a:any,b:any)=>({
        points:a.points+Number(b.base_points||0),matches:a.matches+Number(b.base_matches_scored||0),exacts:a.exacts+Number(b.base_exact_count||0),mvps:a.mvps+Number(b.base_mvp_count||0)
      }),{points:0,matches:0,exacts:0,mvps:0});
      const titleCount=((wins as any).data||[]).reduce((n:number,x:any)=>n+Number(x.wins||0),0);
      return jsonOut({ok:true,player:{id:player.id,name:player.name,createdAt:player.created_at},
        activePollas:active.map((p:any)=>({id:p.id,number:p.number,status:p.status})),
        totals:{participations:(parts||[]).length,predictions:Number((preds as any).count||0),compactedPollas:compactedCount,seasons:seasonCount,titles:titleCount,...baseTotals},
        canDelete:active.length===0,
        note:"Los respaldos ZIP ya sellados no se reescriben; conservan la copia de auditoría original. En la app el historial pasa a mostrarse anonimizado."
      });
    }

    if (action === "deleteHistoricalPlayer") {
      const playerId=String(params.playerId||"").trim();
      const mode=String(params.mode||"anonymize").trim();
      if(!["anonymize","erase_visible"].includes(mode)) return jsonOut({ok:false,error:"Modo de eliminación inválido."},400);
      const rpc=await supabase.rpc("erase_player_history_identity_tico",{
        p_player_id:playerId,p_mode:mode,p_admin_name:String(params.adminName||"Admin")
      });
      if(rpc.error) return jsonOut({ok:false,error:rpc.error.message||"No se pudo eliminar la identidad histórica."});
      await logAdminAction("deleteHistoricalPlayer",String(params.adminName||"Admin"),`Jugador ${playerId} · modo ${mode}`);
      return jsonOut({ok:true,result:rpc.data});
    }

    if (
      action ===
      "addParticipants"
    ) {
      const pollaId =
        String(
          params.pollaId ||
            "",
        );

      const editable =
        await assertPollaEditable(
          pollaId,
        );

      if (!editable.ok) {
        return jsonOut(editable);
      }

      let names:
        any[] = [];

      try {
        names =
          Array.isArray(
            params.names,
          )
            ? params.names
            : JSON.parse(
                String(
                  params.names ||
                    "[]",
                ),
              );
      } catch (_) {
        names = [];
      }

      let added = 0;
      const activationCodes: Array<{name:string, code:string}> = [];

      // REGLA INTENCIONAL:
      // addParticipants es un override administrativo. El Admin puede agregar
      // manualmente a una Polla gratuita incluso a alguien no clasificado.
      // La restricción de clasificación sigue aplicándose al autorregistro.

      const seen =
        new Set<string>();

      for (const raw of names) {
        const name =
          cleanName(raw);

        const key =
          normalizeName(name);

        if (
          !name ||
          !key ||
          seen.has(key)
        ) {
          continue;
        }

        seen.add(key);

        let jugador =
          await findJugador(
            name,
          );

        if (!jugador) {
          const {
            data,
            error,
          } =
            await supabase
              .from("jugadores")
              .insert({
                name,
                name_key:
                  key,
                pin_hash:
                  null,
                failed_attempts:
                  0,
                security_answer_hash:
                  null,
              })
              .select(
                "id, name, name_key, pin_hash, failed_attempts, security_answer_hash, created_at",
              )
              .single();

          if (error) {
            if (
              error.code ===
              "23505"
            ) {
              jugador =
                await findJugador(
                  name,
                );
            } else {
              throw error;
            }
          } else {
            jugador = data;
            const activationCode = await setActivationCode(data.id, "FIRST");
            activationCodes.push({ name: data.name, code: activationCode });
          }
        }

        if (!jugador) {
          continue;
        }

        if (
          await findParticipant(
            pollaId,
            jugador.id,
          )
        ) {
          continue;
        }

        await ensureEnrolled(
          pollaId,
          jugador.id,
          "",
        );

        added++;
      }

      return jsonOut({
        ok: true,
        added,
        activationCodes,
      });
    }

    if (
      action ===
      "setParticipantPaid"
    ) {
      const pollaId =
        String(
          params.pollaId ||
            "",
        );

      const jugador =
        await findJugador(
          cleanName(
            params.name,
          ),
        );

      if (!jugador) {
        return jsonOut({
          ok: false,
          error:
            "Participante no encontrado.",
        });
      }

      const {
        data,
        error,
      } =
        await supabase
          .from(
            "participantes",
          )
          .update({
            paid:
              boolParam(
                params.paid,
              ),
          })
          .eq(
            "polla_id",
            pollaId,
          )
          .eq(
            "jugador_id",
            jugador.id,
          )
          .select("id");

      if (error) throw error;

      if (!data?.length) {
        return jsonOut({
          ok: false,
          error:
            "Participante no encontrado.",
        });
      }

      return jsonOut({
        ok: true,
      });
    }

    if (
      action ===
      "previewParticipantDeletion"
    ) {
      const pollaId = String(params.pollaId || "");
      const jugador = await findJugador(cleanName(params.name));
      if (!jugador) {
        return jsonOut({ ok:false, error:"Participante no encontrado." });
      }
      const part = await findParticipant(pollaId, jugador.id);
      if (!part) {
        return jsonOut({ ok:false, error:"Ese jugador no participa en esta Polla." });
      }
      const remainsHistorical = await willRemainHistoricalAfterPollaRemoval(jugador, pollaId);
      return jsonOut({
        ok:true,
        name:jugador.name,
        willDeleteGlobally:!remainsHistorical,
      });
    }

    if (
      action ===
      "deleteParticipantFull"
    ) {
      const pollaId =
        String(
          params.pollaId ||
            "",
        );

      const editable =
        await assertPollaEditable(
          pollaId,
        );

      if (!editable.ok) {
        return jsonOut(
          editable,
        );
      }

      const jugador =
        await findJugador(
          cleanName(
            params.name,
          ),
        );

      if (!jugador) {
        return jsonOut({
          ok: true,
        });
      }

      const {
        data: ms = [],
        error: mr,
      } =
        await supabase
          .from("partidos")
          .select(
            "id, result_submitted, actual_home, actual_away, is_star_match, is_canceled",
          )
          .eq(
            "polla_id",
            pollaId,
          );

      if (mr) throw mr;

      const mids =
        ms.map(
          (m) => m.id,
        );

      if (mids.length) {
        const d =
          await supabase
            .from(
              "pronosticos",
            )
            .delete()
            .eq(
              "jugador_id",
              jugador.id,
            )
            .in(
              "partido_id",
              mids,
            );

        if (d.error) {
          throw d.error;
        }
      }

      const d =
        await supabase
          .from(
            "participantes",
          )
          .delete()
          .eq(
            "polla_id",
            pollaId,
          )
          .eq(
            "jugador_id",
            jugador.id,
          );

      if (d.error) throw d.error;

      // La baja cambia el universo de pronósticos. Recalculamos los partidos
      // ya resueltos para que el bonus de exacto minoritario (<30%) y los
      // puntos de quienes siguen en la Polla queden consistentes.
      for (const m of ms) {
        if (
          m.is_canceled ||
          !m.result_submitted ||
          m.actual_home === null ||
          m.actual_away === null
        ) {
          continue;
        }

        await recalculateSubmittedMatchPoints(
          m.id,
          Number(m.actual_home),
          Number(m.actual_away),
          !!m.is_star_match,
        );
      }

      const cleanup = await cleanupOrphanPlayer(jugador);
      // Aunque la identidad global se borre, si este jugador había sido
      // invitado por otro, el referido histórico de esa Polla se conserva.
      return jsonOut({
        ok: true,
        deletedGlobally: cleanup.deletedGlobally,
      });
    }

    if (
      action ===
      "renameParticipant"
    ) {
      const pollaId =
        String(
          params.pollaId ||
            "",
        );

      const editable = await assertPollaEditable(pollaId);
      if (!editable.ok) return jsonOut(editable);

      const oldName =
        cleanName(
          params.oldName,
        );

      const newName =
        cleanName(
          params.newName,
        );

      if (!newName) {
        return jsonOut({
          ok: false,
          error:
            "Nombre inválido.",
        });
      }

      const jugador =
        await findJugador(
          oldName,
        );

      if (!jugador) {
        return jsonOut({
          ok: false,
          error:
            "Participante no encontrado.",
        });
      }

      const other =
        await findJugador(
          newName,
        );

      if (
        other &&
        other.id !==
          jugador.id
      ) {
        const inPolla =
          await findParticipant(
            pollaId,
            other.id,
          );

        return jsonOut({
          ok: false,
          error:
            inPolla
              ? `Ya existe un participante llamado ${newName} en esta Polla.`
              : `El nombre ${newName} ya pertenece a otra cuenta.`,
        });
      }

      const oldKey =
        normalizeName(
          oldName,
        );

      const newKey =
        normalizeName(
          newName,
        );

      const { error } =
        await supabase
          .from("jugadores")
          .update({
            name: newName,
            name_key:
              newKey,
          })
          .eq(
            "id",
            jugador.id,
          );

      if (error) throw error;

      // Si tenía arrastre histórico, renombrarlo con la identidad.
      const {
        data: baseOld,
        error: baseRead,
      } =
        await supabase
          .from(
            "tabla_acumulada_base",
          )
          .select(
            "base_points",
          )
          .eq(
            "name_key",
            oldKey,
          )
          .maybeSingle();

      if (baseRead) {
        throw baseRead;
      }

      if (
        baseOld &&
        oldKey !== newKey
      ) {
        const {
          data: baseNew,
          error: baseNewRead,
        } =
          await supabase
            .from(
              "tabla_acumulada_base",
            )
            .select(
              "base_points",
            )
            .eq(
              "name_key",
              newKey,
            )
            .maybeSingle();

        if (baseNewRead) {
          throw baseNewRead;
        }

        if (baseNew) {
          const u =
            await supabase
              .from(
                "tabla_acumulada_base",
              )
              .update({
                base_points:
                  Number(
                    baseNew
                      .base_points ||
                      0,
                  ) +
                  Number(
                    baseOld
                      .base_points ||
                      0,
                  ),
                name:
                  newName,
                jugador_id:
                  jugador.id,
              })
              .eq(
                "name_key",
                newKey,
              );

          if (u.error) {
            throw u.error;
          }

          const d =
            await supabase
              .from(
                "tabla_acumulada_base",
              )
              .delete()
              .eq(
                "name_key",
                oldKey,
              );

          if (d.error) {
            throw d.error;
          }
        } else {
          const u =
            await supabase
              .from(
                "tabla_acumulada_base",
              )
              .update({
                name:
                  newName,
                name_key:
                  newKey,
                jugador_id:
                  jugador.id,
              })
              .eq(
                "name_key",
                oldKey,
              );

          if (u.error) {
            throw u.error;
          }
        }
      }

      // Sincronizar Hall of Fame; si por alguna anomalía ya existía el nuevo
      // nombre, se fusionan victorias en vez de perderlas.
      const { data: oldWin, error: owErr } = await supabase.from("ganadores").select("id,wins").eq("name", oldName).maybeSingle();
      if (owErr) throw owErr;
      if (oldWin) {
        const { data: newWin, error: nwErr } = await supabase.from("ganadores").select("id,wins").eq("name", newName).maybeSingle();
        if (nwErr) throw nwErr;
        if (newWin && newWin.id !== oldWin.id) {
          const u = await supabase.from("ganadores").update({ wins:Number(newWin.wins||0)+Number(oldWin.wins||0) }).eq("id",newWin.id);
          if (u.error) throw u.error;
          const d = await supabase.from("ganadores").delete().eq("id",oldWin.id); if (d.error) throw d.error;
        } else {
          const u = await supabase.from("ganadores").update({ name:newName }).eq("id",oldWin.id); if (u.error) throw u.error;
        }
      }

      const { data: seasons = [], error: seErr } = await supabase.from("temporadas").select("id,standings_json,qualified_names");
      if (seErr) throw seErr;
      for (const s of seasons) {
        let changed=false;
        const standings = Array.isArray(s.standings_json) ? s.standings_json.map((x:any)=>{
          if (normalizeName(x?.name||"")===oldKey) { changed=true; return {...x,name:newName}; }
          return x;
        }) : s.standings_json;
        const qualified = Array.isArray(s.qualified_names) ? s.qualified_names.map((n:any)=>{
          if (normalizeName(String(n||""))===oldKey) { changed=true; return newName; }
          return n;
        }) : s.qualified_names;
        if (changed) { const u=await supabase.from("temporadas").update({standings_json:standings,qualified_names:qualified}).eq("id",s.id); if(u.error) throw u.error; }
      }
      const ev = await supabase.from("identity_events").insert({ polla_id:pollaId, old_jugador_id:jugador.id, new_jugador_id:jugador.id, old_name:oldName, new_name:newName, event_type:"GLOBAL_RENAME", admin_name:String(params.adminName||"Manolo") });
      if (ev.error) throw ev.error;

      return jsonOut({ ok:true });
    }

    if (
      action ===
      "splitParticipantIdentity"
    ) {
      const pollaId=String(params.pollaId||"");
      const oldName=cleanName(params.oldName);
      const newName=cleanName(params.newName);
      const editable=await assertPollaEditable(pollaId); if(!editable.ok) return jsonOut(editable);
      if(!newName) return jsonOut({ok:false,error:"Nombre nuevo inválido."});
      if(await findJugador(newName)) return jsonOut({ok:false,error:`El nombre ${newName} ya pertenece a otra identidad.`});
      const old=await findJugador(oldName); if(!old) return jsonOut({ok:false,error:"Participante no encontrado."});
      const participant=await findParticipant(pollaId,old.id); if(!participant) return jsonOut({ok:false,error:"Ese jugador no participa en esta Polla."});
      const {data:newJ,error:createErr}=await supabase.from("jugadores").insert({name:newName,name_key:normalizeName(newName),pin_hash:null,failed_attempts:0,security_answer_hash:null}).select("id,name").single();
      if(createErr) throw createErr;
      const activationCode=await setActivationCode(newJ.id,"SPLIT");
      const {data:ms=[],error:me}=await supabase.from("partidos").select("id").eq("polla_id",pollaId); if(me) throw me;
      const mids=ms.map((m:any)=>m.id);
      if(mids.length){const u=await supabase.from("pronosticos").update({jugador_id:newJ.id}).eq("jugador_id",old.id).in("partido_id",mids); if(u.error) throw u.error;}
      const pu=await supabase.from("participantes").update({jugador_id:newJ.id}).eq("id",participant.id); if(pu.error) throw pu.error;
      const r1=await supabase.from("referidos").update({invitado_jugador_id:newJ.id}).eq("polla_id",pollaId).eq("invitado_jugador_id",old.id); if(r1.error) throw r1.error;
      const r2=await supabase.from("referidos").update({invitador_jugador_id:newJ.id}).eq("polla_id",pollaId).eq("invitador_jugador_id",old.id); if(r2.error) throw r2.error;
      const ev=await supabase.from("identity_events").insert({polla_id:pollaId,old_jugador_id:old.id,new_jugador_id:newJ.id,old_name:old.name,new_name:newName,event_type:"SPLIT_FROM_POLLA",admin_name:String(params.adminName||"Manolo")}); if(ev.error) throw ev.error;
      const cleanup=await cleanupOrphanPlayer(old);
      return jsonOut({ok:true,newName,activationCode,oldIdentityDeleted:cleanup.deletedGlobally});
    }

    if (
      action ===
      "regenerateActivationCode"
    ) {
      const jugador=await findJugador(cleanName(params.name));
      if(!jugador) return jsonOut({ok:false,error:"Jugador no encontrado."});
      const code=await setActivationCode(jugador.id, jugador.activation_purpose || (jugador.pin_hash?"RESET":"FIRST"));
      return jsonOut({ok:true,activationCode:code});
    }

    if (
      action ===
      "resetPin"
    ) {
      const jugador=await findJugador(cleanName(params.name));
      if(!jugador) return jsonOut({ok:false,error:"No se encontró a esa persona en Jugadores."});
      const {error}=await supabase.from("jugadores").update({pin_hash:null,failed_attempts:0}).eq("id",jugador.id); if(error) throw error;
      const activationCode=await setActivationCode(jugador.id,"RESET");
      return jsonOut({ok:true,activationCode});
    }

    if (
      action ===
      "addMatch"
    ) {
      const pollaId =
        String(
          params.pollaId ||
            "",
        );

      const editable =
        await assertPollaEditable(
          pollaId,
        );

      if (!editable.ok) {
        return jsonOut(editable);
      }

      const matchNumber = intParam(params.matchNumber, -1);
      const home = String(params.home || "").trim();
      const away = String(params.away || "").trim();
      const closeAt = String(params.closeAt || "").trim();

      if (matchNumber <= 0) {
        return jsonOut({ ok:false, error:"Número de partido inválido. Debe ser mayor que 0." });
      }
      if (!home || !away) {
        return jsonOut({ ok:false, error:"Completa el equipo local y visitante." });
      }
      if (home.length > 80 || away.length > 80) {
        return jsonOut({ok:false,error:"El nombre de un equipo es demasiado largo."});
      }
      if (!validDateParam_(closeAt)) {
        return jsonOut({ ok:false, error:"Fecha/hora de cierre inválida." });
      }

      const {
        data: dup,
        error: de,
      } =
        await supabase
          .from("partidos")
          .select("id")
          .eq(
            "polla_id",
            pollaId,
          )
          .eq(
            "match_number",
            matchNumber,
          )
          .eq(
            "is_canceled",
            false,
          )
          .limit(1);

      if (de) throw de;

      if (dup?.length) {
        return jsonOut({
          ok: false,
          error:
            `Ya existe un Partido ${matchNumber} activo en esta Polla. Elimínalo o edítalo si quieres reemplazarlo.`,
        });
      }

      let imageUrl = "";

      if (params.imageBase64) {
        imageUrl =
          await uploadImageBase64(
            params.imageBase64,
            params.imageMime,
            "partidos",
            crypto.randomUUID(),
          );
      }

      const {
        data,
        error,
      } =
        await supabase
          .from("partidos")
          .insert({
            polla_id:
              pollaId,
            match_number:
              matchNumber,
            home,
            away,
            close_at:
              closeAt,
            image_url:
              imageUrl ||
              null,
            result_submitted:
              false,
            actual_home:
              null,
            actual_away:
              null,
            is_star_match:
              boolParam(
                params.isStarMatch,
              ),
            is_canceled:
              false,
            cancel_reason:
              null,
          })
          .select("id, polla_id, match_number, home, away, close_at, image_url, result_submitted, actual_home, actual_away, created_at, is_star_match, is_canceled, cancel_reason")
          .single();

      if (error) {
        if (
          error.code ===
          "23505"
        ) {
          return jsonOut({
            ok: false,
            error:
              `Ya existe un Partido ${matchNumber} activo en esta Polla. Elimínalo o edítalo si quieres reemplazarlo.`,
          });
        }

        throw error;
      }

      return jsonOut({
        ok: true,
        id: data.id,
        match: {
          id: data.id,
          pollaId: data.polla_id,
          matchNumber: data.match_number,
          home: data.home,
          away: data.away,
          closeAt: data.close_at,
          imageUrl: data.image_url || "",
          resultSubmitted: !!data.result_submitted,
          actualHome: data.actual_home,
          actualAway: data.actual_away,
          createdAt: data.created_at,
          isStarMatch: !!data.is_star_match,
          isCanceled: !!data.is_canceled,
          cancelReason: data.cancel_reason || "",
        },
      });
    }

    if (
      action ===
      "editMatch"
    ) {
      const id =
        String(
          params.id || "",
        );

      const {
        data: match,
        error: me,
      } =
        await supabase
          .from("partidos")
          .select("*")
          .eq("id", id)
          .maybeSingle();

      if (me) throw me;

      if (!match) {
        return jsonOut({
          ok: false,
          error:
            "Partido no encontrado.",
        });
      }

      const editable =
        await assertPollaEditable(
          match.polla_id,
        );

      if (!editable.ok) {
        return jsonOut(editable);
      }

      if (match.result_submitted) {
        return jsonOut({ ok:false, error:"Este partido ya tiene resultado. Corrige el resultado con la acción de resultado; no edites sus datos deportivos directamente." });
      }

      const currentCloseMs = new Date(match.close_at).getTime();
      const alreadyClosed = Number.isFinite(currentCloseMs) && Date.now() >= currentCloseMs;
      const wantsTeamsChange =
        (params.home !== undefined && String(params.home).trim() !== String(match.home || "").trim()) ||
        (params.away !== undefined && String(params.away).trim() !== String(match.away || "").trim());
      const wantsStarChange =
        params.isStarMatch !== undefined &&
        boolParam(params.isStarMatch) !== !!match.is_star_match;

      let predictionCount = 0;
      if (wantsTeamsChange || wantsStarChange) {
        const { count, error: countErr } = await supabase
          .from("pronosticos")
          .select("id", {count:"exact", head:true})
          .eq("partido_id", id);
        if (countErr) throw countErr;
        predictionCount = Number(count || 0);
      }

      if (wantsTeamsChange && predictionCount > 0) {
        return jsonOut({ok:false,error:"Este partido ya tiene pronósticos. No cambies los equipos; usa Cancelar y Reemplazar para preservar la integridad."});
      }
      if (wantsStarChange && predictionCount > 0) {
        return jsonOut({ok:false,error:"No se puede cambiar la condición de Partido Estrella después de recibir pronósticos."});
      }
      if (params.closeAt !== undefined && alreadyClosed && String(params.closeAt) !== String(match.close_at)) {
        return jsonOut({ok:false,error:"La hora de cierre de un partido que ya cerró no puede modificarse. Usa el flujo de cancelación/reemplazo si corresponde."});
      }

      const u: Record<string, any> = {};

      if (params.matchNumber !== undefined) {
        const nextMatchNumber = intParam(params.matchNumber, -1);
        if (nextMatchNumber <= 0) return jsonOut({ok:false,error:"Número de partido inválido. Debe ser mayor que 0."});
        u.match_number = nextMatchNumber;
      }

      if (params.home !== undefined) {
        const nextHome = String(params.home).trim();
        if (!nextHome) return jsonOut({ok:false,error:"El equipo local no puede quedar vacío."});
        if (nextHome.length>80) return jsonOut({ok:false,error:"El nombre del equipo local es demasiado largo."});
        u.home = nextHome;
      }

      if (params.away !== undefined) {
        const nextAway = String(params.away).trim();
        if (!nextAway) return jsonOut({ok:false,error:"El equipo visitante no puede quedar vacío."});
        if (nextAway.length>80) return jsonOut({ok:false,error:"El nombre del equipo visitante es demasiado largo."});
        u.away = nextAway;
      }

      if (params.closeAt !== undefined) {
        if (!validDateParam_(params.closeAt)) return jsonOut({ok:false,error:"Fecha/hora de cierre inválida."});
        u.close_at = String(params.closeAt);
      }

      if (
        params.isStarMatch !==
        undefined
      ) {
        u.is_star_match =
          boolParam(
            params.isStarMatch,
          );
      }

      if (params.imageBase64) {
        u.image_url =
          await uploadImageBase64(
            params.imageBase64,
            params.imageMime,
            "partidos",
            id,
          );
      }

      const { error } =
        await supabase
          .from("partidos")
          .update(u)
          .eq("id", id);

      if (error) {
        if (
          error.code ===
          "23505"
        ) {
          return jsonOut({
            ok: false,
            error:
              `Ya existe un Partido ${u.match_number} en esta Polla.`,
          });
        }

        throw error;
      }

      return jsonOut({
        ok: true,
      });
    }

    if (
      action ===
      "deleteMatch"
    ) {
      const id =
        String(
          params.id || "",
        );

      const {
        data: match,
        error: readError,
      } =
        await supabase
          .from("partidos")
          .select("polla_id, result_submitted")
          .eq("id", id)
          .maybeSingle();

      if (readError) {
        throw readError;
      }

      if (match) {
        const editable = await assertPollaEditable(match.polla_id);
        if (!editable.ok) return jsonOut(editable);
        if (match.result_submitted) {
          return jsonOut({ok:false,error:"Un partido con resultado no puede borrarse directamente. Corrige el resultado o utiliza el flujo correspondiente."});
        }
        const {count,error:pcErr}=await supabase.from("pronosticos").select("id",{count:"exact",head:true}).eq("partido_id",id);
        if(pcErr) throw pcErr;
        if((count||0)>0 && !boolParam(params.forceDeleteWithPredictions)){
          return jsonOut({ok:false,error:`Este partido tiene ${count} pronóstico(s). Se recomienda cancelar/reemplazar.`,requiresStrongConfirmation:true,predictionCount:count});
        }
      }

      let d =
        await supabase
          .from("pronosticos")
          .delete()
          .eq(
            "partido_id",
            id,
          );

      if (d.error) throw d.error;

      d =
        await supabase
          .from("partidos")
          .delete()
          .eq("id", id);

      if (d.error) throw d.error;

      return jsonOut({
        ok: true,
      });
    }

    if (
      action ===
      "cancelAndReplaceMatch"
    ) {
      const pollaId =
        String(
          params.pollaId ||
            "",
        );

      const editable =
        await assertPollaEditable(
          pollaId,
        );

      if (!editable.ok) {
        return jsonOut(editable);
      }

      const oldId =
        String(
          params.cancelMatchId ||
            "",
        );

      const {
        data: old,
        error: oe,
      } =
        await supabase
          .from("partidos")
          .select("*")
          .eq("id", oldId)
          .eq(
            "polla_id",
            pollaId,
          )
          .maybeSingle();

      if (oe) throw oe;

      if (!old) {
        return jsonOut({
          ok: false,
          error:
            "Partido a cancelar no encontrado.",
        });
      }

      if (
        old.result_submitted
      ) {
        return jsonOut({
          ok: false,
          error:
            "Este partido ya tiene un resultado cargado, no se puede cancelar. Si el resultado está mal, corrígelo en vez de cancelar el partido.",
        });
      }

      const newNum = intParam(params.newMatchNumber, -1);
      const newHome = String(params.newHome || "").trim();
      const newAway = String(params.newAway || "").trim();
      const newCloseAt = String(params.newCloseAt || "").trim();

      if (newNum <= 0) return jsonOut({ok:false,error:"Número del partido de reemplazo inválido."});
      if (!newHome || !newAway) return jsonOut({ok:false,error:"Completa los equipos del partido de reemplazo."});
      if (newHome.length>80 || newAway.length>80) return jsonOut({ok:false,error:"El nombre de un equipo de reemplazo es demasiado largo."});
      if (!validDateParam_(newCloseAt)) return jsonOut({ok:false,error:"Fecha/hora del partido de reemplazo inválida."});

      const {
        data: dup,
        error: de,
      } =
        await supabase
          .from("partidos")
          .select("id")
          .eq(
            "polla_id",
            pollaId,
          )
          .eq(
            "match_number",
            newNum,
          )
          .eq(
            "is_canceled",
            false,
          )
          .neq(
            "id",
            oldId,
          )
          .limit(1);

      if (de) throw de;

      if (dup?.length) {
        return jsonOut({
          ok: false,
          error:
            `Ya existe un Partido ${newNum} activo en esta Polla.`,
        });
      }

      let imageUrl = "";

      if (
        params.newImageBase64
      ) {
        imageUrl =
          await uploadImageBase64(
            params.newImageBase64,
            params.newImageMime,
            "partidos",
            crypto.randomUUID(),
          );
      }

      const up =
        await supabase
          .from("partidos")
          .update({
            is_canceled:
              true,
            cancel_reason:
              String(
                params.cancelReason ||
                  "Fuerza mayor",
              ).trim(),
          })
          .eq(
            "id",
            oldId,
          );

      if (up.error) {
        throw up.error;
      }

      const ins =
        await supabase
          .from("partidos")
          .insert({
            polla_id:
              pollaId,

            match_number:
              newNum,

            home:
              newHome,

            away:
              newAway,

            close_at:
              newCloseAt,

            image_url:
              imageUrl ||
              null,

            result_submitted:
              false,

            actual_home:
              null,

            actual_away:
              null,

            is_star_match:
              boolParam(
                params.newIsStar,
              ),

            is_canceled:
              false,

            cancel_reason:
              null,
          })
          .select("id")
          .single();

      if (ins.error) {
        // Rollback manual de la marca cancelada.
        await supabase
          .from("partidos")
          .update({
            is_canceled:
              old.is_canceled,
            cancel_reason:
              old.cancel_reason,
          })
          .eq(
            "id",
            oldId,
          );

        throw ins.error;
      }

      return jsonOut({
        ok: true,
        newId:
          ins.data.id,
      });
    }

    if (
      action ===
      "submitResult"
    ) {
      const id =
        String(
          params.id || "",
        );

      const actualHome =
        Number(
          params.actualHome,
        );

      const actualAway =
        Number(
          params.actualAway,
        );

      if (
        !Number.isInteger(
          actualHome,
        ) ||
        !Number.isInteger(
          actualAway,
        ) ||
        actualHome < 0 ||
        actualAway < 0
      ) {
        return jsonOut({
          ok: false,
          error:
            "Marcador final inválido.",
        });
      }

      const {
        data: match,
        error: me,
      } =
        await supabase
          .from("partidos")
          .select(
            "id, polla_id, close_at, result_submitted, is_canceled",
          )
          .eq("id", id)
          .maybeSingle();

      if (me) throw me;

      if (!match) {
        return jsonOut({
          ok: false,
          error:
            "Partido no encontrado.",
        });
      }

      if (
        match.is_canceled
      ) {
        return jsonOut({
          ok: false,
          error:
            "Este partido está cancelado.",
        });
      }

      const closeMs = new Date(match.close_at).getTime();
      if (!match.close_at || !Number.isFinite(closeMs)) {
        return jsonOut({ok:false,error:"Este partido no tiene una hora de cierre válida. Corrige el partido antes de cargar el resultado."});
      }
      if (Date.now() < closeMs) {
        return jsonOut({
          ok:false,
          error:"MATCH_NOT_CLOSED",
          closeAt:match.close_at,
          serverNow:new Date().toISOString(),
        });
      }

      const editable =
        await assertPollaEditable(
          match.polla_id,
        );

      if (!editable.ok) {
        return jsonOut(
          editable,
        );
      }

      const { data: atomicResult, error: atomicError } = await supabase.rpc(
        "submit_match_result_tico",
        {
          p_match_id:id,
          p_actual_home:actualHome,
          p_actual_away:actualAway,
        },
      );
      if (atomicError) throw atomicError;
      if (!atomicResult?.ok) {
        return jsonOut({
          ok:false,
          error:String(atomicResult?.error || "No se pudo guardar el resultado."),
          closeAt:atomicResult?.closeAt || match.close_at,
          serverNow:atomicResult?.serverNow || new Date().toISOString(),
        });
      }

      return jsonOut({
        ok:true,
        changedPredictions:Number(atomicResult.changedPredictions || 0),
      });
    }


    return jsonOut(
      {
        ok: false,
        error: "UNKNOWN_ACTION",
        action,
      },
      400,
    );
  } catch (err) {
    console.error(JSON.stringify({
      level: "error",
      requestId,
      action: requestAction || null,
      message: err instanceof Error ? err.message : String(err),
      stack: err instanceof Error ? err.stack : undefined,
      at: new Date().toISOString(),
    }));

    return jsonOut(
      {
        ok: false,
        error: "SERVER_ERROR",
        requestId,
      },
      500,
    );
  }
});
