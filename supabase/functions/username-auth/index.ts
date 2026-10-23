// Local proposal. Deploy only after independent security review and approval.
// This public endpoint never returns an account email and never logs request bodies.

const encoder = new TextEncoder();
const GENERIC_LOGIN_ERROR = 'Identifiant ou mot de passe incorrect.';
const GENERIC_RESET_MESSAGE = 'Si cet identifiant correspond à un compte, un message de récupération sera envoyé.';
const GENERIC_SERVICE_ERROR = 'Le service est momentanément indisponible. Réessayez plus tard.';
const MAX_BODY_BYTES = 8192;
const USERNAME_PATTERN = /^[A-Za-z][A-Za-z0-9._-]{2,31}$/;

function injectedKey(name: string): string {
  const raw = Deno.env.get(name) || '';
  if (!raw) return '';
  try {
    const keys = JSON.parse(raw);
    return typeof keys?.default === 'string' ? keys.default : '';
  } catch {
    return '';
  }
}

function getConfig() {
  const origins = (Deno.env.get('AUTH_ALLOWED_ORIGINS') || '')
    .split(',').map(value => value.trim()).filter(Boolean);
  return {
    url: (Deno.env.get('SUPABASE_URL') || '').replace(/\/$/, ''),
    publishableKey: injectedKey('SUPABASE_PUBLISHABLE_KEYS')
      || Deno.env.get('USERNAME_AUTH_PUBLISHABLE_KEY')
      || Deno.env.get('SUPABASE_ANON_KEY')
      || '',
    serviceRoleKey: injectedKey('SUPABASE_SECRET_KEYS')
      || Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')
      || '',
    rateLimitSecret: Deno.env.get('USERNAME_RATE_LIMIT_SECRET') || '',
    resetRedirectUrl: Deno.env.get('AUTH_PASSWORD_RESET_REDIRECT_URL') || '',
    origins
  };
}

function jsonResponse(body, status, origin) {
  const headers = new Headers({
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store, max-age=0',
    'Pragma': 'no-cache',
    'Vary': 'Origin'
  });
  if (origin) {
    headers.set('Access-Control-Allow-Origin', origin);
    headers.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
    headers.set('Access-Control-Allow-Headers', 'apikey, authorization, content-type, x-client-info');
    headers.set('Access-Control-Max-Age', '600');
  }
  return new Response(JSON.stringify(body), { status, headers });
}

function clientIp(request) {
  // The application limiter is a modest extra guard. Supabase Auth keeps its
  // own limits; missing proxy headers must not prevent a valid login.
  const cfIp = request.headers.get('cf-connecting-ip')?.trim();
  const forwarded = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim();
  return cfIp || forwarded || '';
}

function normalizeUsername(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

function hex(bytes) {
  return [...new Uint8Array(bytes)].map(value => value.toString(16).padStart(2, '0')).join('');
}

async function keyedFingerprint(secret, value) {
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  return hex(await crypto.subtle.sign('HMAC', key, encoder.encode(value)));
}

async function dummyEmail(action, username) {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(`${action}\u0000${username}`));
  return `unknown-${hex(digest).slice(0, 24)}@invalid.invalid`;
}

async function readJsonLimited(request) {
  const reader = request.body?.getReader();
  if (!reader) throw new Error('invalid_body');
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BODY_BYTES) {
        await reader.cancel();
        throw new Error('body_too_large');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return JSON.parse(new TextDecoder('utf-8', { fatal:true }).decode(bytes));
}

async function serviceRpc(config, functionName, payload) {
  const headers = {
    'apikey': config.serviceRoleKey,
    'Content-Type': 'application/json',
    'Accept': 'application/json'
  };
  // New sb_secret keys are not JWTs. Supabase rejects them if duplicated in
  // Authorization; the legacy service_role JWT still needs its Bearer header.
  if (!config.serviceRoleKey.startsWith('sb_secret_')) {
    headers.Authorization = `Bearer ${config.serviceRoleKey}`;
  }
  const response = await fetch(`${config.url}/rest/v1/rpc/${functionName}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(payload),
    cache: 'no-store'
  });
  if (!response.ok) throw new Error('private_rpc_failed');
  return response.json();
}

async function consumeRateLimit(config, username, ip) {
  if (!config.rateLimitSecret) throw new Error('optional_rate_limit_unavailable');
  const effectiveIp = ip || 'proxy-ip-unavailable';
  const ipHash = await keyedFingerprint(config.rateLimitSecret, `ip\u0000${effectiveIp}`);
  const accountIpHash = await keyedFingerprint(config.rateLimitSecret, `account\u0000${effectiveIp}\u0000${username}`);
  const result = await serviceRpc(config, 'organisation_consume_username_auth_attempt', {
    p_ip_bucket_hash: ipHash,
    p_account_ip_bucket_hash: accountIpHash
  });
  const row = Array.isArray(result) ? result[0] : result;
  if (!row || typeof row.allowed !== 'boolean') throw new Error('rate_limit_unavailable');
  return row;
}

async function resolveUsername(config, username) {
  const result = await serviceRpc(config, 'organisation_resolve_username_for_auth', { p_username:username });
  const row = Array.isArray(result) ? result[0] : result;
  if (!row || typeof row.user_id !== 'string' || typeof row.auth_email !== 'string') return null;
  return { userId:row.user_id, email:row.auth_email };
}

async function authPasswordGrant(config, email, password) {
  return fetch(`${config.url}/auth/v1/token?grant_type=password`, {
    method: 'POST',
    headers: { 'apikey':config.publishableKey, 'Content-Type':'application/json', 'Accept':'application/json' },
    body: JSON.stringify({ email, password }),
    cache: 'no-store'
  });
}

async function sendRecovery(config, email) {
  return fetch(`${config.url}/auth/v1/recover`, {
    method: 'POST',
    headers: { 'apikey':config.publishableKey, 'Content-Type':'application/json', 'Accept':'application/json' },
    body: JSON.stringify({ email, redirect_to:config.resetRedirectUrl }),
    cache: 'no-store'
  });
}

async function getConfirmedAuthUser(config, authorization) {
  const token = authorization?.match(/^Bearer\s+(.+)$/i)?.[1]?.trim();
  if (!token || token.length > 16384) return null;
  const response = await fetch(`${config.url}/auth/v1/user`, {
    method:'GET',
    headers:{ 'apikey':config.publishableKey, 'Authorization':`Bearer ${token}`, 'Accept':'application/json' },
    cache:'no-store'
  });
  if (!response.ok) return null;
  const user = await response.json();
  if (!user?.id || !user.email_confirmed_at) return null;
  return { id:user.id };
}

async function handleRequest(request) {
  const config = getConfig();
  const origin = request.headers.get('origin') || '';
  if (!origin || !config.origins.includes(origin)) return jsonResponse({ error:'Requête refusée.' }, 403, '');
  if (request.method === 'OPTIONS') return new Response(null, { status:204, headers: new Headers({
    'Access-Control-Allow-Origin':origin,
    'Access-Control-Allow-Methods':'POST, OPTIONS',
    'Access-Control-Allow-Headers':'apikey, authorization, content-type, x-client-info',
    'Access-Control-Max-Age':'600',
    'Vary':'Origin'
  }) });
  if (request.method !== 'POST') return jsonResponse({ error:'Méthode non autorisée.' }, 405, origin);
  if (!config.url || !config.publishableKey || !config.serviceRoleKey) {
    return jsonResponse({ error:GENERIC_SERVICE_ERROR }, 503, origin);
  }

  let body;
  try { body = await readJsonLimited(request); }
  catch { return jsonResponse({ error:'Requête invalide.' }, 400, origin); }
  const action = body?.action;
  const user