/*
  ARiA Odonto — Proxy seguro de APIs (Cloudflare Pages Function)
  Rota: /api  (qualquer POST para /api chega aqui)

  ═══════════════════════════════════════════════════════════════
  MUDANÇA DE SEGURANÇA (v16):
  Antes, o front-end falava DIRETO com Supabase/OpenRouter/Evolution
  usando chaves hardcoded no HTML (visíveis no DevTools de qualquer
  visitante). Agora TODO acesso passa por aqui. O proxy:

    1. Valida o Firebase ID Token enviado pelo front (garante que a
       pessoa está realmente logada e pega o UID real do token —
       nunca confia em um "user_id" que o cliente tente mandar).
    2. Usa a SERVICE_ROLE key do Supabase (nunca exposta ao browser),
       que ignora RLS — por isso o filtro por dono do dado é feito
       AQUI, no servidor, e não depende mais de policy do Postgres.
    3. As chaves de OpenRouter e Evolution também só são usadas aqui.

  Variáveis de ambiente — configure em:
  Cloudflare Dashboard → Workers & Pages → ariaclinicas
  → Settings → Environment Variables → Add variable

    SUPABASE_URL              = https://ahldwfaqfblhoqugrpbu.supabase.co
    SUPABASE_SERVICE_ROLE_KEY = eyJ...  (⚠️ a SERVICE ROLE, não a anon!
                                 pegue em Supabase → Project Settings →
                                 API → service_role secret)
    FIREBASE_PROJECT_ID       = id-do-seu-projeto-firebase
    OPENROUTER_KEY            = sk-or-v1-...
    EVOLUTION_URL             = https://sua-evolution.render.com
    EVOLUTION_KEY             = sua-chave-evolution

  ⚠️ IMPORTANTE: remova a variável SUPABASE_KEY (anon) antiga se ela
  ainda existir — ela não é mais usada e não deve ficar configurada
  por engano em nenhum lugar.
  ═══════════════════════════════════════════════════════════════
*/

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Content-Type': 'application/json',
};

function jsonErr(msg, status = 400) {
  return new Response(JSON.stringify({ error: msg }), { status, headers: corsHeaders });
}

// ──────────────────────────────────────────────────────────────
// Valida o Firebase ID Token usando o endpoint público do Google
// (não precisa do Firebase Admin SDK completo, só uma chamada REST
// que verifica assinatura, expiração e o project_id correto).
// Retorna o UID real, ou null se o token for inválido/expirado.
// ──────────────────────────────────────────────────────────────
// Cache em memória das chaves públicas do Google entre invocações do
// mesmo worker "quente" (reduz uma chamada de rede na maioria dos casos).
let _jwksCache = null;
let _jwksCacheExpiry = 0;

async function getGoogleJwks() {
  const now = Date.now();
  if (_jwksCache && now < _jwksCacheExpiry) return _jwksCache;

  // Endpoint oficial do Firebase/Google no formato JWK — importável
  // direto pelo WebCrypto, sem precisar parsear certificado X.509/ASN.1.
  const res = await fetch(
    'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com'
  );
  if (!res.ok) return null;
  const jwks = await res.json();
  _jwksCache = jwks;
  _jwksCacheExpiry = now + 5 * 60 * 1000; // 5 min
  return jwks;
}

async function verifyFirebaseToken(idToken, projectId) {
  if (!idToken || !projectId) return null;

  const parts = idToken.split('.');
  if (parts.length !== 3) return null;
  const [headerB64, payloadB64, sigB64] = parts;

  let header, payload;
  try {
    header = JSON.parse(base64UrlDecode(headerB64));
    payload = JSON.parse(base64UrlDecode(payloadB64));
  } catch (_) {
    return null;
  }

  // Checagens de validade do payload, conforme a documentação do
  // Firebase para verificação manual de ID Tokens.
  const now = Math.floor(Date.now() / 1000);
  if (!payload.exp || payload.exp < now) return null;
  if (!payload.iat || payload.iat > now + 60) return null; // tolerância de relógio
  if (payload.aud !== projectId) return null;
  if (payload.iss !== `https://securetoken.google.com/${projectId}`) return null;
  if (!payload.sub || typeof payload.sub !== 'string') return null;
  if (header.alg !== 'RS256') return null;

  const kid = header.kid;
  if (!kid) return null;

  const jwks = await getGoogleJwks();
  if (!jwks || !jwks.keys) return null;
  const jwk = jwks.keys.find(k => k.kid === kid);
  if (!jwk) return null;

  const valid = await verifySignatureRS256(`${headerB64}.${payloadB64}`, sigB64, jwk);
  if (!valid) return null;

  return payload.sub; // Firebase UID real e criptograficamente verificado
}

function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return atob(str);
}

async function verifySignatureRS256(signedData, sigB64, jwk) {
  try {
    const cryptoKey = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify']
    );
    const sig = base64UrlToBytes(sigB64);
    const data = new TextEncoder().encode(signedData);
    return await crypto.subtle.verify('RSASSA-PKCS1-v1_5', cryptoKey, sig, data);
  } catch (e) {
    return false;
  }
}

// ──────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────
function base64UrlToBytes(b64url) {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
  const bin = atob(b64 + pad);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// Tabelas que usam "usuario_id" em vez de "user_id" (caso especial: contatos)
const USER_COL_OVERRIDE = {
  contatos: 'usuario_id',
};

// Lista de tabelas que o proxy tem permissão de tocar — qualquer tabela
// fora desta lista é recusada (evita que alguém injete um nome de
// tabela arbitrário no payload).
const ALLOWED_TABLES = new Set([
  'odonto_pacientes',
  'odonto_consultas',
  'odonto_prontuarios',
  'odonto_financeiro',
  'odonto_doutores',
  'odonto_clinicas',
  'contatos',
]);

async function handleRequest(context) {
  const { request, env } = context;

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonErr('Body inválido', 400);
  }

  const { action } = body;

  // Ações que exigem usuário autenticado:
  const AUTH_REQUIRED = new Set(['db', 'rpc', 'ia', 'evolution', 'cadastrar_clinica']);

  let uid = null;
  if (AUTH_REQUIRED.has(action)) {
    const idToken = body.idToken || request.headers.get('x-firebase-token');
    uid = await verifyFirebaseToken(idToken, env.FIREBASE_PROJECT_ID);
    if (!uid) {
      return jsonErr('Não autenticado. Faça login novamente.', 401);
    }
  }

  // ══════════════════════════════════════════════
  // BANCO — Supabase via service_role, com user_id
  // forçado a partir do token verificado (nunca do
  // que o cliente mandar no payload).
  // ══════════════════════════════════════════════
  if (action === 'db') {
    const { table, op, payload, filters, order, limit, select } = body;

    if (!ALLOWED_TABLES.has(table)) {
      return jsonErr('Tabela não permitida', 403);
    }
    const userCol = USER_COL_OVERRIDE[table] || 'user_id';

    try {
      let url = `${env.SUPABASE_URL}/rest/v1/${table}`;
      let method = 'GET';
      let sbBody;
      const headers = {
        'Content-Type': 'application/json',
        'apikey': env.SUPABASE_SERVICE_ROLE_KEY,
        'Authorization': `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
      };
      const qs = new URLSearchParams();

      if (op === 'select') {
        method = 'GET';
        qs.set(userCol, `eq.${uid}`);
        // filtros extra (ex: { id: 5 } -> id=eq.5), sempre adicionais
        // ao filtro de dono, nunca substituindo-o
        if (filters && typeof filters === 'object') {
          for (const [k, v] of Object.entries(filters)) {
            if (k === userCol) continue; // não deixa sobrescrever o dono
            qs.set(k, `eq.${v}`);
          }
        }
        if (order) qs.set('order', order);
        if (limit) qs.set('limit', String(limit));
        qs.set('select', select || '*');

      } else if (op === 'insert') {
        method = 'POST';
        headers['Prefer'] = select ? 'return=representation' : 'return=minimal';
        const rows = Array.isArray(payload) ? payload : [payload];
        sbBody = rows.map(row => ({ ...row, [userCol]: uid, id: undefined }));

      } else if (op === 'update') {
        method = 'PATCH';
        headers['Prefer'] = 'return=minimal';
        qs.set(userCol, `eq.${uid}`); // só atualiza linha que pertence ao uid
        if (filters && typeof filters === 'object') {
          for (const [k, v] of Object.entries(filters)) {
            if (k === userCol) continue;
            qs.set(k, `eq.${v}`);
          }
        }
        const clean = { ...payload };
        delete clean[userCol];
        delete clean.id;
        sbBody = clean;

      } else if (op === 'delete') {
        method = 'DELETE';
        headers['Prefer'] = 'return=minimal';
        qs.set(userCol, `eq.${uid}`); // só deleta linha que pertence ao uid
        if (filters && typeof filters === 'object') {
          for (const [k, v] of Object.entries(filters)) {
            if (k === userCol) continue;
            qs.set(k, `eq.${v}`);
          }
        }

      } else if (op === 'upsert') {
        method = 'POST';
        headers['Prefer'] = `resolution=merge-duplicates,return=${select ? 'representation' : 'minimal'}`;
        const onConflict = body.onConflict || userCol;
        qs.set('on_conflict', onConflict);
        sbBody = { ...payload, [userCol]: uid };

      } else {
        return jsonErr('Operação inválida', 400);
      }

      const qsStr = qs.toString();
      if (qsStr) url += `?${qsStr}`;

      const res = await fetch(url, {
        method,
        headers,
        body: sbBody !== undefined ? JSON.stringify(sbBody) : undefined,
      });

      const text = await res.text();
      const data = text ? JSON.parse(text) : null;

      if (!res.ok) {
        return new Response(JSON.stringify({ error: data?.message || 'Erro no banco', detail: data }), {
          status: res.status, headers: corsHeaders,
        });
      }
      return new Response(JSON.stringify({ data, error: null }), { status: 200, headers: corsHeaders });

    } catch (err) {
      return jsonErr(err.message, 500);
    }
  }

  // ══════════════════════════════════════════════
  // RPC — funções do Postgres (ex: get_plano_trial)
  // ══════════════════════════════════════════════
  if (action === 'rpc') {
    const { name, params } = body;
    const ALLOWED_RPC = new Set(['get_plano_trial']);
    if (!ALLOWED_RPC.has(name)) {
      return jsonErr('RPC não permitida', 403);
    }
    try {
      // Força p_user_id = uid do token verificado, ignorando o que
      // o client mandar em params (mesma lógica anti-fraude do 'db').
      const safeParams = { ...params, p_user_id: uid };
      const res = await fetch(`${env.SUPABASE_URL}/rest/v1/rpc/${name}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'apikey': env.SUPABASE_SERVICE_ROLE_KEY,
          'Authorization': `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
        },
        body: JSON.stringify(safeParams),
      });
      const text = await res.text();
      const data = text ? JSON.parse(text) : null;
      if (!res.ok) {
        return new Response(JSON.stringify({ error: data?.message || 'Erro na função', detail: data }), {
          status: res.status, headers: corsHeaders,
        });
      }
      return new Response(JSON.stringify({ data, error: null }), { status: 200, headers: corsHeaders });
    } catch (err) {
      return jsonErr(err.message, 500);
    }
  }

  // ══════════════════════════════════════════════
  // IA — OpenRouter (agora exige login)
  // ══════════════════════════════════════════════
  if (action === 'ia') {
    const { messages, model } = body;
    try {
      const res = await fetch('https://openrouter.ai/api/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${env.OPENROUTER_KEY}`,
          'HTTP-Referer': 'https://ariaclinicas.pages.dev',
          'X-Title': 'ARiA Dental',
        },
        body: JSON.stringify({
          model: model || 'cohere/command-r7b-12-2024',
          messages,
          max_tokens: body.max_tokens || 800,
        }),
      });
      const data = await res.json();
      return new Response(JSON.stringify(data), { status: 200, headers: corsHeaders });
    } catch (err) {
      return jsonErr(err.message, 500);
    }
  }

  // ══════════════════════════════════════════════
  // EVOLUTION — WhatsApp proxy (agora exige login)
  // ══════════════════════════════════════════════
  if (action === 'evolution') {
    const { evoEndpoint, evoMethod = 'GET', evoBody } = body;
    try {
      const res = await fetch(`${env.EVOLUTION_URL}${evoEndpoint}`, {
        method: evoMethod,
        headers: {
          'Content-Type': 'application/json',
          'apikey': env.EVOLUTION_KEY,
        },
        body: evoBody ? JSON.stringify(evoBody) : undefined,
      });
      const data = await res.json().catch(() => ({}));
      return new Response(JSON.stringify(data), { status: res.status, headers: corsHeaders });
    } catch (err) {
      return jsonErr(err.message, 500);
    }
  }

  // ══════════════════════════════════════════════
  // CADASTRO DE CLÍNICA
  // ══════════════════════════════════════════════
  if (action === 'cadastrar_clinica') {
    const { nome_clinica, telefone_clinica, instance_name } = body;
    try {
      const res = await fetch(`${env.SUPABASE_URL}/rest/v1/odonto_clinicas`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'apikey': env.SUPABASE_SERVICE_ROLE_KEY,
          'Authorization': `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
          'Prefer': 'return=minimal',
        },
        body: JSON.stringify({
          user_id: uid, // sempre o uid do token, nunca do payload
          nome_clinica, telefone_clinica,
          instance_name, created_at: new Date().toISOString(),
        }),
      });
      if (!res.ok) {
        const err = await res.text();
        return jsonErr(err, 500);
      }
      return new Response(JSON.stringify({ ok: true }), { status: 200, headers: corsHeaders });
    } catch (err) {
      return jsonErr(err.message, 500);
    }
  }

  return jsonErr('Ação desconhecida', 400);
}

// Ponto de entrada real do Cloudflare Pages. Envolve handleRequest() inteiro
// num try/catch — assim, qualquer exceção não prevista em algum trecho
// (ex: verifyFirebaseToken, fetch externo, etc.) sempre volta como JSON
// válido (com a mensagem real do erro) em vez de virar uma página HTML
// genérica de erro do Cloudflare, que quebrava o front com "Resposta
// inválida do servidor" sem dar nenhuma pista do que aconteceu.
export async function onRequestPost(context) {
  try {
    return await handleRequest(context);
  } catch (err) {
    return jsonErr('Erro inesperado no servidor: ' + (err && err.message ? err.message : String(err)), 500);
  }
}

// OPTIONS — preflight CORS
export async function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, x-firebase-token',
    },
  });
}
