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
    LOG_LEVEL                 = info   (opcional — "debug" p/ investigar)
    ALLOWED_ORIGINS           = https://seudominio.com.br (opcional — ver
                                 seção CORS abaixo; sem isso, usa o default
                                 *.ariaclinicas.pages.dev + localhost)

  KV Namespace OPCIONAL (proteção extra contra abuso de custo na IA):
    RATE_LIMIT_KV — ver seção "RATE LIMITING" mais abaixo neste arquivo
    para o passo a passo de criação/binding.

  ⚠️ IMPORTANTE: remova a variável SUPABASE_KEY (anon) antiga se ela
  ainda existir — ela não é mais usada e não deve ficar configurada
  por engano em nenhum lugar.

  ═══════════════════════════════════════════════════════════════
  SEGURANÇA (v18 — correções pós-auditoria):
    - CORS deixou de ser '*' (qualquer site podia ler a resposta) e
      agora usa allowlist de origem (ver função buildCorsHeaders).
    - `filters`/`order` da ação 'db' agora passam por uma allowlist de
      colunas por tabela (ver ALLOWED_COLUMNS) — antes aceitava
      qualquer nome de coluna vindo do cliente.
    - Rate limiting best-effort na ação 'ia' via KV opcional (ver
      checkRateLimit) — protege contra abuso de custo do OpenRouter.
  Ver RELATORIO_SEGURANCA.md para o detalhamento completo, incluindo
  itens que precisam de ação fora do código (Firestore Rules, Cloudflare
  Rate Limiting Rules no dashboard).
  ═══════════════════════════════════════════════════════════════

  ═══════════════════════════════════════════════════════════════
  OBSERVABILIDADE (v17 — auditoria de logging):
  Todo o handler agora passa por um logger estruturado (ver
  ./lib/logger.js) que:
    - Emite JSON em vez de string livre (parseável por qualquer
      ferramenta de logs / SIEM).
    - Carrega requestId + userId (uid) + action em CADA linha, para
      conseguir filtrar "me mostra tudo que aconteceu na requisição X"
      ou "tudo que o usuário Y fez hoje".
    - Sanitiza (mascara/redige) tokens, chaves e dados pessoais antes
      de qualquer console.log/console.error — nunca vaza SERVICE_ROLE,
      idToken, senha, etc, mesmo em erro.
    - Separa níveis: debug/info/warn/error/fatal.
  ═══════════════════════════════════════════════════════════════
*/

import { createLogger, newRequestId } from './lib/logger.js';

/* ════════════════════════════════════════════════════════════
   CORS — allowlist de origem (substitui o antigo '*')
   ════════════════════════════════════════════════════════════
   Antes: 'Access-Control-Allow-Origin': '*' — qualquer site na
   internet podia chamar este endpoint autenticado e LER a resposta
   via fetch() no navegador de quem estivesse logado (ex: um XSS em
   outro domínio, ou um site malicioso explorando engenharia social
   para abrir o app numa aba enquanto o dentista está logado).

   Agora só origens explicitamente permitidas recebem o header —
   qualquer outra origem tem a resposta bloqueada pelo próprio
   navegador (o request ainda roda no servidor, mas o JS da página
   maliciosa não consegue ler a resposta).

   Configuração (Cloudflare Dashboard → Settings → Environment
   Variables):
     ALLOWED_ORIGINS = https://seudominio.com.br,https://outrodominio.com
   (opcional — sem essa variável, cai no default abaixo, que já
   cobre o domínio *.pages.dev do projeto e localhost para dev)
═══════════════════════════════════════════════════════════════ */
const DEFAULT_ALLOWED_ORIGIN_SUFFIXES = ['.ariaclinicas.pages.dev'];
const DEFAULT_ALLOWED_ORIGINS = new Set([
  'https://ariaclinicas.pages.dev',
  'http://localhost:8788', // wrangler pages dev --local
  'http://127.0.0.1:8788',
]);

function isOriginAllowed(origin, env) {
  if (!origin) return false;
  const configured = (env.ALLOWED_ORIGINS || '')
    .split(',').map(s => s.trim()).filter(Boolean);
  if (configured.includes(origin)) return true;
  if (DEFAULT_ALLOWED_ORIGINS.has(origin)) return true;
  return DEFAULT_ALLOWED_ORIGIN_SUFFIXES.some(suffix => origin.endsWith(suffix));
}

function buildCorsHeaders(request, env) {
  const origin = request.headers.get('Origin');
  const headers = { 'Content-Type': 'application/json', 'Vary': 'Origin' };
  if (isOriginAllowed(origin, env)) {
    headers['Access-Control-Allow-Origin'] = origin;
  }
  // Se a origem não é permitida, simplesmente NÃO setamos o header —
  // o navegador de quem fez a requisição bloqueia a leitura da resposta.
  return headers;
}

function jsonErr(msg, status, corsHeaders) {
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

async function getGoogleJwks(log) {
  const now = Date.now();
  if (_jwksCache && now < _jwksCacheExpiry) return _jwksCache;

  try {
    // Endpoint oficial do Firebase/Google no formato JWK — importável
    // direto pelo WebCrypto, sem precisar parsear certificado X.509/ASN.1.
    const res = await fetch(
      'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com'
    );
    if (!res.ok) {
      log.error('Falha ao buscar JWKS do Google', { httpStatus: res.status });
      return null;
    }
    const jwks = await res.json();
    _jwksCache = jwks;
    _jwksCacheExpiry = now + 5 * 60 * 1000; // 5 min
    return jwks;
  } catch (err) {
    // Antes: falhava silenciosamente (retornava null igual a "token inválido",
    // indistinguível de uma tentativa de fraude). Agora fica claro que foi
    // uma falha de INFRAESTRUTURA (rede/Google fora do ar), não de auth.
    log.error('Exceção ao buscar JWKS do Google', { error: err });
    return null;
  }
}

async function verifyFirebaseToken(idToken, projectId, log) {
  if (!idToken || !projectId) {
    log.warn('verifyFirebaseToken: token ou projectId ausente');
    return null;
  }

  const parts = idToken.split('.');
  if (parts.length !== 3) {
    log.warn('verifyFirebaseToken: token com formato inválido (não é JWT)');
    return null;
  }
  const [headerB64, payloadB64, sigB64] = parts;

  let header, payload;
  try {
    header = JSON.parse(base64UrlDecode(headerB64));
    payload = JSON.parse(base64UrlDecode(payloadB64));
  } catch (err) {
    // Antes: catch(_) { return null } — indistinguível de token expirado.
    log.warn('verifyFirebaseToken: falha ao decodificar JWT', { error: err });
    return null;
  }

  // Checagens de validade do payload, conforme a documentação do
  // Firebase para verificação manual de ID Tokens.
  const now = Math.floor(Date.now() / 1000);
  if (!payload.exp || payload.exp < now) {
    log.info('verifyFirebaseToken: token expirado', { sub: payload.sub });
    return null;
  }
  if (!payload.iat || payload.iat > now + 60) {
    log.warn('verifyFirebaseToken: iat no futuro (possível clock skew ou token forjado)', { sub: payload.sub });
    return null;
  }
  if (payload.aud !== projectId) {
    log.warn('verifyFirebaseToken: aud não confere com FIREBASE_PROJECT_ID');
    return null;
  }
  if (payload.iss !== `https://securetoken.google.com/${projectId}`) {
    log.warn('verifyFirebaseToken: iss inválido');
    return null;
  }
  if (!payload.sub || typeof payload.sub !== 'string') {
    log.warn('verifyFirebaseToken: payload sem sub válido');
    return null;
  }
  if (header.alg !== 'RS256') {
    log.warn('verifyFirebaseToken: alg inesperado', { alg: header.alg });
    return null;
  }

  const kid = header.kid;
  if (!kid) {
    log.warn('verifyFirebaseToken: header sem kid');
    return null;
  }

  const jwks = await getGoogleJwks(log);
  if (!jwks || !jwks.keys) return null;
  const jwk = jwks.keys.find(k => k.kid === kid);
  if (!jwk) {
    log.warn('verifyFirebaseToken: kid não encontrado nas JWKS atuais (chave rotacionada?)', { kid });
    return null;
  }

  const valid = await verifySignatureRS256(`${headerB64}.${payloadB64}`, sigB64, jwk, log);
  if (!valid) {
    log.warn('verifyFirebaseToken: assinatura inválida — possível token forjado', { sub: payload.sub });
    return null;
  }

  return payload.sub; // Firebase UID real e criptograficamente verificado
}

function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return atob(str);
}

async function verifySignatureRS256(signedData, sigB64, jwk, log) {
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
  } catch (err) {
    // Antes: catch(e) { return false } sem nenhum log — uma falha de
    // WebCrypto (ex: JWK malformado) parecia idêntica a "assinatura errada".
    log.error('verifySignatureRS256: exceção ao verificar assinatura', { error: err });
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
  'odonto_convenios',
  'odonto_metas',
  'contatos',
]);

// Colunas que o cliente pode usar em `filters`/`order` por tabela — sem
// isso, o endpoint aceitava QUALQUER nome de coluna vindo do corpo da
// requisição (ex: filters: { qualquer_coisa: 'x' }), o que permite
// enumerar o schema do banco por tentativa e erro. Não é SQL injection
// (o PostgREST trata como igualdade literal), mas fecha essa superfície.
const ALLOWED_COLUMNS = {
  odonto_pacientes:   new Set(['id', 'nome', 'status', 'data_nasc', 'telefone', 'convenio_id', 'crm_stage', 'crm_stage_updated_at']),
  odonto_consultas:   new Set(['id', 'paciente_id', 'doutor_id', 'data', 'hora', 'status', 'procedimento']),
  odonto_prontuarios: new Set(['id', 'paciente_id', 'doutor_id', 'data', 'procedimento']),
  odonto_financeiro:  new Set(['id', 'paciente_id', 'status', 'data_item', 'criado_em']),
  odonto_doutores:    new Set(['id', 'nome', 'status', 'especialidade']),
  odonto_clinicas:    new Set(['id', 'nome_clinica', 'plano']),
  odonto_convenios:   new Set(['id', 'nome', 'ativo']),
  odonto_metas:       new Set(['id', 'mes']),
  contatos:           new Set(['id', 'usuario_id', 'instance_name']),
};
function isColumnAllowed(table, column) {
  const set = ALLOWED_COLUMNS[table];
  // Coluna pode vir com operador do PostgREST anexado no `order`
  // (ex: "nome.asc") — comparamos só a parte antes do primeiro ponto.
  const base = String(column).split('.')[0];
  return !!set && set.has(base);
}

/* ════════════════════════════════════════════════════════════
   RATE LIMITING (best-effort) — ação 'ia'
   ════════════════════════════════════════════════════════════
   Cada chamada de IA custa dinheiro real (OpenRouter). Sem limite,
   um único usuário (ou uma sessão comprometida) pode gerar uma
   fatura alta em poucos minutos.

   Isso usa um KV Namespace OPCIONAL chamado RATE_LIMIT_KV. Se você
   não configurar esse binding, o rate limit simplesmente não roda
   (log de warn uma vez) — não quebra a aplicação, mas também não
   protege. Para ativar:

   1. Cloudflare Dashboard → Workers & Pages → KV → Create namespace
      (ex: "aria-rate-limit")
   2. No seu projeto Pages → Settings → Functions → KV namespace bindings
      → Add binding: Variable name = RATE_LIMIT_KV, KV namespace = a
      que você criou.

   Isso cobre abuso vindo de UM usuário autenticado. Para proteção
   ampla contra volumetria (ex: milhares de IPs diferentes batendo no
   endpoint), configure também "Rate limiting rules" em Cloudflare
   Dashboard → Security → WAF — isso opera antes da requisição
   sequer chegar nesta function, e é mais eficaz contra esse tipo de
   ataque do que qualquer coisa que possamos fazer aqui em código.
═══════════════════════════════════════════════════════════════ */
const RATE_LIMITS = {
  ia: { max: 30, windowSec: 60 * 10 }, // 30 chamadas de IA / 10 min / usuário
};

let _warnedNoKvOnce = false;

async function checkRateLimit(env, uid, action, log) {
  const rule = RATE_LIMITS[action];
  if (!rule) return { allowed: true };
  if (!env.RATE_LIMIT_KV) {
    if (!_warnedNoKvOnce) {
      _warnedNoKvOnce = true;
      log.warn('RATE_LIMIT_KV não configurado — rate limiting da ação "ia" está DESATIVADO', { action });
    }
    return { allowed: true };
  }

  const key = `rl:${action}:${uid}`;
  try {
    const raw = await env.RATE_LIMIT_KV.get(key);
    const count = raw ? parseInt(raw, 10) : 0;
    if (count >= rule.max) {
      log.warn('Rate limit excedido', { action, uid, count, max: rule.max });
      return { allowed: false };
    }
    // expirationTtl reinicia a contagem a cada janela — simples e
    // suficiente para conter abuso; não precisa de sliding window aqui.
    await env.RATE_LIMIT_KV.put(key, String(count + 1), { expirationTtl: rule.windowSec });
    return { allowed: true };
  } catch (err) {
    // Falha no KV não deve derrubar a ação principal — só registra e
    // segue permitindo (fail-open), já que isso é uma proteção extra,
    // não a defesa primária (essa é a allowlist + auth + tabelas).
    log.error('Falha ao checar rate limit (fail-open)', { action, error: err });
    return { allowed: true };
  }
}

async function handleRequest(context, log) {
  const { request, env } = context;
  const corsHeaders = buildCorsHeaders(request, env);

  let body;
  try {
    body = await request.json();
  } catch (err) {
    log.warn('Body da requisição não é JSON válido', { error: err });
    return jsonErr('Body inválido', 400, corsHeaders);
  }

  const { action } = body;
  log.info('Requisição recebida', { action, table: body.table, op: body.op });

  // Ações que exigem usuário autenticado:
  const AUTH_REQUIRED = new Set(['db', 'rpc', 'ia', 'evolution', 'cadastrar_clinica']);

  let uid = null;
  if (AUTH_REQUIRED.has(action)) {
    const idToken = body.idToken || request.headers.get('x-firebase-token');
    uid = await verifyFirebaseToken(idToken, env.FIREBASE_PROJECT_ID, log);
    if (!uid) {
      log.warn('Requisição rejeitada: autenticação falhou', { action });
      return jsonErr('Não autenticado. Faça login novamente.', 401, corsHeaders);
    }
    // A partir daqui, todo log ganha o userId automaticamente —
    // é o "child logger": mesmo requestId, mais contexto.
    log = log.child({ userId: uid });
  }

  // ══════════════════════════════════════════════
  // BANCO — Supabase via service_role, com user_id
  // forçado a partir do token verificado (nunca do
  // que o cliente mandar no payload).
  // ══════════════════════════════════════════════
  if (action === 'db') {
    const { table, op, payload, filters, order, limit, select } = body;

    if (!ALLOWED_TABLES.has(table)) {
      log.warn('Tentativa de acessar tabela não permitida', { table });
      return jsonErr('Tabela não permitida', 403, corsHeaders);
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
            if (!isColumnAllowed(table, k)) {
              log.warn('Coluna não permitida em filters (select)', { table, coluna: k });
              continue;
            }
            qs.set(k, `eq.${v}`);
          }
        }
        if (order) {
          if (isColumnAllowed(table, order)) qs.set('order', order);
          else log.warn('Coluna não permitida em order (select)', { table, order });
        }
        if (limit) qs.set('limit', String(limit));
        qs.set('select', select || '*');

      } else if (op === 'insert') {
        method = 'POST';
        headers['Prefer'] = select ? 'return=representation' : 'return=minimal';
        const rows = Array.isArray(payload) ? payload : [payload];
        // IMPORTANTE (bug corrigido): este código antes fazia `id: undefined`
        // pra "nunca confiar no id vindo do cliente" — parecia uma boa
        // prática de segurança, mas quebrava a aplicação inteira, porque
        // TODO o front-end gera o id no cliente via `Date.now()` e reutiliza
        // esse mesmo valor depois pra editar/excluir/referenciar aquele
        // registro (inclusive como chave estrangeira em consultas,
        // prontuários e financeiro apontando pro paciente).
        //
        // Como `Prefer: return=minimal` não devolve o registro criado, o
        // front-end nunca ficava sabendo qual id o Postgres teria gerado
        // sozinho — resultado: paciente aparecia normalmente na tela
        // (cache local), mas qualquer consulta/prontuário criado depois
        // pra ele falhava com "violates foreign key constraint", porque o
        // id salvo no banco era diferente do id que o paciente tinha na
        // tela. Em tabelas sem valor padrão pra `id` (ex: odonto_doutores),
        // o insert falhava na hora com "null value in column id violates
        // not-null constraint".
        //
        // Não há ganho de segurança real em bloquear o id vindo do
        // cliente aqui: o dono do registro já é forçado no passo abaixo
        // ([userCol]: uid), então ninguém consegue "roubar" um registro só
        // escolhendo um id — na pior hipótese colide com outro id (o
        // Postgres rejeita por PRIMARY KEY, e o Date.now() já torna isso
        // extremamente improvável).
        sbBody = rows.map(row => ({ ...row, [userCol]: uid }));

      } else if (op === 'update') {
        method = 'PATCH';
        headers['Prefer'] = 'return=minimal';
        qs.set(userCol, `eq.${uid}`); // só atualiza linha que pertence ao uid
        if (filters && typeof filters === 'object') {
          for (const [k, v] of Object.entries(filters)) {
            if (k === userCol) continue;
            if (!isColumnAllowed(table, k)) {
              log.warn('Coluna não permitida em filters (update)', { table, coluna: k });
              continue;
            }
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
            if (!isColumnAllowed(table, k)) {
              log.warn('Coluna não permitida em filters (delete)', { table, coluna: k });
              continue;
            }
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
        log.warn('Operação de banco inválida', { op });
        return jsonErr('Operação inválida', 400, corsHeaders);
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
        // Antes: só retornava pro cliente, nada ficava registrado no
        // servidor — se o Supabase começasse a rejeitar tudo (ex: RLS
        // mal configurada, coluna renomeada), a equipe só saberia por
        // reclamação de usuário. Log de erro com nível correto (warn se
        // é erro esperado do cliente, error se é 5xx do Supabase).
        const level = res.status >= 500 ? 'error' : 'warn';
        log[level]('Supabase retornou erro', { table, op, httpStatus: res.status, detail: data });
        return new Response(JSON.stringify({ error: data?.message || 'Erro no banco', detail: data }), {
          status: res.status, headers: corsHeaders,
        });
      }
      log.info('Operação de banco concluída', { table, op, rows: Array.isArray(data) ? data.length : undefined });
      return new Response(JSON.stringify({ data, error: null }), { status: 200, headers: corsHeaders });

    } catch (err) {
      // Antes: catch(err) { return jsonErr(err.message, 500) } — nenhum
      // log no servidor. Uma falha de rede pro Supabase (fora do ar,
      // DNS, timeout) desaparecia sem deixar rastro nenhum.
      log.error('Exceção ao executar operação de banco', { table, op, error: err });
      return jsonErr(err.message, 500, corsHeaders);
    }
  }

  // ══════════════════════════════════════════════
  // RPC — funções do Postgres (ex: get_plano_trial)
  // ══════════════════════════════════════════════
  if (action === 'rpc') {
    const { name, params } = body;
    const ALLOWED_RPC = new Set(['get_plano_trial']);
    if (!ALLOWED_RPC.has(name)) {
      log.warn('Tentativa de chamar RPC não permitida', { name });
      return jsonErr('RPC não permitida', 403, corsHeaders);
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
        const level = res.status >= 500 ? 'error' : 'warn';
        log[level]('RPC retornou erro', { name, httpStatus: res.status, detail: data });
        return new Response(JSON.stringify({ error: data?.message || 'Erro na função', detail: data }), {
          status: res.status, headers: corsHeaders,
        });
      }
      log.info('RPC concluída', { name });
      return new Response(JSON.stringify({ data, error: null }), { status: 200, headers: corsHeaders });
    } catch (err) {
      log.error('Exceção ao chamar RPC', { name, error: err });
      return jsonErr(err.message, 500, corsHeaders);
    }
  }

  // ══════════════════════════════════════════════
  // IA — OpenRouter (agora exige login)
  // ══════════════════════════════════════════════
  if (action === 'ia') {
    const { messages, model } = body;

    const rl = await checkRateLimit(env, uid, 'ia', log);
    if (!rl.allowed) {
      return jsonErr('Limite de mensagens à IA atingido. Tente novamente em alguns minutos.', 429, corsHeaders);
    }

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
      if (!res.ok) {
        // Antes: se a OpenRouter respondesse 4xx/5xx, o proxy repassava o
        // corpo pro cliente com status 200 (!) — nunca virava erro visível
        // em log nenhum. Aqui separamos claramente sucesso de falha.
        log.error('OpenRouter retornou erro', { httpStatus: res.status, model: model || 'default' });
      } else {
        log.info('Chamada à IA concluída', { model: model || 'default' });
      }
      return new Response(JSON.stringify(data), { status: 200, headers: corsHeaders });
    } catch (err) {
      log.error('Exceção ao chamar OpenRouter', { error: err });
      return jsonErr(err.message, 500, corsHeaders);
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
      const data = await res.json().catch((parseErr) => {
        // Antes: catch(() => ({})) silencioso — uma resposta não-JSON da
        // Evolution API (ex: HTML de erro do proxy/nginx) virava um objeto
        // vazio sem qualquer rastro do que realmente aconteceu.
        log.warn('Resposta da Evolution API não é JSON válido', { evoEndpoint, error: parseErr });
        return {};
      });
      if (!res.ok) {
        log.warn('Evolution API retornou erro', { evoEndpoint, evoMethod, httpStatus: res.status });
      } else {
        log.info('Chamada à Evolution API concluída', { evoEndpoint, evoMethod });
      }
      return new Response(JSON.stringify(data), { status: res.status, headers: corsHeaders });
    } catch (err) {
      log.error('Exceção ao chamar Evolution API', { evoEndpoint, evoMethod, error: err });
      return jsonErr(err.message, 500, corsHeaders);
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
        const errText = await res.text();
        log.error('Falha ao cadastrar clínica no Supabase', { httpStatus: res.status, detail: errText });
        return jsonErr(errText, 500, corsHeaders);
      }
      log.info('Clínica cadastrada com sucesso', { nome_clinica });
      return new Response(JSON.stringify({ ok: true }), { status: 200, headers: corsHeaders });
    } catch (err) {
      log.error('Exceção ao cadastrar clínica', { error: err });
      return jsonErr(err.message, 500, corsHeaders);
    }
  }

  log.warn('Ação desconhecida solicitada', { action });
  return jsonErr('Ação desconhecida', 400, corsHeaders);
}

// Ponto de entrada real do Cloudflare Pages. Envolve handleRequest() inteiro
// num try/catch — assim, qualquer exceção não prevista em algum trecho
// (ex: verifyFirebaseToken, fetch externo, etc.) sempre volta como JSON
// válido (com a mensagem real do erro) em vez de virar uma página HTML
// genérica de erro do Cloudflare, que quebrava o front com "Resposta
// inválida do servidor" sem dar nenhuma pista do que aconteceu.
//
// Todo o request ganha um requestId único aqui, no ponto de entrada —
// é o valor que amarra todas as linhas de log dessa invocação, e é
// também devolvido no header de resposta para o front poder citá-lo
// caso o usuário abra um chamado de suporte.
export async function onRequestPost(context) {
  const requestId = newRequestId();
  const log = createLogger({ requestId }, context.env);
  const startedAt = Date.now();

  try {
    const response = await handleRequest(context, log);
    log.debug('Requisição finalizada', { durationMs: Date.now() - startedAt, httpStatus: response.status });
    response.headers.set('x-request-id', requestId);
    return response;
  } catch (err) {
    // fatal: exceção não tratada em nenhum ponto do handler — sempre o
    // nível mais alto, porque indica um bug não previsto no código.
    log.fatal('Exceção não tratada no proxy', { error: err, durationMs: Date.now() - startedAt });
    const corsHeaders = buildCorsHeaders(context.request, context.env);
    const res = jsonErr('Erro inesperado no servidor: ' + (err && err.message ? err.message : String(err)), 500, corsHeaders);
    res.headers.set('x-request-id', requestId);
    return res;
  }
}

// OPTIONS — preflight CORS (mesma allowlist de origem do POST)
export async function onRequestOptions(context) {
  const corsHeaders = buildCorsHeaders(context.request, context.env);
  return new Response(null, {
    status: 204,
    headers: {
      ...corsHeaders,
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, x-firebase-token',
    },
  });
}
