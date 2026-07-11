/*
  ═══════════════════════════════════════════════════════════════
  ARiA — Logger estruturado (Cloudflare Pages Functions / Workers)
  ═══════════════════════════════════════════════════════════════

  POR QUE NÃO WINSTON / PINO AQUI?
  Cloudflare Pages Functions roda no runtime de Workers (isolates V8),
  não em Node.js puro. Winston depende de `fs`, `stream` e transports
  Node — não funciona no edge. O Pino "core" também depende de streams
  Node; só o `pino/browser` (sem transports) rodaria, mas ainda assim
  adiciona ~30-50kb e complexidade de bundling para um proxy que precisa
  de cold start rápido. A prática recomendada pela própria Cloudflare
  é logging estruturado via console.log/console.error em JSON — que é
  automaticamente capturado por:
    - `wrangler pages deployment tail` (tempo real)
    - Cloudflare Dashboard → Workers & Pages → seu projeto → Logs
    - Logpush (se configurado) para exportar a um data lake / Datadog /
      Grafana Loki / Axiom / etc.

  Este módulo reproduz a API que Winston/Pino oferecem (logger.info,
  logger.warn, logger.error, logger.fatal, child loggers com contexto)
  mas com zero dependências, compatível 100% com o runtime de Workers.

  Se no futuro migrar para um Worker "puro" com `nodejs_compat` habilitado,
  dá pra trocar o `_write()` por um transport real (ex: enviar para Axiom
  via HTTP) sem mudar nenhuma chamada de log no resto do código.
  ═══════════════════════════════════════════════════════════════
*/

// ──────────────────────────────────────────────────────────────
// Sanitização / Data Masking
// ──────────────────────────────────────────────────────────────
// Chaves que NUNCA podem aparecer em texto puro no log — são
// totalmente substituídas por "[REDACTED]".
const FULL_REDACT_KEYS = new Set([
  'password', 'senha', 'pass', 'pwd',
  'token', 'idtoken', 'id_token', 'accesstoken', 'access_token',
  'refreshtoken', 'refresh_token', 'x-firebase-token',
  'apikey', 'api_key', 'authorization',
  'service_role', 'service_role_key', 'supabase_service_role_key',
  'secret', 'client_secret', 'private_key', 'privatekey',
  'cartao', 'card_number', 'cvv', 'cvc',
]);

// Chaves com dado pessoal (LGPD) que preferimos mascarar parcialmente
// em vez de apagar por completo — ainda ajuda a debugar sem expor o
// dado inteiro (ex: "jo***@***.com" em vez do e-mail completo).
const PARTIAL_MASK_KEYS = new Set([
  'email', 'e-mail',
  'telefone', 'phone', 'celular', 'whatsapp',
  'cpf', 'rg', 'nome', 'nome_completo', 'paciente_nome',
]);

function maskString(value) {
  if (typeof value !== 'string' || value.length === 0) return value;
  if (value.includes('@')) {
    // e-mail: mantém 2 primeiros chars + domínio
    const [user, domain] = value.split('@');
    return `${user.slice(0, 2)}***@${domain}`;
  }
  if (value.length <= 4) return '*'.repeat(value.length);
  // mantém só os 2 primeiros e 2 últimos caracteres
  return `${value.slice(0, 2)}${'*'.repeat(Math.max(value.length - 4, 3))}${value.slice(-2)}`;
}

// Sanitiza recursivamente qualquer objeto antes de logar — nunca
// gravamos o objeto original, sempre uma cópia tratada.
function sanitize(value, depth = 0) {
  if (depth > 6) return '[max depth]'; // evita objetos circulares/gigantes
  if (value === null || value === undefined) return value;

  if (Array.isArray(value)) {
    return value.slice(0, 50).map(v => sanitize(v, depth + 1)); // limita arrays grandes
  }

  if (value instanceof Error) {
    return {
      name: value.name,
      message: value.message,
      stack: value.stack, // stack é seguro — não deve conter dado pessoal
    };
  }

  if (typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      const key = k.toLowerCase();
      if (FULL_REDACT_KEYS.has(key)) {
        out[k] = '[REDACTED]';
      } else if (PARTIAL_MASK_KEYS.has(key) && typeof v === 'string') {
        out[k] = maskString(v);
      } else {
        out[k] = sanitize(v, depth + 1);
      }
    }
    return out;
  }

  if (typeof value === 'string' && value.length > 2000) {
    return value.slice(0, 2000) + '…[truncated]';
  }

  return value;
}

// ──────────────────────────────────────────────────────────────
// Níveis
// ──────────────────────────────────────────────────────────────
const LEVELS = { debug: 10, info: 20, warn: 30, error: 40, fatal: 50 };

// Nível mínimo que efetivamente sai no console — em produção normalmente
// 'info', mas pode ser baixado via env var LOG_LEVEL=debug para depurar.
function minLevel(env) {
  const lvl = (env && env.LOG_LEVEL) || 'info';
  return LEVELS[lvl] ?? LEVELS.info;
}

// ──────────────────────────────────────────────────────────────
// Fábrica do logger — uma instância por request, sempre carregando
// o contexto (requestId, userId, action) em todo log emitido.
// ──────────────────────────────────────────────────────────────
function createLogger(baseContext = {}, env = {}) {
  const threshold = minLevel(env);

  function write(level, message, meta = {}) {
    if (LEVELS[level] < threshold) return;

    const entry = {
      timestamp: new Date().toISOString(),
      level,
      service: 'aria-odonto-api',
      message,
      ...sanitize(baseContext),
      ...sanitize(meta),
    };

    const line = JSON.stringify(entry);
    // console.error para warn/error/fatal garante que apareçam mesmo
    // em pipelines que só capturam stderr; info/debug vão em stdout.
    if (level === 'error' || level === 'fatal' || level === 'warn') {
      console.error(line);
    } else {
      console.log(line);
    }
  }

  return {
    debug: (message, meta) => write('debug', message, meta),
    info:  (message, meta) => write('info', message, meta),
    warn:  (message, meta) => write('warn', message, meta),
    error: (message, meta) => write('error', message, meta),
    fatal: (message, meta) => write('fatal', message, meta),
    // "child logger" — herda o contexto atual e adiciona mais campos
    // (ex: depois de descobrir o uid, gera um child com userId fixo).
    child(extraContext) {
      return createLogger({ ...baseContext, ...extraContext }, env);
    },
  };
}

// Gera um requestId curto e único por invocação — essencial pra
// correlacionar todas as linhas de log de uma mesma requisição.
function newRequestId() {
  return crypto.randomUUID();
}

export { createLogger, newRequestId, sanitize };
