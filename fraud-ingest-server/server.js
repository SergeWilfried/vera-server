/**
 * Fraud ingest server — SDK pipe + Postgres persistence + console API:
 *
 *   POST /v1/events   gzip NDJSON batches from the SDK
 *                     -> verifies X-Signature (HMAC-SHA256, per-tenant key)
 *                     -> pretty-prints each event, persists sessions/devices/
 *                        users/events to Postgres
 *
 *   POST /v1/score    scoring stub matching the SessionContext spec
 *                     -> verifies the sessionToken minted by the SDK
 *                     -> ALLOW / STEP_UP / HOLD on 0–100 policy bands;
 *                        HOLD raises an Open alert in the analyst queue
 *
 *   Console API (Bearer key, see CONSOLE_KEYS):
 *     GET   /v1/console/overview
 *     GET   /v1/console/alerts?state=Open        GET  /v1/console/alerts/:id
 *     PATCH /v1/console/alerts/:id               {state?, disposition?}
 *     POST  /v1/console/alerts/:id/case          {assignee?, summary?}
 *     GET   /v1/console/cases?status=            GET  /v1/console/cases/:id
 *     PATCH /v1/console/cases/:id                {status?, assignee?, note?}
 *     GET   /v1/console/users/:userRef
 *     GET   /v1/console/sessions/:sessionId/events
 *
 *   GET  /stats       event counts per type (from Postgres)
 *
 * Deps: pg only. Postgres via DATABASE_URL (default postgresql://localhost/vera_fraud).
 * Run: node server.js   (PORT and tenant keys configurable below)
 */
const http = require('http');
const zlib = require('zlib');
const crypto = require('crypto');
const db = require('./db');
const scoring = require('./scoring');

const PORT = process.env.PORT || 8080;

// key must match SdkConfig on the device (>=32 bytes). coreBankingWebhook
// is where analyst actions (payment release/block, session terminate) are
// pushed, signed with the same key.
const TENANTS = {
  'wallet-acme': {
    key: Buffer.from('0123456789abcdef0123456789abcdef'),
    coreBankingWebhook: process.env.CORE_WEBHOOK || 'http://localhost:8090/core-banking/hooks',
  },
};

// Machine/service keys (SIEM export, integrations) -> tenant scope.
// Human analysts authenticate via POST /v1/console/login instead.
const CONSOLE_KEYS = {
  [process.env.CONSOLE_KEY || 'dev-console-key']: 'wallet-acme',
};

// RBAC ranks. Service keys act at senior level (integrations can act on
// alerts) but can never manage the team — that's admin, humans only.
const ROLE_RANK = { readonly: 0, analyst: 1, senior: 2, admin: 3, service: 2 };
const RANK = { READ: 0, ANALYST: 1, SENIOR: 2, ADMIN: 3 };

// ---------- helpers ----------

function hmacB64(key, buf) {
  return crypto.createHmac('sha256', key).update(buf).digest('base64');
}

function b64urlDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}

/** Verify the compact session token: b64url(payload).b64url(hmac) */
function verifySessionToken(token) {
  const dot = token.lastIndexOf('.');
  if (dot < 0) return { ok: false, reason: 'malformed' };
  const body = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  let payload;
  try { payload = JSON.parse(b64urlDecode(body).toString('utf8')); }
  catch { return { ok: false, reason: 'bad payload' }; }
  const key = TENANTS[payload.t]?.key;
  if (!key) return { ok: false, reason: 'unknown tenant ' + payload.t };
  const expect = crypto.createHmac('sha256', key).update(body, 'utf8').digest();
  const got = b64urlDecode(sig);
  if (expect.length !== got.length || !crypto.timingSafeEqual(expect, got))
    return { ok: false, reason: 'bad signature' };
  const ageSec = Math.floor(Date.now() / 1000) - (payload.iat || 0);
  if (ageSec > 3600) return { ok: false, reason: 'expired (' + ageSec + 's)' };
  return { ok: true, payload };
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function json(res, code, obj) {
  const body = JSON.stringify(obj, null, 2);
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(body);
}

const C = { reset: '\x1b[0m', dim: '\x1b[2m', green: '\x1b[32m',
            yellow: '\x1b[33m', red: '\x1b[31m', cyan: '\x1b[36m', mag: '\x1b[35m' };

function colorFor(type) {
  if (type.startsWith('BIZ_')) return C.green;
  if (type.startsWith('PASSIVE_TOUCH')) return C.cyan;
  if (type.startsWith('PASSIVE_')) return C.mag;
  return C.yellow;
}

// ---------- action delivery (webhook into core banking) ----------

const WEBHOOK_TYPES = {
  RELEASE_PAYMENT: 'payment.release',
  BLOCK_PAYMENT: 'payment.block',
  TERMINATE_SESSION: 'session.terminate',
};

/**
 * Push one action to the tenant's core-banking webhook, signed with the
 * tenant key over the raw body. The first attempt is awaited (so the
 * console response reports real delivery status); on failure two retries
 * run in the background with backoff.
 */
async function deliverAction(tenantId, action, { retriesLeft = 2, backoffMs = 2000 } = {}) {
  const tenant = TENANTS[tenantId];
  const payload = Buffer.from(JSON.stringify({
    id: action.id, type: WEBHOOK_TYPES[action.kind], tenantId,
    alertId: action.alert_id, ...action.target,
    note: action.note || null, ts: Date.now(),
  }), 'utf8');
  const sig = hmacB64(tenant.key, payload);

  try {
    const r = await fetch(tenant.coreBankingWebhook, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json',
                 'X-Tenant-Id': tenantId, 'X-Signature': sig },
      body: payload,
      signal: AbortSignal.timeout(3000),
    });
    if (!r.ok) throw new Error('webhook returned ' + r.status);
    await db.markWebhookResult(action.id, true, null);
    console.log(`  ${C.green}→ delivered${C.reset} ${action.id} ${WEBHOOK_TYPES[action.kind]} ` +
        `to core banking`);
    return 'delivered';
  } catch (e) {
    await db.markWebhookResult(action.id, false, String(e.message || e));
    console.log(`  ${C.red}→ webhook failed${C.reset} ${action.id} (${e.message})` +
        (retriesLeft ? ` — retrying in ${backoffMs}ms` : ' — giving up'));
    if (retriesLeft > 0) {
      setTimeout(() => {
        deliverAction(tenantId, action,
          { retriesLeft: retriesLeft - 1, backoffMs: backoffMs * 2 }).catch(() => {});
      }, backoffMs);
    }
    return 'failed';
  }
}

// ---------- ingest ----------

async function handleEvents(req, res) {
  const raw = await readBody(req);
  const tenantId = req.headers['x-tenant-id'];
  const sigHeader = req.headers['x-signature'] || '';
  const key = TENANTS[tenantId]?.key;

  if (!key) return json(res, 400, { error: 'unknown tenant: ' + tenantId });

  // 1. Verify HMAC over the raw (gzipped) body — exactly what the SDK signs
  const expected = hmacB64(key, raw);
  const a = Buffer.from(sigHeader), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    console.log(`${C.red}✗ signature mismatch${C.reset} tenant=${tenantId}`);
    return json(res, 401, { error: 'bad signature' });
  }

  // 2. Decompress + parse NDJSON
  let text;
  try { text = zlib.gunzipSync(raw).toString('utf8'); }
  catch { return json(res, 400, { error: 'not gzip' }); }

  const lines = text.split('\n').filter(Boolean);
  const installId = req.headers['x-install-id'];
  console.log(`\n${C.green}✓ batch${C.reset} tenant=${tenantId} ` +
      `sdk=${req.headers['x-sdk']} install=${String(installId).slice(0, 8)}… ` +
      `events=${lines.length}`);

  const events = [];
  for (const line of lines) {
    let ev;
    try { ev = JSON.parse(line); }
    catch { console.log(`${C.red}  unparseable line${C.reset}`); continue; }
    events.push(ev);

    const col = colorFor(ev.type || '?');
    const bits = [];
    if (ev.userRef) bits.push('user=' + ev.userRef.slice(0, 8) + '…');
    if (ev.sessionId) bits.push('sess=' + ev.sessionId.slice(0, 8) + '…');
    if (ev.callSignals) {
      const cs = ev.callSignals;
      if (cs.inGsmCall) bits.push(C.red + 'IN GSM CALL' + C.reset + col);
      if (cs.inVoipCall) bits.push(C.red + 'IN VOIP CALL' + C.reset + col);
      if (cs.speakerOn) bits.push('speaker');
    }
    console.log(`  ${col}${ev.type}${C.reset} ${C.dim}${bits.join(' ')}${C.reset}`);
    if (ev.payload && Object.keys(ev.payload).length) {
      console.log(`    ${C.dim}${JSON.stringify(ev.payload).slice(0, 160)}${C.reset}`);
    }
  }

  // 3. Persist atomically
  await db.recordBatch(tenantId, installId, events);

  // 4. Device leg of the action channel: hand any pending terminate
  //    commands for these sessions back to the SDK in the batch response.
  //    (The SDK uploads every 15s, so command latency is bounded by that.)
  const sessionIds = [...new Set(events.map(e => e.sessionId).filter(Boolean))];
  const commands = await db.pendingDeviceCommands(tenantId, sessionIds);
  if (commands.length) {
    await db.markDeviceDelivered(commands.map(c => c.id));
    for (const c of commands) {
      console.log(`  ${C.red}⇠ command${C.reset} ${c.kind} -> device ` +
          `(session ${String(c.target.sessionId).slice(0, 8)}…)`);
    }
  }
  json(res, 200, {
    accepted: events.length,
    commands: commands.map(c => ({ id: c.id, kind: c.kind, ...c.target })),
  });
}

// ---------- bank transaction feed ----------

/**
 * POST /v1/transactions — the tenant's core banking pushes settled ledger
 * movements (both directions). Same HMAC scheme as /v1/events: X-Tenant-Id
 * + X-Signature over the raw body. Body: {"transactions": [...]}.
 * Replays are absorbed (txnRef is unique); every account that gained an
 * OUT movement is re-checked for mule velocity, which can raise an alert
 * with no app session involved at all.
 */
async function handleTransactions(req, res) {
  const raw = await readBody(req);
  const tenantId = req.headers['x-tenant-id'];
  const sigHeader = req.headers['x-signature'] || '';
  const key = TENANTS[tenantId]?.key;
  if (!key) return json(res, 400, { error: 'unknown tenant: ' + tenantId });

  const a = Buffer.from(sigHeader), b = Buffer.from(hmacB64(key, raw));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    console.log(`${C.red}✗ feed signature mismatch${C.reset} tenant=${tenantId}`);
    return json(res, 401, { error: 'bad signature' });
  }

  let body;
  try { body = JSON.parse(raw.toString('utf8')); }
  catch { return json(res, 400, { error: 'bad json' }); }
  const txns = Array.isArray(body) ? body : body.transactions;
  if (!Array.isArray(txns)) return json(res, 400, { error: 'transactions must be an array' });

  for (const t of txns) {
    if (!t.txnRef || !t.accountRef || !['IN', 'OUT'].includes(t.direction) ||
        !(Number(t.amount) > 0)) {
      return json(res, 400, { error: 'each txn needs txnRef, accountRef, direction IN|OUT, amount > 0' });
    }
  }

  const { inserted, outAccounts } = await db.recordBankTxns(tenantId, txns);
  console.log(`\n${C.cyan}⇄ feed${C.reset} tenant=${tenantId} txns=${txns.length} ` +
      `new=${inserted} outAccounts=${outAccounts.length}`);

  // Ledger detectors, each with its own typology and 24h dedupe per account.
  const alerts = [];
  for (const accountRef of outAccounts) {
    const userRef = txns.find(t => t.accountRef === accountRef && t.userRef)?.userRef || null;

    const detectors = [
      { threatType: 'Money Mule', label: 'mule pattern',
        run: async () => {
          const flow = await db.getAccountFlow(tenantId, accountRef);
          return { result: scoring.scoreAccountFlow(flow),
                   txn: { accountRef, in72: flow.in72, out24: flow.out24,
                          fanOut24: flow.fanOut24 } };
        } },
      { threatType: 'Agent Commission Fraud', label: 'commission pattern',
        run: async () => {
          const stats = await db.getAgentActivity(tenantId, accountRef);
          return { result: scoring.scoreAgentActivity(stats),
                   txn: { accountRef, txns24h: stats.total24,
                          topCounterparty: stats.topCpRef,
                          splitSum: stats.topCpSum } };
        } },
    ];

    for (const d of detectors) {
      if (await db.hasRecentOpenAlert(tenantId, accountRef, d.threatType)) continue;
      const { result: r, txn } = await d.run();
      if (r.score < 85) continue;
      const id = await db.raiseAlert(tenantId, {
        accountRef, userRef, score: r.score, threatType: d.threatType,
        signal: r.summary, signals: r.signals, txn,
      });
      alerts.push(id);
      console.log(`  ${C.red}▲ ${d.label}${C.reset} account=${accountRef.slice(0, 8)}… ` +
          `score=${r.score} alert=${id}`);
      for (const s of r.signals) {
        console.log(`    ${C.dim}+${s.weight} ${s.code} — ${s.evidence}${C.reset}`);
      }
    }
  }

  json(res, 200, { accepted: inserted, duplicates: txns.length - inserted, alerts });
}

// ---------- scoring ----------

async function handleScore(req, res) {
  const raw = await readBody(req);
  let body;
  try { body = JSON.parse(raw.toString('utf8')); }
  catch { return json(res, 400, { error: 'bad json' }); }

  const v = verifySessionToken(body.sessionToken || '');
  if (!v.ok) return json(res, 401, { error: 'invalid session token: ' + v.reason });

  const txn = body.transaction || {};

  // Behavioral scoring over the stored evidence for this session + user history
  const ctx = await db.getScoringContext(
    v.payload.t, v.payload.s, v.payload.u || null, v.payload.d || null);
  const result = scoring.score(ctx, txn);

  // Policy bands: 0–54 approve · 55–84 step-up · 85–100 hold for analyst
  const decision = result.score >= 85 ? 'HOLD' : result.score >= 55 ? 'STEP_UP' : 'ALLOW';
  const intervention = scoring.interventionFor(decision, result.threatType);

  const alertId = await db.recordDecision({
    tenantId: v.payload.t, sessionId: v.payload.s, installId: v.payload.d,
    userRef: v.payload.u || null, txnRef: txn.txnRef, txn,
    decision, score: result.score, reasons: result.reasons,
    signals: result.signals, threatType: result.threatType,
    signal: result.summary,
  });

  console.log(`\n${C.yellow}⚖ score${C.reset} txn=${txn.txnRef} tenant=${v.payload.t} ` +
      `session=${String(v.payload.s).slice(0, 8)}… -> ${decision} (${result.score})` +
      (result.threatType ? ` ${C.mag}${result.threatType}${C.reset}` : '') +
      (alertId ? `  ${C.red}alert ${alertId}${C.reset}` : ''));
  for (const s of result.signals) {
    console.log(`    ${C.dim}+${s.weight} ${s.code} — ${s.evidence}${C.reset}`);
  }

  json(res, 200, {
    decision,
    riskScore: result.score,
    reasons: result.reasons,
    signals: result.signals,
    threatType: result.threatType,
    intervention,
    alertId,
    session: { tenantId: v.payload.t, sessionId: v.payload.s,
               installId: v.payload.d, userRef: v.payload.u || null },
  });
}

// ---------- console API ----------

/**
 * Resolve Authorization: Bearer <credential> to an identity:
 * an analyst session token (DB-backed, revocable, role-ranked), or a
 * legacy machine/service key (senior-level, cannot manage the team).
 */
async function resolveAuth(req) {
  const auth = req.headers['authorization'] || '';
  const cred = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!cred) return null;
  if (CONSOLE_KEYS[cred]) {
    return { tenantId: CONSOLE_KEYS[cred], token: cred,
             actor: { email: 'service-key', role: 'service', rank: ROLE_RANK.service } };
  }
  const s = await db.resolveAnalystToken(cred);
  if (!s) return null;
  return { tenantId: s.tenant_id, token: cred,
           actor: { id: s.analyst_id, email: s.email, name: s.name,
                    role: s.role, rank: ROLE_RANK[s.role] ?? 0 } };
}

// [method, pattern, handler(tenantId, match, query, body, actor), minRank]
const routes = [
  ['GET', /^\/v1\/console\/me$/, (t, m, q, b, actor) => actor, RANK.READ],
  ['GET', /^\/v1\/console\/overview$/, (t) => db.overview(t), RANK.READ],
  ['GET', /^\/v1\/console\/alerts$/, (t, m, q) => db.listAlerts(t, q), RANK.READ],
  ['GET', /^\/v1\/console\/alerts\/([\w-]+)$/, (t, m) => db.getAlert(t, m[1]), RANK.READ],
  ['PATCH', /^\/v1\/console\/alerts\/([\w-]+)$/,
    (t, m, q, b) => db.updateAlert(t, m[1], b), RANK.ANALYST],
  ['POST', /^\/v1\/console\/alerts\/([\w-]+)\/case$/,
    async (t, m, q, b, actor) => {
      const caseId = await db.createCase(t, m[1], { ...b, actor: actor.email });
      return caseId ? { caseId } : null;
    }, RANK.ANALYST],
  ['GET', /^\/v1\/console\/cases$/, (t, m, q) => db.listCases(t, q), RANK.READ],
  ['GET', /^\/v1\/console\/cases\/([\w-]+)$/, (t, m) => db.getCase(t, m[1]), RANK.READ],
  ['PATCH', /^\/v1\/console\/cases\/([\w-]+)$/,
    (t, m, q, b, actor) => db.updateCase(t, m[1], { ...b, actor: actor.email }),
    RANK.ANALYST],
  ['GET', /^\/v1\/console\/users\/([\w-]+)$/, (t, m) => db.getUserProfile(t, m[1]), RANK.READ],
  ['GET', /^\/v1\/console\/sessions\/([\w-]+)\/events$/,
    (t, m) => db.getSessionEvents(t, m[1]), RANK.READ],
  ['GET', /^\/v1\/console\/accounts\/([\w-]+)\/transactions$/,
    (t, m) => db.listAccountTxns(t, m[1]), RANK.READ],
  ['GET', /^\/v1\/console\/actions$/, (t, m, q) => db.listActions(t, q), RANK.READ],
  ['POST', /^\/v1\/console\/alerts\/([\w-]+)\/actions$/,
    async (t, m, q, b, actor) => {
      const action = await db.createAction(t, m[1], { ...b, requestedBy: actor.email });
      if (action === null) return null;                    // alert not found
      if (action.error) return { _status: 400, ...action };
      const webhookStatus = await deliverAction(t, action);
      return { ...action, webhook_status: webhookStatus };
    }, RANK.SENIOR],
  // Team management — admin only, never service keys.
  ['GET', /^\/v1\/console\/team$/, (t) => db.listAnalysts(t), RANK.ADMIN],
  ['POST', /^\/v1\/console\/team$/,
    async (t, m, q, b) => {
      const a = await db.createAnalyst(t, b);
      return a.error ? { _status: 400, ...a } : a;
    }, RANK.ADMIN],
  ['PATCH', /^\/v1\/console\/team\/(\d+)$/,
    async (t, m, q, b) => {
      const a = await db.updateAnalyst(t, Number(m[1]), b);
      return a?.error ? { _status: 400, ...a } : a;
    }, RANK.ADMIN],
];

async function handleConsole(req, res, url) {
  // Login is the only unauthenticated console route.
  if (req.method === 'POST' && url.pathname === '/v1/console/login') {
    let body;
    try { body = JSON.parse((await readBody(req)).toString('utf8') || '{}'); }
    catch { return json(res, 400, { error: 'bad json' }); }
    const analyst = await db.verifyLogin(body.email || '', body.password || '');
    if (!analyst) return json(res, 401, { error: 'invalid credentials' });
    const s = await db.createAnalystSession(analyst.id);
    console.log(`${C.cyan}⚿ login${C.reset} ${analyst.email} (${analyst.role})`);
    return json(res, 200, {
      token: s.token, expiresAt: s.expiresAt,
      analyst: { email: analyst.email, name: analyst.name, role: analyst.role },
    });
  }

  const auth = await resolveAuth(req);
  if (!auth) return json(res, 401, { error: 'missing or invalid credentials' });
  const { tenantId, actor } = auth;

  if (req.method === 'POST' && url.pathname === '/v1/console/logout') {
    if (actor.role !== 'service') await db.deleteAnalystSession(auth.token);
    return json(res, 200, { ok: true });
  }

  for (const [method, re, fn, minRank] of routes) {
    const m = url.pathname.match(re);
    if (req.method === method && m) {
      if (actor.rank < (minRank || 0)) {
        return json(res, 403, { error: `requires ${Object.keys(RANK)
          .find(k => RANK[k] === minRank).toLowerCase()} role or higher`, role: actor.role });
      }
      let body = {};
      if (method !== 'GET') {
        try { body = JSON.parse((await readBody(req)).toString('utf8') || '{}'); }
        catch { return json(res, 400, { error: 'bad json' }); }
      }
      const query = Object.fromEntries(url.searchParams);
      const out = await fn(tenantId, m, query, body, actor);
      if (out === null) return json(res, 404, { error: 'not found' });
      if (out && out._status) {
        const { _status, ...rest } = out;
        return json(res, _status, rest);
      }
      return json(res, 200, out);
    }
  }
  json(res, 404, { error: 'not found' });
}

// ---------- server ----------

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    if (req.method === 'POST' && url.pathname === '/v1/events') return await handleEvents(req, res);
    if (req.method === 'POST' && url.pathname === '/v1/transactions') return await handleTransactions(req, res);
    if (req.method === 'POST' && url.pathname === '/v1/score') return await handleScore(req, res);
    if (url.pathname.startsWith('/v1/console/')) return await handleConsole(req, res, url);
    if (req.method === 'GET' && url.pathname === '/stats')
      return json(res, 200, await db.eventTypeCounts());
    json(res, 404, { error: 'not found' });
  } catch (e) {
    console.error(e);
    json(res, 500, { error: 'internal' });
  }
});

db.init(Object.keys(TENANTS)).then(async () => {
  const adminEmail = process.env.CONSOLE_ADMIN_EMAIL || 'admin@demobank.cz';
  const seeded = await db.seedAdmin('wallet-acme', adminEmail,
    process.env.CONSOLE_ADMIN_PASSWORD || 'admin-dev-password');
  if (seeded) {
    console.log(`Seeded bootstrap admin ${adminEmail} ` +
      `(password from CONSOLE_ADMIN_PASSWORD, default admin-dev-password)`);
  }
  server.listen(PORT, () => {
    console.log(`Fraud ingest server on http://localhost:${PORT}`);
    console.log(`  POST /v1/events  (SDK batches)   POST /v1/transactions  (bank feed)   POST /v1/score  (token join -> alerts)`);
    console.log(`  GET  /v1/console/*  (Bearer key)   GET /stats`);
    console.log(`  Tenants: ${Object.keys(TENANTS).join(', ')}  ->  Postgres ${process.env.DATABASE_URL || 'postgresql://localhost/vera_fraud'}\n`);
  });
}).catch(e => {
  console.error('DB init failed — is Postgres running and vera_fraud created?', e.message);
  process.exit(1);
});
