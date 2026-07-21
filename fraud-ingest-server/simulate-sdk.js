/**
 * Simulates the Android SDK: builds signed gzipped NDJSON batches and
 * session tokens exactly the way the Java SDK does, then drives the
 * server. Doubles as the wire-format reference for future JS/Flutter SDKs.
 *
 * Run: node simulate-sdk.js [scenario] [baseUrl]
 *
 * Scenarios:
 *   wire     (default) one raw batch + one scoring call — wire-format demo
 *   clean    known user, known device, usual behavior      -> ALLOW
 *   coached  in-call + hesitation + new payee + big amount -> HOLD, APP Scam
 *   ato      new device + hooking + alien touch cadence    -> HOLD, Account Takeover
 *   mule     dormant 8 months + SIM swap + rapid big txn   -> HOLD, Money Mule
 *
 * Behavioral scenarios first replay a few historical sessions (backdated
 * event timestamps) so the scoring engine has baselines to compare against.
 */
const zlib = require('zlib');
const crypto = require('crypto');

const args = process.argv.slice(2);
const BASE = args.find(a => a.startsWith('http')) || 'http://localhost:8080';
const SCENARIO = args.find(a => !a.startsWith('http')) || 'wire';

const TENANT = process.env.TENANT || 'wallet-acme';
// Tenant HMAC key — override with SDK_KEY to target a server whose key was
// rotated (e.g. the deployed instance): SDK_KEY=<key> KEY_ID=<kid> node …
const KEY = Buffer.from(process.env.SDK_KEY || '0123456789abcdef0123456789abcdef');
const KEY_ID = process.env.KEY_ID || 'k1';   // key version advertised on uploads
const DAY = 86400000;

const b64url = b => b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function mintToken(sessionId, installId, userRef) {
  const payload = { t: TENANT, s: sessionId, d: installId,
                    iat: Math.floor(Date.now() / 1000) };
  if (userRef) payload.u = userRef;
  const body = b64url(Buffer.from(JSON.stringify(payload), 'utf8'));
  const sig = b64url(crypto.createHmac('sha256', KEY).update(body, 'utf8').digest());
  return body + '.' + sig;
}

/** Client-generated event id, stamped like the real SDKs do — the server
 *  may use it to dedupe resent batches (at-least-once uploads). */
const stamp = (events) =>
  events.map(e => e.eventId ? e : { eventId: crypto.randomUUID(), ...e });

async function sendBatch(installId, events) {
  const gz = zlib.gzipSync(stamp(events).map(e => JSON.stringify(e)).join('\n'));
  const sig = crypto.createHmac('sha256', KEY).update(gz).digest('base64');
  const r = await fetch(BASE + '/v1/events', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-ndjson', 'Content-Encoding': 'gzip',
               'X-Tenant-Id': TENANT, 'X-Install-Id': installId,
               'X-Signature': sig, 'X-Key-Id': KEY_ID, 'X-Sdk': 'simulator/0.2.0' },
    body: gz,
  });
  if (r.status !== 200) throw new Error('/v1/events -> ' + r.status + ' ' + await r.text());
  return r.json();   // {accepted, commands: [...]} — the device leg of the action channel
}

const SITE_KEY = process.env.SITE_KEY || 'site_wallet-acme_pub';
const WEB_ORIGIN = 'http://localhost:5199';

/** Browser SDK collector batch — public site-key + Origin (no HMAC). */
async function sendCollect(installId, events) {
  const r = await fetch(BASE + '/v1/collect', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-ndjson', 'X-Tenant-Id': TENANT,
               'X-Site-Key': SITE_KEY, 'X-Install-Id': installId, 'X-Sdk': 'web/0.1.0',
               'Origin': WEB_ORIGIN },
    body: stamp(events).map(e => JSON.stringify(e)).join('\n'),
  });
  if (r.status !== 200) throw new Error('/v1/collect -> ' + r.status + ' ' + await r.text());
  return r.json();
}

/** Server-minted session token for a browser session. */
async function collectToken(sessionId, installId, userRef) {
  const r = await fetch(BASE + '/v1/collect/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Tenant-Id': TENANT,
               'X-Site-Key': SITE_KEY, 'Origin': WEB_ORIGIN },
    body: JSON.stringify({ sessionId, installId, userRef }),
  });
  return (await r.json()).token;
}

// Mouse "strokes" (same shape as touch): human = slower, curvier.
const mouseStrokes = (n, dur, gap, straight) => Array.from({ length: n }, () => ({
  t: Date.now(), dur: Math.round(rnd(dur * 0.85, dur * 1.15)), len: Math.round(rnd(20, 200)),
  straight: straight != null ? straight : Math.round(rnd(60, 95)) / 100,
  gap: Math.round(rnd(gap * 0.8, gap * 1.2)),
}));

const normalUA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36';

/** Replay clean web sessions to seed a mouse baseline + known browser. */
async function buildWebHistory(u, daysAgo, amounts) {
  for (let i = 0; i < daysAgo.length; i++) {
    const t0 = Date.now() - daysAgo[i] * DAY;
    const sid = crypto.randomUUID();
    await sendCollect(u.install, [
      { type: 'PASSIVE_WEB_FINGERPRINT', sessionId: sid, installId: u.install, ts: t0,
        payload: { userAgent: normalUA, headless: false, botFlags: [], hardwareConcurrency: 8,
                   screenW: 1920, screenH: 1080, languages: ['en-US'] } },
      { type: 'BIZ_LOGIN_RESULT', sessionId: sid, installId: u.install, userRef: u.ref,
        ts: t0 + 2000, payload: { outcome: 'SUCCESS' } },
      { type: 'PASSIVE_MOUSE_STROKES', sessionId: sid, installId: u.install, userRef: u.ref,
        ts: t0 + 40000, payload: { strokes: mouseStrokes(12, 300, 500) } },
      { type: 'BIZ_TXN_INITIATED', sessionId: sid, installId: u.install, userRef: u.ref,
        ts: t0 + 90000, payload: { amountBucket: 'LOW', currency: 'CZK', payeeIsNew: false, channel: 'BANK_TRANSFER' } },
    ]);
    if (amounts[i]) {
      const tok = await collectToken(sid, u.install, u.ref);
      await sendScore(tok, { txnRef: 'WHIST-' + i, amount: amounts[i], currency: 'CZK', payeeIsNew: false });
    }
  }
}

/** Bank-side feed batch — signed JSON, same HMAC scheme as event batches. */
async function sendFeed(txns) {
  const raw = Buffer.from(JSON.stringify({ transactions: txns }), 'utf8');
  const sig = crypto.createHmac('sha256', KEY).update(raw).digest('base64');
  const r = await fetch(BASE + '/v1/transactions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json',
               'X-Tenant-Id': TENANT, 'X-Signature': sig },
    body: raw,
  });
  if (r.status !== 200) throw new Error('/v1/transactions -> ' + r.status + ' ' + await r.text());
  return r.json();
}

async function sendScore(token, txn) {
  const r = await fetch(BASE + '/v1/score', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sessionToken: token, transaction: txn }),
  });
  return r.json();
}

const rnd = (a, b) => a + Math.random() * (b - a);
const strokes = (n, dur, gap) => Array.from({ length: n }, () => ({
  dur: Math.round(rnd(dur * 0.85, dur * 1.15)), len: Math.round(rnd(3, 40)),
  straight: Math.round(rnd(80, 100)) / 100, pAvg: Math.round(rnd(30, 55)) / 100,
  pMax: Math.round(rnd(45, 70)) / 100, gap: Math.round(rnd(gap * 0.8, gap * 1.2)),
}));

const keys = (n, dt) => Array.from({ length: n }, (_, i) => ({
  dt: i === 0 ? -1 : Math.round(rnd(dt * 0.8, dt * 1.2)), op: 'i',
}));

const noCall = { inGsmCall: false, inVoipCall: false, speakerOn: false };

/** One well-behaved historical session: login, browsing, a small payment. */
function historySession(user, t0) {
  const s = crypto.randomUUID();
  const ev = [
    { type: 'PASSIVE_DEVICE_FINGERPRINT', sessionId: s, installId: user.install, ts: t0,
      payload: { manufacturer: 'Samsung', model: 'SM-A546', sdkInt: 34 } },
    { type: 'PASSIVE_LOCATION_COARSE', sessionId: s, installId: user.install, ts: t0,
      payload: { tier: 'GEOHASH5', geohash: user.geohash, ageMs: 42000 } },
    { type: 'BIZ_LOGIN_RESULT', sessionId: s, installId: user.install, userRef: user.ref,
      ts: t0 + 2000, payload: { outcome: 'SUCCESS' }, callSignals: noCall },
    { type: 'PASSIVE_TOUCH_STROKES', sessionId: s, installId: user.install, userRef: user.ref,
      ts: t0 + 40000, payload: { strokes: strokes(10, user.dur, user.gap) } },
    { type: 'PASSIVE_KEYSTROKES', sessionId: s, installId: user.install, userRef: user.ref,
      ts: t0 + 70000, payload: { fieldId: 'transfer.amount', keys: keys(15, user.keyDt) } },
    { type: 'BIZ_TXN_INITIATED', sessionId: s, installId: user.install, userRef: user.ref,
      ts: t0 + 95000, callSignals: noCall,
      payload: { amountBucket: 'LOW', currency: 'CZK', payeeIsNew: false, channel: 'BILL' } },
  ];
  return { sessionId: s, events: ev };
}

/** Replay history + build amount profile via ALLOW-scored small payments. */
async function buildHistory(user, daysAgo, amounts) {
  for (let i = 0; i < daysAgo.length; i++) {
    const t0 = Date.now() - daysAgo[i] * DAY;
    const h = historySession(user, t0);
    await sendBatch(user.install, h.events);
    if (amounts[i]) {
      await sendScore(mintToken(h.sessionId, user.install, user.ref),
        { txnRef: 'HIST-' + i, amount: amounts[i], currency: 'CZK', payeeIsNew: false });
    }
  }
}

function newUser() {
  return {
    ref: crypto.createHash('sha256').update('salt+' + crypto.randomUUID()).digest('hex'),
    install: crypto.randomUUID(),
    geohash: 'u2fkb8x', dur: 110, gap: 350, keyDt: 180,
  };
}

function report(name, expect, got) {
  const ok = got.decision === expect.decision &&
             (expect.threatType === undefined || got.threatType === expect.threatType);
  console.log(`\n${ok ? '✓' : '✗'} ${name}: ${got.decision} (${got.riskScore})` +
      (got.threatType ? ` — ${got.threatType}` : '') +
      (got.alertId ? `  alert=${got.alertId}` : ''));
  for (const s of got.signals || []) console.log(`    +${s.weight} ${s.code} — ${s.evidence}`);
  if (!ok) {
    console.log(`  EXPECTED ${expect.decision}` +
        (expect.threatType ? ` / ${expect.threatType}` : ''));
    process.exitCode = 1;
  }
}

// ---------------- scenarios ----------------

const scenarios = {

  /** Original raw demo — the wire-format reference. */
  async wire() {
    const u = newUser();
    const s = crypto.randomUUID();
    const now = Date.now();
    await sendBatch(u.install, [
      { type: 'PASSIVE_DEVICE_FINGERPRINT', sessionId: s, installId: u.install, ts: now,
        payload: { manufacturer: 'Tecno', model: 'Spark 10', sdkInt: 33, screenW: 720, screenH: 1600 } },
      { type: 'PASSIVE_SIM_TELEMETRY', sessionId: s, installId: u.install, ts: now,
        payload: { networkOperator: '61302', subscriptionCount: 2, simChangedSinceLastSession: true } },
      { type: 'BIZ_LOGIN_RESULT', sessionId: s, installId: u.install, userRef: u.ref,
        ts: now + 1000, payload: { outcome: 'SUCCESS' }, callSignals: noCall },
      { type: 'PASSIVE_TOUCH_STROKES', sessionId: s, installId: u.install, userRef: u.ref,
        ts: now + 5000, payload: { strokes: strokes(5, 110, 350) } },
      { type: 'BIZ_TXN_INITIATED', sessionId: s, installId: u.install, userRef: u.ref,
        ts: now + 9000, payload: { amountBucket: 'HIGH', currency: 'XOF', payeeIsNew: true, channel: 'P2P' },
        callSignals: { inGsmCall: false, inVoipCall: true, speakerOn: true } },
    ]);
    const got = await sendScore(mintToken(s, u.install, u.ref),
      { txnRef: 'TXN-TEST-1', amount: 750000, currency: 'XOF', payeeIsNew: true, channel: 'P2P' });
    console.log('/v1/score ->', JSON.stringify(got, null, 2));
  },

  /** Known user, known device, usual everything -> ALLOW. */
  async clean() {
    const u = newUser();
    await buildHistory(u, [30, 14, 2], [4000, 5000, 4500]);
    const t0 = Date.now();
    const s = crypto.randomUUID();
    await sendBatch(u.install, [
      { type: 'PASSIVE_LOCATION_COARSE', sessionId: s, installId: u.install, ts: t0,
        payload: { tier: 'GEOHASH5', geohash: u.geohash, ageMs: 30000 } },
      { type: 'BIZ_LOGIN_RESULT', sessionId: s, installId: u.install, userRef: u.ref,
        ts: t0 + 2000, payload: { outcome: 'SUCCESS' }, callSignals: noCall },
      { type: 'PASSIVE_TOUCH_STROKES', sessionId: s, installId: u.install, userRef: u.ref,
        ts: t0 + 45000, payload: { strokes: strokes(10, u.dur, u.gap) } },
      { type: 'PASSIVE_KEYSTROKES', sessionId: s, installId: u.install, userRef: u.ref,
        ts: t0 + 70000, payload: { fieldId: 'transfer.amount', keys: keys(15, u.keyDt) } },
      { type: 'BIZ_TXN_INITIATED', sessionId: s, installId: u.install, userRef: u.ref,
        ts: t0 + 90000, callSignals: noCall,
        payload: { amountBucket: 'LOW', currency: 'CZK', payeeIsNew: false, channel: 'BILL' } },
    ]);
    report('clean', { decision: 'ALLOW' },
      await sendScore(mintToken(s, u.install, u.ref),
        { txnRef: 'TXN-CLEAN', amount: 5200, currency: 'CZK', payeeIsNew: false }));
  },

  /** Coached APP scam: active VoIP call, hesitation, new payee, 50x amount. */
  async coached() {
    const u = newUser();
    await buildHistory(u, [30, 14, 2], [4000, 5000, 4500]);
    const t0 = Date.now();
    const s = crypto.randomUUID();
    const inCall = { inGsmCall: false, inVoipCall: true, speakerOn: true };
    await sendBatch(u.install, [
      { type: 'PASSIVE_LOCATION_COARSE', sessionId: s, installId: u.install, ts: t0,
        payload: { tier: 'GEOHASH5', geohash: u.geohash, ageMs: 30000 } },
      { type: 'BIZ_LOGIN_RESULT', sessionId: s, installId: u.install, userRef: u.ref,
        ts: t0 + 2000, payload: { outcome: 'SUCCESS' }, callSignals: noCall },
      { type: 'PASSIVE_TOUCH_STROKES', sessionId: s, installId: u.install, userRef: u.ref,
        ts: t0 + 120000, payload: { strokes: strokes(10, u.dur, u.gap) } },
      { type: 'BIZ_PAYEE_ADDED', sessionId: s, installId: u.install, userRef: u.ref,
        ts: t0 + 300000, callSignals: inCall,
        payload: { payeeRef: 'p-' + crypto.randomUUID().slice(0, 8), channel: 'BANK' } },
      { type: 'PASSIVE_KEYSTROKES', sessionId: s, installId: u.install, userRef: u.ref,
        ts: t0 + 420000,
        payload: { fieldId: 'transfer.amount',
                   keys: [{ dt: -1, op: 'i' }, { dt: 6200, op: 'i' }, { dt: 400, op: 'd' },
                          { dt: 300, op: 'd' }, { dt: 5100, op: 'i' }, { dt: 700, op: 'd' }] } },
      { type: 'BIZ_TXN_INITIATED', sessionId: s, installId: u.install, userRef: u.ref,
        ts: t0 + 540000, callSignals: inCall,
        payload: { amountBucket: 'VERY_HIGH', currency: 'CZK', payeeIsNew: true, channel: 'BANK_TRANSFER' } },
    ]);
    const got = await sendScore(mintToken(s, u.install, u.ref),
      { txnRef: 'TXN-COACHED', amount: 240000, currency: 'CZK', payeeIsNew: true });
    report('coached', { decision: 'HOLD', threatType: 'APP Scam' }, got);
    return { sessionId: s, user: u, alertId: got.alertId };
  },

  /** Account takeover: brand-new device, frida, alien touch tempo, alien geo. */
  async ato() {
    const u = newUser();
    await buildHistory(u, [30, 14, 2], [4000, 5000, 4500]);
    const attacker = crypto.randomUUID();   // new install, same victim userRef
    const t0 = Date.now();
    const s = crypto.randomUUID();
    await sendBatch(attacker, [
      { type: 'PASSIVE_APP_INTEGRITY', sessionId: s, installId: attacker, ts: t0,
        payload: { rootLikely: true, emulatorLikely: false, hookingFramework: 'frida',
                   accessibilityServices: [] } },
      { type: 'PASSIVE_LOCATION_COARSE', sessionId: s, installId: attacker, ts: t0,
        payload: { tier: 'GEOHASH5', geohash: 'u336xpr', ageMs: 10000 } },
      { type: 'BIZ_LOGIN_RESULT', sessionId: s, installId: attacker, userRef: u.ref,
        ts: t0 + 2000, payload: { outcome: 'SUCCESS' }, callSignals: noCall },
      { type: 'PASSIVE_TOUCH_STROKES', sessionId: s, installId: attacker, userRef: u.ref,
        ts: t0 + 20000, payload: { strokes: strokes(12, 45, 90) } },   // scripted tempo
      { type: 'PASSIVE_KEYSTROKES', sessionId: s, installId: attacker, userRef: u.ref,
        ts: t0 + 30000,
        payload: { fieldId: 'transfer.amount', keys: keys(15, 55) } }, // scripted typing
      { type: 'BIZ_TXN_INITIATED', sessionId: s, installId: attacker, userRef: u.ref,
        ts: t0 + 40000, callSignals: noCall,
        payload: { amountBucket: 'MID', currency: 'CZK', payeeIsNew: false, channel: 'BANK_TRANSFER' } },
    ]);
    report('ato', { decision: 'HOLD', threatType: 'Account Takeover' },
      await sendScore(mintToken(s, attacker, u.ref),
        { txnRef: 'TXN-ATO', amount: 8000, currency: 'CZK', payeeIsNew: false }));
  },

  /** Money mule: 8 months dormant, SIM swap, fresh inbound via the bank
   *  feed, then a big transfer 15s after login. */
  async mule() {
    const u = newUser();
    await buildHistory(u, [240], []);       // one old session, no spending history
    const acct = 'acc-' + crypto.randomUUID().slice(0, 12);
    await sendFeed([{ txnRef: 'F-' + crypto.randomUUID().slice(0, 8), accountRef: acct,
                      userRef: u.ref, direction: 'IN', amount: 650000, currency: 'CZK',
                      counterpartyRef: 'cp-source', channel: 'BANK_TRANSFER',
                      ts: Date.now() - 10 * 60000 }]);
    const t0 = Date.now();
    const s = crypto.randomUUID();
    await sendBatch(u.install, [
      { type: 'PASSIVE_SIM_TELEMETRY', sessionId: s, installId: u.install, ts: t0,
        payload: { networkOperator: '23002', subscriptionCount: 1, simChangedSinceLastSession: true } },
      { type: 'BIZ_LOGIN_RESULT', sessionId: s, installId: u.install, userRef: u.ref,
        ts: t0 + 1000, payload: { outcome: 'SUCCESS' }, callSignals: noCall },
      { type: 'BIZ_TXN_INITIATED', sessionId: s, installId: u.install, userRef: u.ref,
        ts: t0 + 15000, callSignals: noCall,
        payload: { amountBucket: 'VERY_HIGH', currency: 'CZK', payeeIsNew: true, channel: 'P2P' } },
    ]);
    report('mule', { decision: 'HOLD', threatType: 'Money Mule' },
      await sendScore(mintToken(s, u.install, u.ref),
        { txnRef: 'TXN-MULE', amount: 600000, currency: 'CZK', payeeIsNew: true }));
  },

  /** Pure ledger mule: no app session at all. Quiet account receives 95k,
   *  splits it to three counterparties within the hour — the feed handler
   *  alone must raise the alert, and a replay must not raise a second one. */
  async feedmule() {
    const acct = 'acc-' + crypto.randomUUID().slice(0, 12);
    const mk = () => 'F-' + crypto.randomUUID().slice(0, 8);
    await sendFeed([{ txnRef: mk(), accountRef: acct, direction: 'IN', amount: 95000,
                      currency: 'CZK', counterpartyRef: 'cp-victim',
                      channel: 'BANK_TRANSFER', ts: Date.now() - 30 * 60000 }]);
    const outs = ['cp-x1', 'cp-x2', 'cp-x3'].map((cp, i) => ({
      txnRef: mk(), accountRef: acct, direction: 'OUT', amount: 31000,
      currency: 'CZK', counterpartyRef: cp, channel: 'P2P',
      ts: Date.now() - (3 - i) * 60000 }));
    const got = await sendFeed(outs);
    const replay = await sendFeed(outs);   // idempotency: same batch again

    const ok = got.alerts.length === 1 &&
               replay.accepted === 0 && replay.alerts.length === 0;
    console.log(`\n${ok ? '✓' : '✗'} feedmule: alert=${got.alerts[0] || 'none'} ` +
        `(no session) · replay accepted=${replay.accepted} alerts=${replay.alerts.length}`);
    if (!ok) {
      console.log('  EXPECTED exactly one alert on first send, none on replay', got, replay);
      process.exitCode = 1;
    }
  },

  /** Agent commission fraud ("fraude à la commission agent"): an agent
   *  splits one deposit into a burst of near-identical small cash-ins to
   *  the same customer to farm per-transaction commissions. Ledger-only;
   *  a follow-up txn must not raise a duplicate alert. */
  async agent() {
    const acct = 'agt-' + crypto.randomUUID().slice(0, 12);
    const mk = () => 'F-' + crypto.randomUUID().slice(0, 8);
    const t = i => Date.now() - (120 - i * 9) * 60000;   // spread over ~2h
    const split = Array.from({ length: 8 }, (_, i) => ({
      txnRef: mk(), accountRef: acct, direction: 'OUT', amount: 9500,
      currency: 'XOF', counterpartyRef: 'cp-cust-1', channel: 'CASH_OUT', ts: t(i) }));
    const noise = Array.from({ length: 4 }, (_, i) => ({
      txnRef: mk(), accountRef: acct, direction: 'OUT', amount: 9000,
      currency: 'XOF', counterpartyRef: 'cp-cust-' + (i + 2), channel: 'CASH_OUT',
      ts: t(i + 8) }));
    const got = await sendFeed([...split, ...noise]);
    const followUp = await sendFeed([{ txnRef: mk(), accountRef: acct, direction: 'OUT',
      amount: 9500, currency: 'XOF', counterpartyRef: 'cp-cust-1', channel: 'CASH_OUT',
      ts: Date.now() }]);

    const ok = got.alerts.length === 1 && followUp.alerts.length === 0;
    console.log(`\n${ok ? '✓' : '✗'} agent: alert=${got.alerts[0] || 'none'} ` +
        `(commission split) · follow-up alerts=${followUp.alerts.length}`);
    if (!ok) {
      console.log('  EXPECTED one Agent Commission Fraud alert, no duplicate', got, followUp);
      process.exitCode = 1;
    }
  },

  /** Analyst auth + RBAC: bootstrap admin logs in, builds the team, and
   *  every role is probed against the endpoints it must and must not
   *  reach. Also checks logout revocation and legacy service-key limits. */
  async auth() {
    const api = (path, { method = 'GET', token, body } = {}) =>
      fetch(BASE + path, {
        method,
        headers: { 'Content-Type': 'application/json',
                   ...(token ? { Authorization: 'Bearer ' + token } : {}) },
        body: body ? JSON.stringify(body) : undefined,
      }).then(async r => ({ status: r.status, body: await r.json().catch(() => ({})) }));
    const login = (email, password) =>
      api('/v1/console/login', { method: 'POST', body: { email, password } });

    // 1. Bootstrap admin; wrong password must fail.
    const bad = await login('admin@demobank.cz', 'wrong-password');
    const adm = await login('admin@demobank.cz',
      process.env.CONSOLE_ADMIN_PASSWORD || 'admin-dev-password');
    const admin = adm.body.token;

    // 2. Admin builds the team (unique emails so the scenario re-runs).
    const sfx = crypto.randomUUID().slice(0, 8);
    const mk = (role) => api('/v1/console/team', { method: 'POST', token: admin,
      body: { email: `${role}-${sfx}@demobank.cz`, name: role, role,
              password: 'analyst-pass-1' } });
    await mk('readonly'); await mk('analyst'); await mk('senior');
    const ro = (await login(`readonly-${sfx}@demobank.cz`, 'analyst-pass-1')).body.token;
    const an = (await login(`analyst-${sfx}@demobank.cz`, 'analyst-pass-1')).body.token;
    const sr = (await login(`senior-${sfx}@demobank.cz`, 'analyst-pass-1')).body.token;

    // 3. A HOLD alert to act on.
    const { alertId } = await scenarios.coached();

    // 4. Role probes.
    const roRead = await api('/v1/console/alerts', { token: ro });
    const roWrite = await api(`/v1/console/alerts/${alertId}`, { method: 'PATCH',
      token: ro, body: { disposition: 'nope' } });
    const anWrite = await api(`/v1/console/alerts/${alertId}`, { method: 'PATCH',
      token: an, body: { disposition: 'Confirmed fraud — reviewed' } });
    const anAction = await api(`/v1/console/alerts/${alertId}/actions`, { method: 'POST',
      token: an, body: { kind: 'TERMINATE_SESSION' } });
    const srAction = await api(`/v1/console/alerts/${alertId}/actions`, { method: 'POST',
      token: sr, body: { kind: 'TERMINATE_SESSION', note: 'senior kill' } });

    // 5. Audit: the action carries the senior's identity.
    const audit = srAction.body.requested_by === `senior-${sfx}@demobank.cz`;

    // 6. Logout revokes the token.
    await api('/v1/console/logout', { method: 'POST', token: sr });
    const revoked = await api('/v1/console/me', { token: sr });

    // 7. Legacy service key: senior-level, but never team management.
    const svcKey = process.env.CONSOLE_KEY || 'dev-console-key';
    const svcRead = await api('/v1/console/overview', { token: svcKey });
    const svcTeam = await api('/v1/console/team', { token: svcKey });

    const ok =
      bad.status === 401 && adm.status === 200 && adm.body.analyst.role === 'admin' &&
      roRead.status === 200 && roWrite.status === 403 &&
      anWrite.status === 200 && anAction.status === 403 &&
      srAction.status === 200 && audit &&
      revoked.status === 401 &&
      svcRead.status === 200 && svcTeam.status === 403;

    console.log(`\n${ok ? '✓' : '✗'} auth: bad-login=${bad.status} ` +
        `ro read/write=${roRead.status}/${roWrite.status} ` +
        `an write/action=${anWrite.status}/${anAction.status} ` +
        `sr action=${srAction.status} audit=${audit} ` +
        `revoked=${revoked.status} svc read/team=${svcRead.status}/${svcTeam.status}`);
    if (!ok) process.exitCode = 1;
  },

  /** Web SDK (browser) — Go server only (site-key collector + web scoring).
   *  A victim's account is taken over from a headless-automation browser: a
   *  new browser (install), headless fingerprint, and robotic mouse dynamics
   *  that deviate from the user's learned mouse profile. Must HOLD as Account
   *  Takeover with HEADLESS_BROWSER + MOUSE_ANOMALY, via /v1/collect. */
  async web() {
    const u = newUser();
    await buildWebHistory(u, [30, 14, 2], [4000, 5000, 4500]);   // known browser + mouse baseline
    const attacker = crypto.randomUUID();   // new browser, victim's stolen credentials
    const t0 = Date.now();
    const s = crypto.randomUUID();
    await sendCollect(attacker, [
      { type: 'PASSIVE_WEB_FINGERPRINT', sessionId: s, installId: attacker, ts: t0,
        payload: { userAgent: 'Mozilla/5.0 HeadlessChrome/126.0', headless: true,
                   botFlags: ['navigator.webdriver', 'automation UA', 'no plugins'],
                   hardwareConcurrency: 2, screenW: 1280, screenH: 720, languages: [] } },
      { type: 'BIZ_LOGIN_RESULT', sessionId: s, installId: attacker, userRef: u.ref,
        ts: t0 + 2000, payload: { outcome: 'SUCCESS' } },
      { type: 'PASSIVE_MOUSE_STROKES', sessionId: s, installId: attacker, userRef: u.ref,
        ts: t0 + 12000, payload: { strokes: mouseStrokes(12, 45, 60, 1.0) } },   // robotic
      { type: 'BIZ_TXN_INITIATED', sessionId: s, installId: attacker, userRef: u.ref,
        ts: t0 + 20000, payload: { amountBucket: 'HIGH', currency: 'CZK', payeeIsNew: true, channel: 'BANK_TRANSFER' } },
    ]);
    const tok = await collectToken(s, attacker, u.ref);
    const got = await sendScore(tok, { txnRef: 'TXN-WEB', amount: 88000, currency: 'CZK', payeeIsNew: true });
    report('web', { decision: 'HOLD', threatType: 'Account Takeover' }, got);
    const codes = (got.signals || []).map((sg) => sg.code);
    for (const need of ['HEADLESS_BROWSER', 'MOUSE_ANOMALY']) {
      if (!codes.includes(need)) { console.log(`  ✗ expected ${need}`); process.exitCode = 1; }
    }
  },

  /** RAT / remote-access (on-device fraud) — Go server only (REMOTE_ACCESS
   *  scoring is a post-freeze addition). A legit user on a KNOWN device is
   *  remote-controlled: a screen-share is active (extra virtual display +
   *  remote-control accessibility service) and the input is scripted. Must
   *  HOLD as Account Takeover with the REMOTE_ACCESS signal. A second check
   *  proves an overlay (obscured touch) alone also raises REMOTE_ACCESS. */
  async rat() {
    const u = newUser();
    await buildHistory(u, [30, 14, 2], [4000, 5000, 4500]);   // known device + baseline
    const t0 = Date.now();
    const s = crypto.randomUUID();
    const ra = { extraDisplays: 1, displayNames: ['AnyDesk-mirror'],
                 accessibilitySuspect: true, accessibilityMatches: ['com.anydesk.anydeskandroid'],
                 screenShareLikely: true };
    await sendBatch(u.install, [
      { type: 'PASSIVE_REMOTE_ACCESS', sessionId: s, installId: u.install, ts: t0, payload: ra },
      { type: 'PASSIVE_LOCATION_COARSE', sessionId: s, installId: u.install, ts: t0,
        payload: { tier: 'GEOHASH5', geohash: u.geohash, ageMs: 30000 } },
      { type: 'BIZ_LOGIN_RESULT', sessionId: s, installId: u.install, userRef: u.ref,
        ts: t0 + 2000, payload: { outcome: 'SUCCESS' }, callSignals: noCall, remoteAccess: ra },
      { type: 'PASSIVE_TOUCH_STROKES', sessionId: s, installId: u.install, userRef: u.ref,
        ts: t0 + 20000, payload: { strokes: strokes(12, 40, 80) } },   // scripted tempo
      { type: 'PASSIVE_KEYSTROKES', sessionId: s, installId: u.install, userRef: u.ref,
        ts: t0 + 30000, payload: { fieldId: 'transfer.amount', keys: keys(15, 55) } },
      { type: 'BIZ_TXN_INITIATED', sessionId: s, installId: u.install, userRef: u.ref,
        ts: t0 + 40000, callSignals: noCall, remoteAccess: ra,
        payload: { amountBucket: 'HIGH', currency: 'CZK', payeeIsNew: true, channel: 'BANK_TRANSFER' } },
    ]);
    const got = await sendScore(mintToken(s, u.install, u.ref),
      { txnRef: 'TXN-RAT', amount: 90000, currency: 'CZK', payeeIsNew: true });
    report('rat', { decision: 'HOLD', threatType: 'Account Takeover' }, got);
    if (!(got.signals || []).some((sg) => sg.code === 'REMOTE_ACCESS')) {
      console.log('  ✗ expected a REMOTE_ACCESS signal'); process.exitCode = 1;
    }

    // Overlay-only variant: obscured touch, no screen-share event.
    const u2 = newUser();
    await buildHistory(u2, [30, 14, 2], [4000, 5000, 4500]);
    const t1 = Date.now();
    const s2 = crypto.randomUUID();
    const obscuredStrokes = strokes(8, u2.dur, u2.gap).map((st) => ({ ...st, obscured: true }));
    await sendBatch(u2.install, [
      { type: 'BIZ_LOGIN_RESULT', sessionId: s2, installId: u2.install, userRef: u2.ref,
        ts: t1 + 1000, payload: { outcome: 'SUCCESS' }, callSignals: noCall },
      { type: 'PASSIVE_TOUCH_STROKES', sessionId: s2, installId: u2.install, userRef: u2.ref,
        ts: t1 + 20000, payload: { strokes: obscuredStrokes } },
      { type: 'BIZ_TXN_INITIATED', sessionId: s2, installId: u2.install, userRef: u2.ref,
        ts: t1 + 40000, callSignals: noCall,
        payload: { amountBucket: 'MID', currency: 'CZK', payeeIsNew: false, channel: 'BANK_TRANSFER' } },
    ]);
    const got2 = await sendScore(mintToken(s2, u2.install, u2.ref),
      { txnRef: 'TXN-OVERLAY', amount: 5000, currency: 'CZK', payeeIsNew: false });
    const overlayFired = (got2.signals || []).some((sg) => sg.code === 'REMOTE_ACCESS'
      && /obscured/.test(sg.evidence));
    console.log(`  ${overlayFired ? '✓' : '✗'} overlay variant: REMOTE_ACCESS from obscured touch`);
    if (!overlayFired) process.exitCode = 1;
  },

  /** Location integrity (Go server only). Two variants:
   *  1. Spoof-to-home ATO — attacker on a new device fakes GPS to the
   *     victim's usual geohash. GEO_UNUSUAL stays silent (location "matches"),
   *     but the mock flag turns the evasion into MOCK_LOCATION -> HOLD/ATO.
   *  2. Impossible travel — known device, honest-looking fix 4,900 km from
   *     one reported minutes earlier -> IMPOSSIBLE_TRAVEL, STEP_UP/ATO. */
  async geo() {
    // -- variant 1: mock provider spoofed to the user's home geohash --------
    const u = newUser();
    await buildHistory(u, [30, 14, 2], [4000, 5000, 4500]);
    const t0 = Date.now();
    const s = crypto.randomUUID();
    const attacker = crypto.randomUUID();               // new install
    await sendBatch(attacker, [
      { type: 'PASSIVE_LOCATION_COARSE', sessionId: s, installId: attacker, ts: t0,
        payload: { tier: 'GEOHASH5', geohash: u.geohash, ageMs: 900, mock: true } },
      { type: 'BIZ_LOGIN_RESULT', sessionId: s, installId: attacker, userRef: u.ref,
        ts: t0 + 2000, payload: { outcome: 'SUCCESS' }, callSignals: noCall },
      { type: 'BIZ_TXN_INITIATED', sessionId: s, installId: attacker, userRef: u.ref,
        ts: t0 + 30000, callSignals: noCall,
        payload: { amountBucket: 'HIGH', currency: 'CZK', payeeIsNew: true, channel: 'BANK_TRANSFER' } },
    ]);
    const got = await sendScore(mintToken(s, attacker, u.ref),
      { txnRef: 'TXN-GEOSPOOF', amount: 88000, currency: 'CZK', payeeIsNew: true });
    report('geo', { decision: 'HOLD', threatType: 'Account Takeover' }, got);
    const codes = (got.signals || []).map((sg) => sg.code);
    if (!codes.includes('MOCK_LOCATION')) {
      console.log('  ✗ expected a MOCK_LOCATION signal'); process.exitCode = 1;
    }
    if (codes.includes('GEO_UNUSUAL')) {
      console.log('  ✗ GEO_UNUSUAL should stay silent when spoofed to home'); process.exitCode = 1;
    } else {
      console.log('  ✓ spoof-to-home: GEO_UNUSUAL silent, MOCK_LOCATION fired instead');
    }

    // -- variant 2: impossible travel on the known device -------------------
    const u2 = newUser();
    await buildHistory(u2, [30, 14, 2], [4000, 5000, 4500]);
    // Honest fix at home 10 minutes ago…
    const tHome = Date.now() - 10 * 60 * 1000;
    const sHome = crypto.randomUUID();
    await sendBatch(u2.install, [
      { type: 'PASSIVE_LOCATION_COARSE', sessionId: sHome, installId: u2.install, ts: tHome,
        payload: { tier: 'GEOHASH5', geohash: u2.geohash, ageMs: 5000, mock: false } },
      { type: 'BIZ_LOGIN_RESULT', sessionId: sHome, installId: u2.install, userRef: u2.ref,
        ts: tHome + 2000, payload: { outcome: 'SUCCESS' }, callSignals: noCall },
    ]);
    // …then a fix ~4,900 km away (Prague -> Lagos) minutes later.
    const t1 = Date.now();
    const s2 = crypto.randomUUID();
    await sendBatch(u2.install, [
      { type: 'PASSIVE_LOCATION_COARSE', sessionId: s2, installId: u2.install, ts: t1,
        payload: { tier: 'GEOHASH5', geohash: 's14mhgs', ageMs: 3000, mock: false } },
      { type: 'BIZ_LOGIN_RESULT', sessionId: s2, installId: u2.install, userRef: u2.ref,
        ts: t1 + 2000, payload: { outcome: 'SUCCESS' }, callSignals: noCall },
      { type: 'BIZ_TXN_INITIATED', sessionId: s2, installId: u2.install, userRef: u2.ref,
        ts: t1 + 30000, callSignals: noCall,
        payload: { amountBucket: 'HIGH', currency: 'CZK', payeeIsNew: true, channel: 'BANK_TRANSFER' } },
    ]);
    const got2 = await sendScore(mintToken(s2, u2.install, u2.ref),
      { txnRef: 'TXN-TELEPORT', amount: 88000, currency: 'CZK', payeeIsNew: true });
    report('geo/travel', { decision: 'STEP_UP', threatType: 'Account Takeover' }, got2);
    if (!(got2.signals || []).some((sg) => sg.code === 'IMPOSSIBLE_TRAVEL')) {
      console.log('  ✗ expected an IMPOSSIBLE_TRAVEL signal'); process.exitCode = 1;
    }
  },

  /** Follow-the-money graph (Go server only). Seeds a subject with a
   *  recurring utility payment (safe), a large transfer to a mule-patterned
   *  in-book account with fan-in from two other customers (mule + hop-2
   *  expansion to its cash-out layer), and a second user on the SAME device
   *  (device-link node from the sessions table). Asserts the graph endpoint
   *  classifies and expands all three. */
  async graph() {
    const u = newUser();
    const rid = crypto.randomUUID().slice(0, 8);
    const acct = 'acc-' + u.ref.slice(0, 8);
    const muleCp = 'mule-' + rid;
    const safeCp = 'util-' + rid;
    const mk = () => 'G-' + crypto.randomUUID().slice(0, 8);
    const others = [newUser(), newUser()];

    await sendFeed([
      // Recurring, months-old relationship -> 'safe'.
      ...[45, 40, 35].map((d) => ({
        txnRef: mk(), accountRef: acct, userRef: u.ref, direction: 'OUT', amount: 1200,
        currency: 'CZK', counterpartyRef: safeCp, channel: 'BILL', ts: Date.now() - d * DAY,
      })),
      // Subject's large transfer into the mule.
      { txnRef: mk(), accountRef: acct, userRef: u.ref, direction: 'OUT', amount: 150000,
        currency: 'CZK', counterpartyRef: muleCp, channel: 'P2P', ts: Date.now() - 3600e3 },
      // Fan-in: two other customers also feed the same counterparty.
      ...others.map((o, i) => ({
        txnRef: mk(), accountRef: 'acc-' + o.ref.slice(0, 8), userRef: o.ref, direction: 'OUT',
        amount: 90000 - i * 10000, currency: 'CZK', counterpartyRef: muleCp,
        channel: 'P2P', ts: Date.now() - (2 + i) * 3600e3 })),
      // The mule as an in-book account: rapid in-out + its cash-out layer (hop 2).
      { txnRef: mk(), accountRef: muleCp, direction: 'IN', amount: 320000, currency: 'CZK',
        counterpartyRef: 'cp-victims', channel: 'P2P', ts: Date.now() - 7200e3 },
      { txnRef: mk(), accountRef: muleCp, direction: 'OUT', amount: 300000, currency: 'CZK',
        counterpartyRef: 'cashout-' + rid, channel: 'BANK_TRANSFER', ts: Date.now() - 1800e3 },
    ]);
    // Device link: the subject's own session, then a second user on the SAME install.
    const s1 = crypto.randomUUID(), s2 = crypto.randomUUID();
    await sendBatch(u.install, [
      { type: 'SCREEN_VIEWED', sessionId: s1, installId: u.install, userRef: u.ref,
        ts: Date.now() - 60000, payload: { screenId: 'home' } }]);
    await sendBatch(u.install, [
      { type: 'SCREEN_VIEWED', sessionId: s2, installId: u.install, userRef: others[0].ref,
        ts: Date.now(), payload: { screenId: 'home' } }]);

    const H = { 'Authorization': 'Bearer ' + (process.env.CONSOLE_KEY || 'dev-console-key') };
    const g = await fetch(`${BASE}/v1/console/graph/${u.ref}`, { headers: H }).then(r => r.json());

    const byLabel = (l) => (g.nodes || []).find(n => n.label === l);
    const safeNode = byLabel(safeCp);
    const muleNode = byLabel(muleCp);
    const hop2 = (g.nodes || []).find(n => n.parent === muleNode?.id && n.label === 'cashout-' + rid);
    const devNode = (g.nodes || []).find(n => n.kind === 'device');
    // Subject + the two other customers all feed the mule -> fan-in of 3.
    const fanFlag = (muleNode?.flags || []).some(f => /Fan-in from \d+ distinct/.test(f));

    const ok = safeNode?.kind === 'safe' && muleNode?.kind === 'mule' && fanFlag &&
      hop2 !== undefined && hop2.kind === 'mule' && devNode !== undefined &&
      Array.isArray(g.subject?.stats) && g.subject.stats.length >= 3;
    console.log(`\n${ok ? '✓' : '✗'} graph: safe=${safeNode?.kind} mule=${muleNode?.kind} ` +
        `fan-in=${fanFlag} hop2=${hop2 ? hop2.label : 'MISSING'} ` +
        `device-link=${devNode ? devNode.label : 'MISSING'} nodes=${(g.nodes || []).length}`);
    if (!ok) {
      console.log('  DETAIL', JSON.stringify(g, null, 1).slice(0, 1500));
      process.exitCode = 1;
    }
  },

  /** AML auto-open (Go server only) — the "two files" doctrine: confirming
   *  a proceeds-capturing fraud must open the parallel AML file, but ONLY
   *  when funds actually moved post-compromise. Positive: coached alert +
   *  outbound feed flows -> resolve as fraud -> linked AML case with the
   *  flow trace, idempotent on re-resolve. Negative: no movement -> no file. */
  async aml() {
    const H = { 'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + (process.env.CONSOLE_KEY || 'dev-console-key') };
    const resolve = (alertId) =>
      fetch(`${BASE}/v1/console/alerts/${alertId}`, {
        method: 'PATCH', headers: H,
        body: JSON.stringify({ state: 'Resolved', disposition: 'Fraud confirmed — alert resolved.' }),
      }).then(r => r.json());

    // Positive: proceeds moved out after the alert -> AML file opens.
    const { user, alertId } = await scenarios.coached();
    const acct = 'acc-' + user.ref.slice(0, 8);
    await sendFeed([
      { txnRef: 'AML-' + crypto.randomUUID().slice(0, 8), accountRef: acct, userRef: user.ref,
        direction: 'OUT', amount: 120000, currency: 'CZK', counterpartyRef: 'cp-mule-1',
        channel: 'P2P', ts: Date.now() + 1000 },
      { txnRef: 'AML-' + crypto.randomUUID().slice(0, 8), accountRef: acct, userRef: user.ref,
        direction: 'OUT', amount: 118000, currency: 'CZK', counterpartyRef: 'cp-mule-2',
        channel: 'P2P', ts: Date.now() + 2000 },
    ]);
    const resolved = await resolve(alertId);
    const amlId = resolved.aml_case_id;
    let amlCase = null, flowEvents = 0;
    if (amlId) {
      amlCase = await fetch(`${BASE}/v1/console/cases/${amlId}`, { headers: H }).then(r => r.json());
      flowEvents = (amlCase.timeline || []).filter(e => /^Flow:/.test(e.event)).length;
    }
    const again = await resolve(alertId);   // idempotent: same file, not a second one

    // Negative: fraud confirmed but nothing moved -> no AML file.
    const second = await scenarios.coached();
    const negative = await resolve(second.alertId);

    const ok = !!amlId && amlCase?.case_type === 'AML' &&
      amlCase?.threat_type === 'Money Laundering' && flowEvents === 2 &&
      again.aml_case_id === amlId && negative.aml_case_id === undefined;
    console.log(`\n${ok ? '✓' : '✗'} aml: file=${amlId ?? 'NONE'} type=${amlCase?.case_type} ` +
        `flows=${flowEvents} idempotent=${again.aml_case_id === amlId} ` +
        `no-movement-no-file=${negative.aml_case_id === undefined}`);
    if (!ok) {
      console.log('  DETAIL', { resolved, amlCase, again: again.aml_case_id, negative: negative.aml_case_id });
      process.exitCode = 1;
    }
  },

  /** Per-tenant key management (Go server only). Drives the operator CLI
   *  (`vera-go tenant …`) against the shared DB, then proves the running
   *  server picks changes up without a restart: create a tenant -> its key
   *  signs batches; rotate -> BOTH old (retiring) and new (active) keys
   *  verify; revoke old -> old 401s, new still works. */
  async keys() {
    const { execFileSync } = require('child_process');
    const path = require('path');
    const GO_DIR = process.env.VERA_GO_DIR ||
      path.join(__dirname, '..', 'fraud-ingest-server-go');
    const cli = (...args) =>
      execFileSync('go', ['run', '.', 'tenant', ...args],
        { cwd: GO_DIR, encoding: 'utf8' });
    const parseKey = (out) => {
      const m = out.match(/kid=(\S+) key=(\S+)/);
      return { kid: m[1], key: m[2] };
    };

    const tid = 't-rot-' + crypto.randomUUID().slice(0, 8);
    const k1 = parseKey(cli('create', tid, 'Rotation Test'));

    // Signed batch under a freshly created tenant (server cache reloads on miss).
    const send = async (key, kid) => {
      const s = crypto.randomUUID(), install = crypto.randomUUID();
      const events = [{ eventId: crypto.randomUUID(), type: 'SCREEN_VIEWED',
        sessionId: s, installId: install, ts: Date.now(), payload: { screenId: 'home' } }];
      const gz = zlib.gzipSync(events.map(e => JSON.stringify(e)).join('\n'));
      const sig = crypto.createHmac('sha256', Buffer.from(key)).update(gz).digest('base64');
      const r = await fetch(BASE + '/v1/events', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-ndjson', 'Content-Encoding': 'gzip',
                   'X-Tenant-Id': tid, 'X-Install-Id': install,
                   'X-Signature': sig, 'X-Key-Id': kid, 'X-Sdk': 'simulator/0.2.0' },
        body: gz,
      });
      return r.status;
    };

    const sleep = (ms) => new Promise(r => setTimeout(r, ms));
    const createOk = await send(k1.key, k1.kid) === 200;

    const k2 = parseKey(cli('rotate-key', tid));
    await sleep(1200);   // reload-on-miss is rate-limited to 1/s
    const oldDuringRotation = await send(k1.key, k1.kid) === 200;  // retiring key
    const newAfterRotation = await send(k2.key, k2.kid) === 200;   // active key

    cli('revoke-key', tid, k1.kid);
    await sleep(6000);   // revocation propagates via the 5s staleness bound
    const revokedRejected = await send(k1.key, k1.kid) === 401;
    const activeSurvives = await send(k2.key, k2.kid) === 200;

    const ok = createOk && oldDuringRotation && newAfterRotation &&
      revokedRejected && activeSurvives;
    console.log(`\n${ok ? '✓' : '✗'} keys: tenant=${tid} create=${createOk} ` +
        `rotate old/new=${oldDuringRotation}/${newAfterRotation} ` +
        `revoked-rejected=${revokedRejected} active-survives=${activeSurvives}`);
    if (!ok) process.exitCode = 1;
  },

  /** Idempotent /v1/score (Go server only): a bank retrying the same txnRef
   *  in the same session must get the SAME decision and alert back — never
   *  a second open alert — while a different txnRef still scores fresh. */
  async idem() {
    const { sessionId, user, alertId } = await scenarios.coached();
    const token = mintToken(sessionId, user.install, user.ref);

    // Retry of the already-decided transaction -> stored decision replayed.
    const again = await sendScore(token,
      { txnRef: 'TXN-COACHED', amount: 240000, currency: 'CZK', payeeIsNew: true });
    // A different transaction in the same session -> scored fresh.
    const fresh = await sendScore(token,
      { txnRef: 'TXN-COACHED-2', amount: 1000, currency: 'CZK', payeeIsNew: false });

    const ok = again.replay === true && again.decision === 'HOLD' &&
      again.alertId === alertId && again.threatType === 'APP Scam' &&
      Array.isArray(again.signals) && again.signals.length > 0 &&
      fresh.replay === undefined;
    console.log(`\n${ok ? '✓' : '✗'} idem: replay=${again.replay} ` +
        `decision=${again.decision} alert=${again.alertId}` +
        `${again.alertId === alertId ? ' (same)' : ` != ${alertId} DUPLICATE!`} · ` +
        `fresh txn replay=${fresh.replay} decision=${fresh.decision}`);
    if (!ok) {
      console.log('  DETAIL', { again, fresh, originalAlert: alertId });
      process.exitCode = 1;
    }
  },

  /** Webhook outbox retries (Go server only). The bank receiver 500s the
   *  synchronous first attempt; the action must land as `failed` with a
   *  scheduled retry, then the Postgres-backed dispatcher redelivers it
   *  (X-Attempt: 2) without any client involvement. Restart survival is
   *  the same mechanism — the schedule lives in the actions table. */
  async retry() {
    const http = require('http');
    let hits = 0;
    const received = [];
    const bank = http.createServer((req, res) => {
      const chunks = [];
      req.on('data', c => chunks.push(c));
      req.on('end', () => {
        hits++;
        if (hits === 1) {              // fail the synchronous first attempt
          res.writeHead(500); res.end();
          return;
        }
        const raw = Buffer.concat(chunks);
        const sigOk = req.headers['x-signature'] ===
          crypto.createHmac('sha256', KEY).update(raw).digest('base64');
        received.push({ ...JSON.parse(raw.toString()), sigOk,
                        attempt: req.headers['x-attempt'] });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"ok":true}');
      });
    });
    await new Promise(r => bank.listen(8090, r));

    try {
      const { alertId } = await scenarios.coached();
      const H = { 'Content-Type': 'application/json',
                  'Authorization': 'Bearer ' + (process.env.CONSOLE_KEY || 'dev-console-key') };
      const act = await fetch(`${BASE}/v1/console/alerts/${alertId}/actions`, {
        method: 'POST', headers: H,
        body: JSON.stringify({ kind: 'TERMINATE_SESSION', note: 'retry test' }),
      }).then(r => r.json());
      const failedFirst = act.webhook_status === 'failed';

      // Backoff after one failure is ~5s (+ dispatcher tick) — poll the
      // action until the outbox redelivers, up to 25s.
      let row = null;
      for (let i = 0; i < 25 && !row; i++) {
        await new Promise(r => setTimeout(r, 1000));
        const list = await fetch(`${BASE}/v1/console/actions`, { headers: H })
          .then(r => r.json());
        const a = list.find(x => x.id === act.id);
        if (a && a.webhook_status === 'delivered') row = a;
      }

      // The dispatcher may also drain stranded actions from earlier runs
      // (that's the outbox working) — assert on OUR action only.
      const mine = received.find(w => w.id === act.id);
      const ok = failedFirst && row !== null &&
        row.webhook_attempts === 2 &&
        mine !== undefined && mine.sigOk &&
        mine.type === 'session.terminate' && mine.attempt === '2';
      console.log(`\n${ok ? '✓' : '✗'} retry: first=${act.webhook_status} ` +
          `redelivered=${row ? `yes (attempts=${row.webhook_attempts})` : 'NO'} ` +
          `attemptHeader=${mine?.attempt ?? 'n/a'}` +
          (received.length > 1 ? ` (+${received.length - 1} stranded actions drained)` : ''));
      if (!ok) {
        console.log('  DETAIL', { act, row, received });
        process.exitCode = 1;
      }
    } finally {
      bank.close();
    }
  },

  /** Invitations + MFA (Go server only — the Node server is frozen as the
   *  SDK wire-format reference and does not implement these endpoints).
   *  Full lifecycle: admin invites, invitee reads the public context,
   *  enrolls TOTP (code computed from the returned secret exactly like an
   *  authenticator app), accepts, then must pass the 2FA challenge on the
   *  next login. Revocation kills the link. */
  async invite() {
    const api = (path, { method = 'GET', token, body } = {}) =>
      fetch(BASE + path, {
        method,
        headers: { 'Content-Type': 'application/json',
                   ...(token ? { Authorization: 'Bearer ' + token } : {}) },
        body: body ? JSON.stringify(body) : undefined,
      }).then(async r => ({ status: r.status, body: await r.json().catch(() => ({})) }));
    const totp = (secret) => {
      const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
      let bits = 0, val = 0; const bytes = [];
      for (const ch of secret) { val = (val << 5) | A.indexOf(ch); bits += 5;
        if (bits >= 8) { bytes.push((val >>> (bits - 8)) & 0xff); bits -= 8; } }
      const msg = Buffer.alloc(8); msg.writeUInt32BE(Math.floor(Date.now() / 30000), 4);
      const h = crypto.createHmac('sha1', Buffer.from(bytes)).update(msg).digest();
      const off = h[19] & 0xf;
      const code = (((h[off] & 0x7f) << 24) | (h[off+1] << 16) | (h[off+2] << 8) | h[off+3]) % 1e6;
      return String(code).padStart(6, '0');
    };

    // 1. Admin invites a new analyst.
    const adm = (await api('/v1/console/login', { method: 'POST',
      body: { email: process.env.CONSOLE_ADMIN_EMAIL || 'admin@demobank.cz',
              password: process.env.CONSOLE_ADMIN_PASSWORD || 'admin-dev-password' } })).body;
    const email = `invitee-${crypto.randomUUID().slice(0, 8)}@demobank.cz`;
    const inv = await api('/v1/console/team/invitations', { method: 'POST',
      token: adm.token, body: { email, role: 'senior' } });
    const listed = await api('/v1/console/team/invitations', { token: adm.token });

    // 2. Invitee reads the public context and accepts with a real TOTP code.
    const pub = await api(`/v1/console/invitations/${inv.body.token}`);
    const wrongCode = await api(`/v1/console/invitations/${inv.body.token}/accept`,
      { method: 'POST', body: { name: 'I. Novak', password: 'invitee-pass-1', code: '000000' } });
    const accept = await api(`/v1/console/invitations/${inv.body.token}/accept`,
      { method: 'POST', body: { name: 'I. Novak', password: 'invitee-pass-1',
                                code: totp(pub.body.secret) } });
    const me = await api('/v1/console/me', { token: accept.body.token });
    const gone = await api(`/v1/console/invitations/${inv.body.token}`);

    // 3. Next login requires the second factor.
    const noCode = await api('/v1/console/login', { method: 'POST',
      body: { email, password: 'invitee-pass-1' } });
    const withCode = await api('/v1/console/login', { method: 'POST',
      body: { email, password: 'invitee-pass-1', code: totp(pub.body.secret) } });

    // 4. Revocation kills a fresh invitation's link.
    const inv2 = await api('/v1/console/team/invitations', { method: 'POST',
      token: adm.token, body: { email: `rev-${crypto.randomUUID().slice(0, 8)}@demobank.cz`,
                                role: 'readonly' } });
    await api(`/v1/console/team/invitations/${inv2.body.token}`,
      { method: 'DELETE', token: adm.token });
    const revoked = await api(`/v1/console/invitations/${inv2.body.token}`);

    const ok =
      inv.status === 200 && listed.body.some?.(i => i.email === email) &&
      pub.status === 200 && pub.body.otpauthUri?.startsWith('otpauth://totp/') &&
      wrongCode.status === 400 &&
      accept.status === 200 && accept.body.analyst.mfaEnrolled === true &&
      me.status === 200 && me.body.email === email && me.body.role === 'senior' &&
      gone.status === 404 &&
      noCode.status === 401 && noCode.body.mfaRequired === true &&
      withCode.status === 200 &&
      revoked.status === 404;

    console.log(`\n${ok ? '✓' : '✗'} invite: created=${inv.status} pub=${pub.status} ` +
        `wrong-code=${wrongCode.status} accept=${accept.status} me=${me.body.role || '-'} ` +
        `consumed=${gone.status} relogin no-code=${noCode.status}(mfa=${!!noCode.body.mfaRequired}) ` +
        `with-code=${withCode.status} revoked=${revoked.status}`);
    if (!ok) {
      console.log('  DETAIL', { inv: inv.body, pub: pub.status, accept: accept.body,
        me: me.body, noCode: noCode.body });
      process.exitCode = 1;
    }
  },

  /** Action channel: analyst terminates the session and blocks the payment.
   *  Plays the bank (webhook receiver on :8090) AND the device (next SDK
   *  batch must carry the terminate command exactly once). */
  async actions() {
    const http = require('http');
    const received = [];
    const bank = http.createServer((req, res) => {
      const chunks = [];
      req.on('data', c => chunks.push(c));
      req.on('end', () => {
        const raw = Buffer.concat(chunks);
        const sigOk = req.headers['x-signature'] ===
          crypto.createHmac('sha256', KEY).update(raw).digest('base64');
        received.push({ ...JSON.parse(raw.toString()), sigOk });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"ok":true}');
      });
    });
    await new Promise(r => bank.listen(8090, r));

    try {
      const { sessionId, user, alertId } = await scenarios.coached();
      const H = { 'Content-Type': 'application/json',
                  'Authorization': 'Bearer ' + (process.env.CONSOLE_KEY || 'dev-console-key') };
      const act = (kind, note) =>
        fetch(`${BASE}/v1/console/alerts/${alertId}/actions`, {
          method: 'POST', headers: H, body: JSON.stringify({ kind, note }),
        }).then(r => r.json());

      // 1. Kill the session, 2. block the payment — both must hit the bank.
      const term = await act('TERMINATE_SESSION', 'coached scam in progress');
      const block = await act('BLOCK_PAYMENT', 'confirmed APP scam');

      // 3. Device leg: next SDK heartbeat batch returns the terminate command…
      const hb = () => sendBatch(user.install, [
        { type: 'SCREEN_VIEWED', sessionId, installId: user.install, userRef: user.ref,
          ts: Date.now(), payload: { screenId: 'home' } }]);
      const beat1 = await hb();
      const beat2 = await hb();   // …exactly once

      // 4. v0.2 SDK protocol: the device acks inside the dying session
      //    (then rotates — mirrors SessionManager.handleServerCommands).
      const cmdId = beat1.commands[0]?.id;
      await sendBatch(user.install, [
        { type: 'PASSIVE_COMMAND_ACK', sessionId, installId: user.install, ts: Date.now(),
          payload: { commandId: cmdId, kind: 'TERMINATE_SESSION' } }]);
      const sessEvents = await fetch(`${BASE}/v1/console/sessions/${sessionId}/events`,
        { headers: H }).then(r => r.json());
      const ack = sessEvents.find(e => e.type === 'PASSIVE_COMMAND_ACK');

      // 5. Alert reflects the analyst decisions.
      const alert = await fetch(`${BASE}/v1/console/alerts/${alertId}`, { headers: H })
        .then(r => r.json());

      const ok =
        term.webhook_status === 'delivered' && block.webhook_status === 'delivered' &&
        received.length === 2 && received.every(w => w.sigOk) &&
        received[0].type === 'session.terminate' && received[1].type === 'payment.block' &&
        received[1].txnRef === 'TXN-COACHED' &&
        beat1.commands.length === 1 && beat1.commands[0].kind === 'TERMINATE_SESSION' &&
        beat2.commands.length === 0 &&
        ack?.payload?.commandId === cmdId &&
        alert.state === 'Resolved' && alert.txn.decision === 'Blocked' &&
        alert.actions.length === 2;

      console.log(`\n${ok ? '✓' : '✗'} actions: webhooks=${received.length} ` +
          `[${received.map(w => w.type + (w.sigOk ? '' : ' BAD-SIG')).join(', ')}] · ` +
          `device cmd on beat1=${beat1.commands.length} beat2=${beat2.commands.length} · ` +
          `ack=${ack ? ack.payload.commandId : 'none'} · ` +
          `alert=${alert.state}/${alert.txn?.decision}`);
      if (!ok) {
        console.log('  DETAIL', { term, block, beat1, beat2,
          alertState: alert.state, decision: alert.txn?.decision });
        process.exitCode = 1;
      }
    } finally {
      bank.close();
    }
  },

  async all() {
    await scenarios.clean(); await scenarios.coached();
    await scenarios.ato(); await scenarios.mule();
    await scenarios.feedmule(); await scenarios.agent();
    await scenarios.actions(); await scenarios.auth();
  },

  /** Populate a fresh database with a broad, realistic demo dataset — a
   *  spread across every threat typology, plus cases, ledger flows for the
   *  graph, and auto-opened AML files. Not a test (no assertions to fail);
   *  safe to run repeatedly. Target + keys are configurable, so the same
   *  command seeds local or the deployed server:
   *    node simulate-sdk.js seed <baseUrl>
   *    SDK_KEY=<rotated> KEY_ID=<kid> CONSOLE_KEY=<key> \
   *      node simulate-sdk.js seed https://…            (deployed) */
  async seed() {
    const H = { 'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + (process.env.CONSOLE_KEY || 'dev-console-key') };
    const run = async (name, fn) => {
      try { await fn(); }
      catch (e) { console.log(`  · ${name} skipped: ${e.message.split('\n')[0]}`); }
    };

    console.log('Seeding demo data …');
    // Clean ALLOW decisions — volume for the Transaction Risk stream.
    for (let i = 0; i < 8; i++) await run('clean', scenarios.clean);
    // A spread of held alerts across every typology.
    for (let i = 0; i < 3; i++) {
      await run('coached', scenarios.coached);   // APP scam
      await run('ato', scenarios.ato);           // account takeover
      await run('mule', scenarios.mule);         // money mule
    }
    await run('agent', scenarios.agent);         // agent commission fraud
    await run('feedmule', scenarios.feedmule);   // ledger-only mule
    await run('rat', scenarios.rat);             // remote access / ODF
    await run('web', scenarios.web);             // browser / headless ATO
    await run('geo', scenarios.geo);             // mock-GPS + impossible travel
    await run('graph', scenarios.graph);         // follow-the-money + device links
    await run('aml', scenarios.aml);             // fraud → auto-opened AML files

    // Open a few investigation cases from the freshest open alerts so Case
    // Management isn't empty for a demo.
    try {
      const open = await fetch(`${BASE}/v1/console/alerts?state=Open`, { headers: H })
        .then(r => r.json());
      const pick = (Array.isArray(open) ? open : []).slice(0, 4);
      let opened = 0;
      for (const a of pick) {
        const r = await fetch(`${BASE}/v1/console/alerts/${a.id}/case`, {
          method: 'POST', headers: H,
          body: JSON.stringify({ assignee: 'P. Hruba', summary: a.signal }),
        });
        if (r.ok) opened++;
      }
      console.log(`  · opened ${opened} investigation case(s)`);
    } catch (e) { console.log(`  · cases skipped: ${e.message.split('\n')[0]}`); }

    const stats = await fetch(`${BASE}/stats`).then(r => r.json()).catch(() => ({}));
    const alerts = await fetch(`${BASE}/v1/console/alerts`, { headers: H })
      .then(r => r.json()).catch(() => []);
    const cases = await fetch(`${BASE}/v1/console/cases`, { headers: H })
      .then(r => r.json()).catch(() => []);
    console.log(`\n✓ seed complete — ${Array.isArray(alerts) ? alerts.length : '?'} alerts, ` +
      `${Array.isArray(cases) ? cases.length : '?'} cases, ` +
      `${Object.values(stats).reduce((a, b) => a + (Number(b) || 0), 0)} events ingested.`);
  },
};

(async () => {
  const fn = scenarios[SCENARIO];
  if (!fn) {
    console.error(`unknown scenario "${SCENARIO}" — one of: ${Object.keys(scenarios).join(', ')}`);
    process.exit(1);
  }
  await fn();
})().catch(e => { console.error(e); process.exit(1); });
