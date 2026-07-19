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

const TENANT = 'wallet-acme';
const KEY = Buffer.from('0123456789abcdef0123456789abcdef');
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

async function sendBatch(installId, events) {
  const gz = zlib.gzipSync(events.map(e => JSON.stringify(e)).join('\n'));
  const sig = crypto.createHmac('sha256', KEY).update(gz).digest('base64');
  const r = await fetch(BASE + '/v1/events', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-ndjson', 'Content-Encoding': 'gzip',
               'X-Tenant-Id': TENANT, 'X-Install-Id': installId,
               'X-Signature': sig, 'X-Sdk': 'simulator/0.2.0' },
    body: gz,
  });
  if (r.status !== 200) throw new Error('/v1/events -> ' + r.status + ' ' + await r.text());
  return r.json();   // {accepted, commands: [...]} — the device leg of the action channel
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
};

(async () => {
  const fn = scenarios[SCENARIO];
  if (!fn) {
    console.error(`unknown scenario "${SCENARIO}" — one of: ${Object.keys(scenarios).join(', ')}`);
    process.exit(1);
  }
  await fn();
})().catch(e => { console.error(e); process.exit(1); });
