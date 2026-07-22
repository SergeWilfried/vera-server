// Demo Bank backend — the "bank's server" half of a Verawall integration.
//
// It does three things a real bank backend does:
//   1. seeds a behavioural baseline for the demo customer (so the platform
//      has something to compare against — done here at startup for the demo);
//   2. serves the Demo Bank web app + the SDK bundle;
//   3. on a transfer, calls Verawall /v1/score SERVER-TO-SERVER with the
//      session token the browser SDK minted, and returns the decision.
//
// The score call is never made from the browser — that's the whole point of
// the token: the browser proves the session, the backend makes the decision.
//
// Run:  node server.mjs        (needs the Verawall server on :8080)
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, extname } from 'node:path';
import crypto from 'node:crypto';
import zlib from 'node:zlib';

const HERE = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.DEMO_PORT || 8099);
const VERAWALL = process.env.VERAWALL_URL || 'http://localhost:8080';
const TENANT = process.env.TENANT || 'wallet-acme';
const SITE_KEY = process.env.SITE_KEY || 'site_wallet-acme_pub';
const KEY = Buffer.from(process.env.SDK_KEY || '0123456789abcdef0123456789abcdef');
const ORIGIN = `http://localhost:${PORT}`;
const DAY = 86_400_000;

// The demo customer. Its ref is the SHA-256 of the email — exactly what the
// SDK sends after FraudSdk.hash(email); the browser and this server agree.
const DEMO_EMAIL = 'olivia@demobank.cz';
const DEMO_REF = crypto.createHash('sha256').update(DEMO_EMAIL).digest('hex');
const TRUSTED_INSTALL = 'demo-trusted-device-01'; // the customer's usual phone

// ---------- wire helpers (mirror the Android SDK / simulator) ----------
const hmacB64 = (buf) => crypto.createHmac('sha256', KEY).update(buf).digest('base64');

async function sendBatch(installId, events) {
  const gz = zlib.gzipSync(events.map((e) => JSON.stringify(e)).join('\n'));
  const r = await fetch(VERAWALL + '/v1/events', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-ndjson', 'Content-Encoding': 'gzip',
      'X-Tenant-Id': TENANT, 'X-Install-Id': installId, 'X-Signature': hmacB64(gz), 'X-Sdk': 'demo-bank/1.0',
    },
    body: gz,
  });
  if (!r.ok) throw new Error(`events ${r.status}: ${await r.text()}`);
}

function mintToken(sessionId, installId, userRef) {
  const p = { t: TENANT, s: sessionId, d: installId, u: userRef, iat: Math.floor(Date.now() / 1000) };
  const body = Buffer.from(JSON.stringify(p)).toString('base64url');
  const sig = crypto.createHmac('sha256', KEY).update(body).digest('base64url');
  return `${body}.${sig}`;
}

async function sendScore(token, txn) {
  const r = await fetch(VERAWALL + '/v1/score', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sessionToken: token, transaction: txn }),
  });
  return r.json();
}

// One clean historical session for the demo customer, backdated.
function historySession(t0) {
  const s = crypto.randomUUID();
  return [
    { type: 'PASSIVE_DEVICE_FINGERPRINT', sessionId: s, installId: TRUSTED_INSTALL, ts: t0,
      payload: { manufacturer: 'Samsung', model: 'SM-A546', sdkInt: 34 } },
    { type: 'BIZ_LOGIN_RESULT', sessionId: s, installId: TRUSTED_INSTALL, userRef: DEMO_REF,
      ts: t0 + 2000, payload: { outcome: 'SUCCESS' } },
    { type: 'BIZ_TXN_INITIATED', sessionId: s, installId: TRUSTED_INSTALL, userRef: DEMO_REF,
      ts: t0 + 60000, payload: { amountBucket: 'LOW', currency: 'CZK', payeeIsNew: false, channel: 'BILL' } },
  ];
}

// Baseline: three small, trusted payments — but ~4 months ago, so the account
// reads as DORMANT when the live session arrives. Gives the platform an amount
// profile (median ~5,000) and a "known device / last seen long ago" history.
async function seedBaseline() {
  const daysAgo = [128, 121, 116];
  const amounts = [4200, 5000, 5600];
  for (let i = 0; i < daysAgo.length; i++) {
    const t0 = Date.now() - daysAgo[i] * DAY;
    const evs = historySession(t0);
    await sendBatch(TRUSTED_INSTALL, evs);
    const sid = evs[0].sessionId;
    await sendScore(mintToken(sid, TRUSTED_INSTALL, DEMO_REF),
      { txnRef: `SEED-${i}`, amount: amounts[i], currency: 'CZK', payeeIsNew: false });
  }
  console.log(`  seeded baseline for ${DEMO_EMAIL} (median ~5,000 CZK, dormant ~4 months)`);
}

// ---------- static + api server ----------
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.map': 'application/json', '.ico': 'image/x-icon' };

async function serveStatic(req, res) {
  let path = req.url.split('?')[0];
  if (path === '/') path = '/index.html';
  // the app imports ../dist/index.js — resolve it under the package root
  const file = path.startsWith('/dist/')
    ? join(HERE, '..', path)
    : join(HERE, path);
  try {
    const body = await readFile(file);
    res.writeHead(200, { 'Content-Type': MIME[extname(file)] || 'application/octet-stream' });
    res.end(body);
  } catch {
    res.writeHead(404); res.end('not found');
  }
}

const readJson = (req) => new Promise((resolve) => {
  let b = ''; req.on('data', (c) => (b += c)); req.on('end', () => { try { resolve(JSON.parse(b || '{}')); } catch { resolve({}); } });
});

const server = http.createServer(async (req, res) => {
  if (req.method === 'POST' && req.url === '/demo/pay') {
    const { token, amount, payeeNew } = await readJson(req);
    if (!token) { res.writeHead(400); return res.end('{"error":"no session token"}'); }
    const decision = await sendScore(token, {
      txnRef: 'DEMO-' + crypto.randomUUID().slice(0, 8),
      amount: Number(amount) || 0, currency: 'CZK', payeeIsNew: !!payeeNew, channel: 'BANK_TRANSFER',
    });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify(decision));
  }
  if (req.method === 'GET' && req.url === '/demo/config') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ tenant: TENANT, siteKey: SITE_KEY, collectorUrl: VERAWALL, demoEmail: DEMO_EMAIL }));
  }
  return serveStatic(req, res);
});

console.log(`Demo Bank → Verawall at ${VERAWALL} (origin ${ORIGIN})`);
try {
  await seedBaseline();
} catch (e) {
  console.log(`  ! baseline seed failed (is the Verawall server on ${VERAWALL}?): ${e.message}`);
}
server.listen(PORT, () => console.log(`Demo Bank running → ${ORIGIN}`));
