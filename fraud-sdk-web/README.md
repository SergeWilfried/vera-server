# fraud-sdk-web

Browser behavioral-fraud SDK for Verawall. It captures the signals a
mobile-only SDK can't reach — **mouse dynamics, keystroke timing, and a
headless/bot fingerprint** — for web-banking and fintech web sessions, and
streams them to the ingest collector. Same event envelope as the Android SDK,
so web and mobile sessions score through one engine.

TypeScript, zero runtime dependencies, ships as ESM.

## Why a public site key (no secret in the browser)

The Android SDK signs its uploads with a per-tenant HMAC secret. A browser
can't hold a secret, so the web SDK authenticates with a **public per-tenant
site key** plus a server-side **Origin allowlist**, and the *server* mints the
session token. This is the standard tradeoff for browser telemetry, and it
buys better UX: drop-in, same-origin, no key exchange or SDK gateway.

- `siteKey` is safe to ship in your page JS (like a publishable/anon key).
- The collector only accepts batches whose `Origin` is on the tenant's
  allowlist (`SITE_ORIGINS` on the server).
- The session token used to authorize a `/v1/score` call is minted by
  `POST /v1/collect/token`, never assembled client-side.

## Install / build

```
npm install          # or: pnpm/yarn
npm run build        # tsc -> dist/  (ESM + .d.ts)
npm run demo         # static server on :8099 for demo/index.html
```

## Quick start

```js
import { FraudSdk, BusinessEvent } from '@veratools/fraud-sdk-web';

FraudSdk.init({
  tenantId: 'wallet-acme',
  siteKey: 'site_wallet-acme_pub',
  // collectorUrl defaults to location.origin; set it when the collector
  // is on another host: collectorUrl: 'https://collect.example.com'
});

// After the user authenticates, tie the session to a HASHED identifier.
FraudSdk.session().setUser(await FraudSdk.hash(userEmail));

// Opt-in per-field keystroke dynamics (timing only, never content).
FraudSdk.captureKeystrokes(pinInput, 'login.pin');

// Business events drive the risk score.
FraudSdk.session().event(
  BusinessEvent.txnInitiated({ amountBucket: 'HIGH', payeeIsNew: true }),
);

// Right before a risky backend call: flush, then hand the token to your
// backend, which calls /v1/score server-to-server.
await FraudSdk.flush();
const token = await FraudSdk.session().getToken(); // -> send as X-Fraud-Session
```

Your backend passes that token to `POST /v1/score`; the browser never calls
`/v1/score` (it's server-to-server, and CORS-blocked on purpose).

## What it captures

| Collector | Event | Signal it feeds |
|---|---|---|
| `fingerprint` | `PASSIVE_WEB_FINGERPRINT` (at init) | `HEADLESS_BROWSER` — `navigator.webdriver`, automation UA, missing plugins, `hardwareConcurrency` |
| `mouse` | `PASSIVE_MOUSE_STROKES` | `MOUSE_ANOMALY` — stroke timing/geometry vs the user's baseline; robotic paths are unnaturally straight at constant velocity |
| `keystroke` | `PASSIVE_KEYSTROKE` (opt-in per field) | keystroke-dynamics baseline / deviation |
| `nav` | `SCREEN_VIEWED` + page lifecycle | session shape |

A mouse/touch **stroke** is a burst of movement between pauses, reduced to
`{t, dur, len, straight, gap}` — timing and geometry only. Keystroke capture
records inter-key timing, never the characters typed.

## Privacy

- No keystroke **content**, ever — timing and geometry only.
- Hash identifiers with `FraudSdk.hash(value)` (SHA-256) before `setUser`;
  the collector never needs raw PII.
- `installId` (a random browser device id) persists in `localStorage` to power
  "known device"; `sessionId` rotates per page session. Falls back to in-memory
  when storage is blocked.

## API

- `FraudSdk.init(config)` — call once on app start; idempotent.
- `FraudSdk.session().setUser(hashedRef)` / `.clearUser()` — bind/rotate identity.
- `FraudSdk.session().event(BusinessEvent.…)` — enqueue a `BIZ_*` event.
- `FraudSdk.session().screenView(screenId)` — a `SCREEN_VIEWED`.
- `FraudSdk.session().getToken()` — the minted session token (`X-Fraud-Session`).
- `FraudSdk.captureKeystrokes(el, fieldId)` — opt-in keystroke dynamics.
- `FraudSdk.flush()` — force-upload the queue (e.g. right before a `/score`).
- `FraudSdk.onLocalRisk(cb)` — subscribe to locally-known risk (`{ level, reasons }`); fires immediately and on every change, so the host app can raise an anti-scam banner with no server round-trip.
- `FraudSdk.reportRemoteAccess(active)` — a native/webview shell reports screen-share / remote-control it detected (e.g. an Android `VirtualDisplay` from AnyDesk); raises local risk **and** emits `PASSIVE_REMOTE_ACCESS` so the server scores `REMOTE_ACCESS`.
- `FraudSdk.hash(value)` — SHA-256 hex for PII.

`config`: `{ tenantId, siteKey, collectorUrl?, sdk?, flushIntervalMs? }`.

## Transport

Events batch to NDJSON and `POST /v1/collect` on a timer (default 5s) and on
`pagehide`/`visibilitychange` (keepalive fetch, so the last events survive
navigation). Failures re-queue a bounded tail. Envelope per line:

```json
{"eventId":"…","type":"…","sessionId":"…","installId":"…","userRef":"…","ts":0,"payload":{}}
```

`eventId` is a client-generated UUID stamped once per event (survives the
re-queue-on-failure path), so the server can dedupe resent batches —
uploads are at-least-once.

## Verification

The collector + web scoring path is covered by the Go server's `web`
conformance scenario:

```
node ../fraud-ingest-server/simulate-sdk.js web http://localhost:8080
```

It mints a token via the public site-key endpoint, streams a headless
fingerprint + robotic mouse strokes, and asserts the session **HOLDs** as
**Account Takeover** with `HEADLESS_BROWSER` + `MOUSE_ANOMALY`.
`demo/index.html` is a runnable "Demo Bank" page for exercising the real SDK
in a browser against a local collector.

See [`../fraud-ingest-server-go`](../fraud-ingest-server-go) for the collector
endpoints (`/v1/collect`, `/v1/collect/token`) and site-key config.
