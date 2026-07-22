# Demo Bank — a full-loop Verawall integration

A tiny bank web app wired to Verawall end to end. It shows **both halves** of a
real integration in one page:

- the **browser SDK** (`fraud-sdk-web`) capturing session behaviour and minting
  a short-lived session token, and
- the **bank's backend** calling `POST /v1/score` **server-to-server** with that
  token and acting on the decision.

The score call is never made from the browser. The browser proves the session
(token); the backend makes the decision. That boundary is the whole point.

```
 browser (Demo Bank SPA)                 demo backend (server.mjs)        Verawall
 ─────────────────────────               ─────────────────────────        ────────
 FraudSdk.init / captureKeystrokes  ──▶  POST /v1/events (NDJSON,gzip,HMAC) ──▶ ingest
 setUser(hash(email)), business events                                         │
 flush() ; getToken()               ──▶  POST /demo/pay {token, amount}        │
                                          └─▶ POST /v1/score {sessionToken}  ──▶ score
 render ALLOW / STEP_UP / HOLD      ◀──   decision JSON                    ◀───┘
```

## Run it

Needs a Verawall ingest server on `:8080` (the Go server, seeded schema).

```bash
# from vera-tools/fraud-sdk-web
npm run demo          # → node demo/server.mjs, serves http://localhost:8099
```

On startup the backend **seeds a behavioural baseline** for the demo customer
(`olivia@demobank.cz`): three small, trusted payments (median ~5,000 CZK) posted
from her usual phone, but backdated ~4 months. That gives the platform an amount
profile and a "known device, last seen long ago" history — so the account reads
as **dormant** when the live browser session arrives. No attack replay is needed;
the HOLD is genuine.

Open <http://localhost:8099>, sign in (credentials pre-filled), and try the two
transfer presets.

## What you'll see — the three bands, live

The right-hand **Verawall** panel shows the exact verdict the backend received:
band, score, classification, alert id, and every signal that fired with its
weight and evidence.

| Preset | Signals stacked | Band · classification |
|---|---|---|
| **Pay landlord** — 8,000 CZK, known payee | new-device (+ headless in an automation browser) | **ALLOW** in a normal browser · **STEP_UP** here → OTP challenge |
| **New payee — large** — 150,000 CZK, first-time payee | first-time payee +15, amount-above-profile +25, new-device +25, dormant-reactivated +25 | **HOLD** · Account Takeover |
| **Coached transfer** — 90,000 CZK, payee added seconds ago | first-time payee +15, **rushed-new-payee +20**, amount-above-profile +25, headless +30 | **HOLD** · **APP Scam** |

The **STEP_UP** path renders a one-time-code screen; entering any 6 digits and
verifying completes the transfer ("Payment sent"). Both **HOLD** paths stop the
money and show "Payment held for review" — the alert appears in the Verawall
console Alert Queue as an `ALT-…`.

### Two kinds of HOLD

The two large transfers reach HOLD for different reasons, and the platform says
so. "New payee — large" reads as **Account Takeover** (unfamiliar device driving
a dormant account). "Coached transfer" emits `BusinessEvent.payeeAdded` and pays
that brand-new payee within seconds — the `RUSHED_NEW_PAYEE` signal fires and the
verdict is classified **APP Scam** (authorised push payment): the real customer,
socially engineered into paying a fraudster they just added. Same band, different
story, different playbook for the analyst.

### A note on `HEADLESS_BROWSER`

Automation browsers (including the one used to verify this demo) present an
automation user-agent, so `HEADLESS_BROWSER (+30)` fires and nudges the small
transfer from ALLOW into STEP_UP. In a real customer's Chrome that signal is
absent and "Pay landlord" clears as a clean **ALLOW**. The large transfer reaches
HOLD on behavioural signals alone (15+25+25+25 = 90) — headless or not.

## Anti-scam banner — local reaction, no server round-trip

Toggle **"Simulate screen-share"** in the Verawall panel and a warning banner
appears instantly at the top of the app:

> 🛡️ **Screen sharing detected on this device** — if someone phoned you and asked
> to install AnyDesk/TeamViewer, or is watching your screen, hang up.

This is the scam-in-progress interstitial banks ship to cut APP-scam losses. Two
things fire from one call:

- **Immediately, locally:** the SDK raises `onLocalRisk({ level:'warn',
  reasons:['SCREEN_SHARE'] })` and the app shows the banner — no network hop,
  because the scam is happening *now*.
- **On the next transfer:** the same call emitted a `PASSIVE_REMOTE_ACCESS`
  event, so the backend's `/v1/score` verdict carries `REMOTE_ACCESS (+35)`
  ("screen sharing active") — visible in the Verawall panel.

**Honest boundary:** a browser page *cannot* detect AnyDesk or screen capture —
those APIs don't exist, browsers block them on purpose. The detection comes from
a **native/webview shell** (Android `VirtualDisplay`, screen-recording callback,
remote-control accessibility services) that reports it into the web SDK:

```js
FraudSdk.onLocalRisk((risk) => showBannerIf(risk.reasons.includes('SCREEN_SHARE')));
// native shell, on detecting screen-share:
FraudSdk.reportRemoteAccess(true);   // → local banner + PASSIVE_REMOTE_ACCESS to server
```

In this pure-web demo the checkbox stands in for that native shell.

## How the SDK is used (see `index.html`)

```js
import { FraudSdk, BusinessEvent } from '../dist/index.js';

const { siteKey, collectorUrl } = await (await fetch('/demo/config')).json();
FraudSdk.init({ tenantId: 'wallet-acme', siteKey, collectorUrl });
FraudSdk.captureKeystrokes(document);              // timing only, never content

FraudSdk.setUser(await FraudSdk.hash(email));      // ref = SHA-256(email)
FraudSdk.business(BusinessEvent.LOGIN_RESULT, { outcome: 'SUCCESS' });
// …on transfer:
FraudSdk.business(BusinessEvent.TXN_INITIATED, { amountBucket, payeeIsNew });
await FraudSdk.flush();
const token = await FraudSdk.getToken();           // hands off to the backend
await fetch('/demo/pay', { method:'POST', body: JSON.stringify({ token, amount, payeeNew }) });
```

## Config (env)

| Var | Default | Meaning |
|---|---|---|
| `DEMO_PORT` | `8099` | port the demo serves on |
| `VERAWALL_URL` | `http://localhost:8080` | Verawall ingest/score base |
| `TENANT` | `wallet-acme` | tenant id |
| `SITE_KEY` | `site_wallet-acme_pub` | public browser site key (Origin-allowlisted) |
| `SDK_KEY` | dev default | tenant HMAC key for the backend's events/token/score |

The `SITE_KEY` is public by design (paired with an Origin allowlist); the
`SDK_KEY` is the server-side secret and never reaches the browser.
