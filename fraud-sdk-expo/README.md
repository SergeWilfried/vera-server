# @veratools/fraud-sdk-expo

Behavioral-fraud SDK for **React Native / Expo**. Captures touch & keystroke
dynamics, a device fingerprint, **screen-share / remote-access** (AnyDesk,
TeamViewer, screen recording), **in-call state** (the coached-scam signal:
active GSM/VoIP call while transacting, hang-up-then-transfer transitions), and
**screenshot detection + capture prevention**, and hands the bank's backend a
session token to score. It emits the **same mobile wire as the Android SDK**,
so the collector and scoring engine treat an RN session identically — no
server changes.

## Screenshot detection & prevention

Via `expo-screen-capture` (cross-platform, works in Expo Go — no native module):

```tsx
// Block screenshots + screen recording on a sensitive screen:
useEffect(() => {
  FraudSdk.preventScreenCapture(true);      // on mount
  return () => { FraudSdk.preventScreenCapture(false); }; // on unmount
}, []);

// React to a screenshot (also sent to the backend as PASSIVE_SCREENSHOT):
FraudSdk.onScreenshot(() => showWarning('Never share screenshots of your codes'));
```

A screenshot during a session scores as `SCREENSHOT` (coached exfiltration:
victims are told to screenshot an OTP / balance and send it to the "agent").

It's the mobile sibling of [`@veratools/fraud-sdk-web`](../fraud-sdk-web): same
wire, same tenant, same console; different (native) collectors.

## Public site key (no secret in the app)

Auth is a **public per-tenant site key** (safe to ship in the bundle), paired
with a tenant allowlist server-side. The app never holds an HMAC key — the
session **token is minted server-side** and the bank's backend makes the
server-to-server `/v1/score` call.

## Install

```bash
npx expo install @veratools/fraud-sdk-expo expo-crypto expo-device expo-secure-store
```

The screen-share detection (Android) and in-call detection (Android via
`AudioManager` — permissionless, sees WhatsApp/Telegram VoIP calls; iOS via
`CXCallObserver` + `AVAudioSession`) ship as bundled **Expo native modules**.
They need a **dev build** — `npx expo prebuild` / EAS — because native code
**can't run in Expo Go**. Everything else (touch, keystroke, business events,
token) works in Expo Go; without the native modules, screen-share and call
state are reported manually via `reportRemoteAccess()` / `reportCallState()`.

## Quick start

```tsx
import { FraudSdk, BusinessEvent } from '@veratools/fraud-sdk-expo';

// once, on app start — await it (install id is loaded from the keystore)
await FraudSdk.init({
  tenantId: 'wallet-acme',
  siteKey: 'site_wallet-acme_pub',
  collectorUrl: 'https://collector.example.com',
});

// bind identity (hash PII first)
FraudSdk.session().setUser(await FraudSdk.hash(userEmail));

// keystroke timing on any field (timing only, never characters)
<TextInput secureTextEntry {...FraudSdk.trackInput('login.pin')} />

// touch dynamics on a wrapping view
<View {...FraudSdk.touch().panHandlers}>{/* your screens */}</View>

// business events
FraudSdk.session().event(BusinessEvent.txnInitiated({ amountBucket: 'HIGH', payeeIsNew: true }));

// right before your backend's /score: flush, then hand off the token
await FraudSdk.flush();
const token = await FraudSdk.session().getToken();
await fetch('/pay', { method: 'POST', body: JSON.stringify({ token, amount }) });
```

## Screen-share / anti-scam banner

On Android the bundled native module watches for the *effect* of remote control /
capture — an extra `VirtualDisplay` (AnyDesk/TeamViewer/MediaProjection
screen-share, casting), the **Android 15+ screen-recording callback** (catches
the on-device recorder, which adds no extra display; needs the install-time
`DETECT_SCREEN_RECORDING` permission, declared in the module manifest), or a
remote-control accessibility service. When it flips, the SDK does two things:

- **immediately, locally** — raises `onLocalRisk({ level:'warn',
  reasons:['SCREEN_SHARE'] })` so the app can show a "someone may be watching your
  screen — hang up" banner with **no server round-trip** (the scam is happening
  now);
- **for scoring** — emits `PASSIVE_REMOTE_ACCESS`, so the next `/v1/score` carries
  `REMOTE_ACCESS (+35)`.

```tsx
FraudSdk.onLocalRisk((risk) => {
  setShowScamBanner(risk.reasons.includes('SCREEN_SHARE'));
});
```

No native module (Expo Go / iOS)? The app's own shell reports it:

```tsx
FraudSdk.reportRemoteAccess(true); // → local banner + PASSIVE_REMOTE_ACCESS
```

## What it captures

| Signal | Source | Event |
|---|---|---|
| Device fingerprint / known device | `expo-device` + install id | `PASSIVE_DEVICE_FINGERPRINT` |
| Touch dynamics (duration, path, straightness) | `PanResponder` | `PASSIVE_TOUCH_STROKES` |
| Keystroke timing + paste heuristic | `TextInput` | `PASSIVE_KEYSTROKES` |
| Screen-share / recording / remote-control | native module (Android) | `PASSIVE_REMOTE_ACCESS` |
| Login / payee / transfer / step-up | your calls | `BIZ_*` |

## Privacy

- Timing and geometry only — never keystroke characters, never screen contents.
- Hash identifiers with `FraudSdk.hash(value)` (SHA-256) before `setUser`.
- Install id lives in the OS keystore (`expo-secure-store`); the session token
  holds no PII and is minted server-side.

## API

- `FraudSdk.init(config)` — **async**; call once on app start; idempotent.
- `FraudSdk.session().setUser(hashedRef)` / `.clearUser()` — bind/rotate identity.
- `FraudSdk.session().event(BusinessEvent.…)` / `.screenView(id)` — business events.
- `FraudSdk.session().getToken()` — the minted session token.
- `FraudSdk.trackInput(fieldId)` — props to spread onto a `<TextInput>`.
- `FraudSdk.touch()` — `{ panHandlers, flush }` for a wrapping `<View>`.
- `FraudSdk.onLocalRisk(cb)` — subscribe to local risk (screen-share); no server hop.
- `FraudSdk.reportRemoteAccess(active)` — manual screen-share report.
- `FraudSdk.flush()` — force-upload (flushes touch strokes first).
- `FraudSdk.hash(value)` — SHA-256 hex for PII.

`config`: `{ tenantId, siteKey, collectorUrl, sdk?, flushIntervalMs?, remoteAccessPollMs? }`.

## Architecture

`src/wire` + `src/core` are platform-agnostic (no RN imports) and typecheck in
plain Node; `src/platform` + `src/collectors` + `android/` are the RN/Expo
adapters. This keeps the wire logic testable and the native surface small.

## Verification

- `npm run typecheck` — the SDK typechecks against RN/Expo (ambient shims in
  `typecheck/` stand in for the real packages in this repo).
- Wire conformance: `node ../fraud-ingest-server/simulate-sdk.js rn <collector>`
  replays exactly what this SDK emits → **HOLD / Account Takeover** with
  `REMOTE_ACCESS`, proving RN sessions score with the existing mobile signals.
- The native Android module is written to the Expo Modules API pattern; it is
  **not built/run on a device in this repo** (no Android toolchain), matching how
  the native Android SDK is verified — server-side scoring + conformance.
