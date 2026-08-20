# Fraud SDK — Android (Java) v0.3

Behavioral fraud-detection SDK for banks and wallet providers. Zero runtime
dependencies (org.json and java.util.concurrent ship with Android).
minSdk 21. All public calls are fire-and-forget and never throw.

**v0.3 — no signing key in the app.** v0.2 embedded the tenant HMAC key in
the APK (any decompiler yielded the tenant secret) and minted session tokens
on-device. The SDK now uploads via the collect path authenticated by the
per-tenant **native app key** (`X-App-Key` — ships in the binary like any
mobile API key, never served to web visitors, rotatable with
`tenant rotate-app-key`), and the session token is **minted server-side**.
The forward path is device attestation (Play Integrity / App Attest)
presented in this same slot.

## Integration (3 steps)

```java
// 1. Application.onCreate()
FraudSdk.init(this, SdkConfig.builder()
    .tenantId("wallet-acme")
    .environment(Environment.PRODUCTION)
    .appKey(appKeyFromProvisioning)      // native credential — NOT the HMAC key
    .tenantHashSalt(tenantSalt)
    .build());

// 2. After login
FraudSdk.session().setUser(FraudSdk.hash(msisdn));
FraudSdk.session().event(BusinessEvent.loginResult(BusinessEvent.Outcome.SUCCESS));

// 3. Before critical API calls — tokens are minted server-side, so prefer
//    the async getter right before a payment (the sync one returns the
//    cached token and may briefly be "" after init/login):
FraudSdk.session().getSessionToken(token -> {
    request.header("X-Fraud-Session", token);
    FraudSdk.flush();
});
```

Optional per-field keystroke dynamics (timing only, never content) —
attach once per sensitive field with a stable id:

```java
FraudSdk.captureKeystrokes(pinField, "login.pin");
FraudSdk.captureKeystrokes(amountField, "transfer.amount");
```

## Server commands (kill switch)

When a fraud analyst terminates a session, the platform hands the command
to the device in the next batch-upload response (latency is bounded by
the upload interval, 15s by default). The SDK acks inside the dying
session, unbinds the user, rotates its session id, then notifies the
host app on the main thread:

```java
FraudSdk.setCommandListener(sessionId -> {
    // Force logout: clear auth tokens, return to the login screen.
});
```

Treat the callback as defense in depth — the platform also pushes
`session.terminate` to your backend's core-banking webhook, which should
invalidate the app session server-side regardless.

## What's collected

| Layer | Class | Trigger |
|---|---|---|
| Touch strokes (aggregated) | capture/TouchCapture | automatic, all activities |
| Keystroke timing | capture/KeystrokeCapture | opt-in per field (FraudSdk.captureKeystrokes) |
| Device fingerprint | collectors/DeviceFingerprintCollector | session start |
| SIM telemetry + swap flag | collectors/SimTelemetryCollector | session start |
| Root/emulator/hooking/accessibility | collectors/IntegrityCollector | session start |
| Location (geohash-5/7, tiered) + mock-provider flag | collectors/LocationCollector | session start |
| Remote access / screen sharing | collectors/RemoteAccessCollector | session start + on business events |
| Business events | events/BusinessEvent | explicit SessionContext calls |

### Remote-access (RAT / on-device-fraud) detection

`RemoteAccessCollector` detects the *effect* of remote control, not a named
app (no reliable "AnyDesk detected" API exists pre-Android-15):

- **Screen sharing** — an extra/virtual display from `DisplayManager`
  (MediaProjection / VirtualDisplay that AnyDesk/TeamViewer spin up), and the
  Android-15 `addScreenRecordingCallback` state when available.
- **Remote-control accessibility** — enabled accessibility services matched
  against a denylist (anydesk/teamviewer/rustdesk/…); only then is a tool named.
- **Overlay** — `TouchCapture` flags strokes whose `MotionEvent` is obscured.
- **Injected input** — the server flags robotic strokes (dead-straight,
  constant pressure) from the touch data already sent.

Emitted as `PASSIVE_REMOTE_ACCESS` at session start and re-sampled on each
business event (a screen-share usually starts right before the transfer),
mirroring how call state rides on business events. The server raises a
`REMOTE_ACCESS` scoring signal → Account Takeover (especially with an active
call — the ODF fingerprint). Reports "likely"; **no `QUERY_ALL_PACKAGES`**
(effect detection only, Play-policy safe).

## Transport

NDJSON events -> file-backed queue (survives restarts, 512KB cap, oldest-first
eviction) -> gzip batch -> HMAC-SHA256 signed POST every 15s with exponential
backoff. 4xx batches are dropped (poison), 5xx/429 retried. 2xx response
bodies are parsed for server `commands` (see kill switch above); malformed
bodies are ignored.

## Privacy invariants

- No IMEI/serial/ICCID. No raw lat/lon. No keystroke content, ever.
- All identifiers pass through per-tenant salted SHA-256 (FraudSdk.hash).
- Location: SDK never requests permission; reads last-known only if host app
  already holds it, truncated to geohash before leaving the device. Each fix
  carries a `mock` integrity flag (fake-GPS provider) — spoofing to a "usual"
  location raises MOCK_LOCATION server-side instead of silencing the geo
  signal, and cross-session velocity powers IMPOSSIBLE_TRAVEL.

## v0.3 TODO

- Play Integrity async verdict wiring (client lib is compileOnly)
- Sensor micro-window capture during text entry (accel/gyro)
- Protobuf envelope (JSON now for debuggability)
- EncryptedSharedPreferences/Keystore for installId + HMAC key at rest
