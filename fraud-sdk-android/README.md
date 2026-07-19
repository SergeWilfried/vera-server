# Fraud SDK — Android (Java) v0.2

Behavioral fraud-detection SDK for banks and wallet providers. Zero runtime
dependencies (org.json, javax.crypto, java.util.concurrent all ship with Android).
minSdk 21. All public calls are fire-and-forget and never throw.

## Integration (3 steps)

```java
// 1. Application.onCreate()
FraudSdk.init(this, SdkConfig.builder()
    .tenantId("wallet-acme")
    .environment(Environment.PRODUCTION)
    .tenantHmacKey(keyFromSecureProvisioning)   // >= 32 bytes
    .tenantHashSalt(tenantSalt)
    .build());

// 2. After login
FraudSdk.session().setUser(FraudSdk.hash(msisdn));
FraudSdk.session().event(BusinessEvent.loginResult(BusinessEvent.Outcome.SUCCESS));

// 3. Before critical API calls
request.header("X-Fraud-Session", FraudSdk.session().getSessionToken());
FraudSdk.flush();
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
| Location (geohash-5/7, tiered) | collectors/LocationCollector | session start |
| Business events | events/BusinessEvent | explicit SessionContext calls |

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
  already holds it, truncated to geohash before leaving the device.

## v0.3 TODO

- Play Integrity async verdict wiring (client lib is compileOnly)
- Sensor micro-window capture during text entry (accel/gyro)
- Protobuf envelope (JSON now for debuggability)
- EncryptedSharedPreferences/Keystore for installId + HMAC key at rest
