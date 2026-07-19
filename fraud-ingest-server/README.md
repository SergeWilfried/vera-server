# Fraud SDK Ingest Server

Both ends of the pipe, now with real persistence: Postgres-backed sessions,
devices, users, events, decisions, alerts and cases, plus a console API.
Single npm dependency (`pg`). Node >= 18.

## Run

    createdb vera_fraud             # once (or set DATABASE_URL)
    npm install
    node server.js                  # listens on :8080 (PORT env to change)
    node simulate-sdk.js            # raw wire-format demo batch + score
    node simulate-sdk.js all        # behavioral scenarios: clean -> ALLOW,
                                    # coached/ato/mule -> HOLD w/ threat type,
                                    # feedmule -> ledger-only mule alert,
                                    # agent -> commission-split alert,
                                    # actions -> webhook + device kill-switch,
                                    # auth -> login + RBAC role probes
                                    # (or run one: clean | coached | ato |
                                    #  mule | feedmule | agent | actions | auth)

Schema is applied idempotently at boot from `schema.sql`.
Env: `DATABASE_URL` (default `postgresql://localhost/vera_fraud`),
`CONSOLE_KEY` (default `dev-console-key`), `PORT`.

## SDK-facing endpoints

- **POST /v1/events** — what the Android SDK's EventUploader hits.
  Verifies the HMAC-SHA256 `X-Signature` over the raw gzipped body,
  gunzips, parses NDJSON, pretty-prints each event (call signals
  highlighted in red), then persists atomically: raw `events`, plus
  incrementally maintained `sessions`, `devices`, `app_users` and
  `user_devices` (powers "known device / NEW device" lookups).
- **POST /v1/score** — the token join. Verifies the sessionToken minted
  by the SDK, then runs the behavioral scoring engine (`scoring.js`) over
  the stored evidence for that session plus the user's history, on the
  console's 0–100 policy bands:
  0–54 **ALLOW** · 55–84 **STEP_UP** · 85–100 **HOLD**.
  Every call is recorded in `decisions` with the signals that fired; a
  HOLD raises an **Open alert** (with signal detail and a threat-type
  classification) and returns its `alertId`.

## Scoring signals

Each signal is `{code, label, weight, evidence}`; the total is capped at 100.

| Signal | Wt | Fires when |
|---|---|---|
| ACTIVE_CALL | 35 | GSM/VoIP call active on a business event (coached session) |
| DEVICE_INTEGRITY | 30 | root indicators or hooking framework (frida/xposed) |
| NEW_DEVICE_FOR_USER | 25 | user's first session on this install |
| AMOUNT_ABOVE_PROFILE | 25 | amount > 3× median of the user's approved txns |
| TOUCH_ANOMALY | 25 | stroke tempo deviates \|z\| > 2.5 from the user's baseline |
| KEYSTROKE_ANOMALY | 20 | median inter-key latency off > 1.6× from the user's baseline |
| DORMANT_REACTIVATED | 25 | > 90 days since the user's previous session |
| NO_USER_BOUND | 20 | session token carries no userRef |
| HIGH_AMOUNT | 20 | large amount with no spending history to compare |
| EMULATOR | 20 | emulator build indicators |
| NEW_PAYEE | 15 | first-time payee (asserted by the tenant backend) |
| SIM_CHANGED | 15 | SIM-swap flag from SDK telemetry |
| RAPID_IN_OUT | 30 | outbound ≥ 60% of inbound received < 24h ago (bank feed) |
| FAN_OUT_24H | 20 | ≥ 3 distinct outbound counterparties in 24h (bank feed) |
| ACCESSIBILITY_SERVICES | 15 | accessibility services active (overlay/RAT proxy) |
| HESITATION | 10 | pauses > 4s or ≥ 3 corrections in a monitored field |
| PASTE_INPUT | 10 | pasted input in a monitored field |
| GEO_UNUSUAL | 10 | geohash area never seen for this user |
| RAPID_TO_TXN | 10 | new-payee txn < 20s after session start |

Threat classification (stored on the alert): APP Scam, Account Takeover,
Money Mule, New Account Fraud, Agent Commission Fraud — derived from
which signals co-fire.

The **ledger-only detector** (`scoreAccountFlow`) runs on feed ingestion,
per account with new outbound movement, and raises a Money Mule alert at
score ≥ 85 (deduped to one open alert per account per 24h):

| Signal | Wt | Fires when |
|---|---|---|
| RAPID_IN_OUT | 40 | ≥ 80% of ≥ 50k inbound (72h) forwarded within 24h |
| QUIET_ACCOUNT | 25 | no account activity in the 90 days before the inbound |
| FLAGGED_COUNTERPARTY | 25 | recent txns against an account with an open alert |
| FAN_OUT | 20 | ≥ 3 distinct outbound counterparties in 24h |

A second ledger detector (`scoreAgentActivity`) targets **agent commission
fraud** ("fraude à la commission agent"): an agent splits one deposit into
a burst of small near-identical transactions to the same customer to farm
per-transaction commission tiers. Same trigger (feed ingestion, per
account with new outbound movement), same ≥ 85 alert threshold and 24h
per-typology dedupe; "small" = amount ≤ 10,000 (commission-tier sized):

| Signal | Wt | Fires when |
|---|---|---|
| SPLIT_TXNS | 45 | ≥ 5 small txns to a single counterparty in 24h |
| MICRO_BURST | 25 | ≥ 10 small txns in 24h across all counterparties |
| UNIFORM_AMOUNTS | 20 | ≥ 60% of the account's 24h txns share one amount |
- **POST /v1/transactions** — the bank-side feed. The tenant's core
  banking pushes settled ledger movements (`{"transactions": [{txnRef,
  accountRef, direction: "IN"|"OUT", amount, counterpartyRef?, userRef?,
  ts?, ...}]}`), signed with the same per-tenant HMAC over the raw body.
  Replays are absorbed (`txnRef` is unique). This is what makes **inbound
  transfers visible**: every account that gains an OUT movement is
  re-checked by the ledger-only mule detector, which can raise a
  Money Mule alert with no app session involved at all. Feed data also
  powers the RAPID_IN_OUT / FAN_OUT_24H signals at session-score time.
- **GET /stats** — event counts per type, from Postgres.

## Console API (`Authorization: Bearer <token>`)

### Analyst auth & RBAC

Humans log in with per-analyst accounts; machines use service keys.

    POST  /v1/console/login      {email, password} -> {token, analyst}
    POST  /v1/console/logout     revokes the token
    GET   /v1/console/me         current identity
    GET   /v1/console/team       list analysts            (admin)
    POST  /v1/console/team       {email, name, role, password}  (admin)
    PATCH /v1/console/team/:id   {role?, disabled?}       (admin; disabling
                                                           revokes sessions)

Passwords are scrypt-hashed (per-account salt); tokens are opaque,
DB-backed and revocable, 12h TTL. A bootstrap admin is seeded at first
boot (`CONSOLE_ADMIN_EMAIL` / `CONSOLE_ADMIN_PASSWORD`, defaults
`admin@demobank.cz` / `admin-dev-password`).

Roles, cumulative: **readonly** (GET only) < **analyst** (+ alert
dispositions, case create/update) < **senior** (+ action channel:
release/block/terminate) < **admin** (+ team management). Legacy
`CONSOLE_KEY` service keys act at senior level for integrations but can
never manage the team. Analyst identity is stamped on what they touch:
`actions.requested_by`, case timeline entries ("— by p.hruba@…").

    GET   /v1/console/overview                      queue + volume KPIs
    GET   /v1/console/alerts?state=Open             alert queue
    GET   /v1/console/alerts/:id                    alert + session timeline
                                                    + device + prior alerts
    PATCH /v1/console/alerts/:id                    {state?, disposition?}
    POST  /v1/console/alerts/:id/case               {assignee?, summary?} -> caseId
    GET   /v1/console/cases?status=                 case list
    GET   /v1/console/cases/:id                     case + timeline + linked alerts
    PATCH /v1/console/cases/:id                     {status?, assignee?, note?}
    GET   /v1/console/users/:userRef                profile: devices, sessions, alerts
    GET   /v1/console/sessions/:sessionId/events    raw session timeline
    GET   /v1/console/accounts/:ref/transactions    bank-feed ledger for an account
    POST  /v1/console/alerts/:id/actions            {kind, note?} — the action channel
    GET   /v1/console/actions                       action log w/ delivery status

## Action channel

`POST /v1/console/alerts/:id/actions` with kind `RELEASE_PAYMENT`,
`BLOCK_PAYMENT`, or `TERMINATE_SESSION`. Each action:

- updates the alert (payment decision -> Released/Blocked + Resolved;
  terminate -> Contained) and, if a case is linked, its timeline;
- is **pushed to the tenant's core-banking webhook** (`coreBankingWebhook`
  in `TENANTS`, override with `CORE_WEBHOOK`) as signed JSON
  (`payment.release` / `payment.block` / `session.terminate`, HMAC over
  the raw body with the tenant key). First attempt is awaited — the
  response carries the real `webhook_status` — then 2 background retries
  with backoff; delivery state is tracked on the action row;
- for TERMINATE_SESSION, is **also queued for the device**: the next SDK
  batch upload for that session gets `{commands: [{kind:
  "TERMINATE_SESSION", ...}]}` in its response (delivered exactly once,
  latency bounded by the SDK's 15s upload cadence). SDK v0.2 handles it:
  acks with a `PASSIVE_COMMAND_ACK` event inside the dying session,
  unbinds the user, rotates its session, and notifies the host app via
  `FraudSdk.setCommandListener` so it can force logout.

Alert states: `Open | Contained | Resolved`.
Case statuses: `Investigating | Escalated | Pending | Closed`.

## Wire it to the real SDK

1. Edit `TENANTS` in server.js — tenant id + 32-byte key must match
   `SdkConfig.tenantId` / `tenantHmacKey` on the device.
2. Point `Environment.SANDBOX` in the SDK at your machine:
   - Emulator: `http://10.0.2.2:8080/v1/events`
   - Real phone on same Wi-Fi: `http://<your-LAN-IP>:8080/v1/events`
     (plain http needs `android:usesCleartextTraffic="true"` in the
     test app's manifest, or a network security config — test only!)
3. Tap around the test app and watch the console. Call yourself on
   WhatsApp while tapping a transfer button to see the in-call flag.

## What "working" looks like

    ✓ batch tenant=wallet-acme sdk=android/0.1.0 install=0f2864f5… events=5
      PASSIVE_DEVICE_FINGERPRINT ...
      BIZ_TXN_INITIATED user=f9f0c360… IN VOIP CALL speaker
    ⚖ score txn=TXN-COACHED -> HOLD (85) APP Scam  alert ALT-2004
        +35 ACTIVE_CALL — VoIP call, speaker on
        +25 AMOUNT_ABOVE_PROFILE — 240000 vs. median 4500 over 3 approved txns

`simulate-sdk.js` also doubles as the wire-format reference if you build
the JS or Flutter SDKs next — it constructs envelopes, the gzip+HMAC
batch, and the session token exactly the way the Java SDK does.

## Layout

    server.js       HTTP surface: ingest, scoring, console routes
    scoring.js      behavioral scoring engine — pure logic, no I/O
    db.js           data-access module — the only file that speaks SQL
    schema.sql      DDL, idempotent, multi-tenant (every row tenant-scoped)
    simulate-sdk.js wire-format reference + attack-scenario replays

Alert detail (`GET /v1/console/alerts/:id`) includes the session timeline
for session alerts, and the account's recent bank ledger (`bankTxns`)
for feed-originated alerts.

Keystroke cadence baselines are live: the SDK exposes
`FraudSdk.captureKeystrokes(field, fieldId)` (timing only, never content),
and the scoring engine compares each session's median inter-key latency
against the user's history (pauses > 4s are excluded — those feed the
separate HESITATION signal).

That closes out the original gap review's platform items. Beyond this
test server, the next frontier is productization: pointing the Verawall
console UI at these APIs instead of its hardcoded demo data, real
webhook/mTLS conventions with core-banking, and horizontal scale.
