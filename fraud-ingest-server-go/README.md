# Fraud Ingest Server — Go

Go port of [`../fraud-ingest-server`](../fraud-ingest-server) (Node),
the canonical/production implementation and the backend the Verawall
console runs against. Same Postgres schema, same wire contracts, same
scoring weights. The Node server is **frozen** as the SDK wire-format
reference and conformance harness; the console-only additions here
(analyst invitations + MFA) exist in Go only.

## Conformance

The Node simulator is the acceptance suite. The nine core scenarios must
pass unchanged, plus the Go-only `invite` scenario:

    createdb vera_fraud                    # once, shared with the Node server
    go build -o vera-go . && PORT=8080 ./vera-go
    cd ../fraud-ingest-server
    node simulate-sdk.js all    http://localhost:8080   # 9 core scenarios
    node simulate-sdk.js invite http://localhost:8080   # invitations + MFA (Go only)
    node simulate-sdk.js rat    http://localhost:8080   # remote-access / ODF (Go only)
    node simulate-sdk.js web    http://localhost:8080   # browser collector + web scoring (Go only)
    node simulate-sdk.js geo    http://localhost:8080   # location integrity (Go only)
    node simulate-sdk.js retry  http://localhost:8080   # webhook outbox retries (Go only)

The `rat` scenario proves the `REMOTE_ACCESS` scoring signal: a known-device
session with an active screen-share (`PASSIVE_REMOTE_ACCESS`) + scripted input
holds as Account Takeover, and an obscured-touch overlay alone also raises it.

The `web` scenario proves the browser collector + web scoring: a fresh-browser
session mints a token through the public site-key endpoint, streams a headless
fingerprint and robotic mouse strokes through `/v1/collect`, and holds as
Account Takeover with `HEADLESS_BROWSER` + `MOUSE_ANOMALY`.

The `geo` scenario proves location integrity: an attacker who spoofs GPS to
the victim's usual geohash silences `GEO_UNUSUAL` but raises `MOCK_LOCATION`
(the evasion becomes the detection), and a fix 4,900 km from one minutes
earlier raises `IMPOSSIBLE_TRAVEL` (geohash-centroid velocity).

The `retry` scenario proves the webhook outbox: the bank receiver rejects the
synchronous first attempt, and the Postgres-backed dispatcher redelivers
(`X-Attempt: 2`) with no client involvement. All five are Go-only
(post-freeze), like `invite`.

Covers: behavioral scoring (clean/coached/ato/mule), ledger-only
detectors (feedmule, agent commission fraud), the action channel
(webhook + device kill-switch + SDK ack protocol), analyst auth/RBAC
(login, role probes, revocation, service-key limits), and the full
invitation + TOTP lifecycle.

## Console API additions (invitations & MFA)

Beyond the shared console API (see the Node README), this server adds
analyst onboarding with two-factor:

    POST   /v1/console/team/invitations            {email, role}        (admin)
    GET    /v1/console/team/invitations                                  (admin)
    DELETE /v1/console/team/invitations/{token}                          (admin)
    POST   /v1/console/team/invitations/{token}/resend                   (admin)
    GET    /v1/console/invitations/{token}          public: context + otpauthUri
    POST   /v1/console/invitations/{token}/accept   public: {name, password, code}

Read-only console views derived from stored data:

    GET /v1/console/detections?days=30    alert counts per threat type
    GET /v1/console/transaction-risk      recent /score decisions + auth mix
    GET /v1/console/activity?limit=8       unified alerts/actions/cases feed

Tenant settings + API keys:

    GET   /v1/console/settings            defaults + stored overrides + derived facts
    PATCH /v1/console/settings            (admin) persist notifications/modules/tenant
    GET   /v1/console/api-keys            (admin) list, masked prefix••••last4
    POST  /v1/console/api-keys            (admin) {name, scope} -> full key ONCE
    DELETE /v1/console/api-keys/{id}      (admin) revoke

### Browser collector (public site key)

The browser SDK ([`../fraud-sdk-web`](../fraud-sdk-web)) can't hold the tenant
HMAC secret, so its telemetry is authed by a **public** per-tenant site key +
an Origin allowlist, and the server mints the session token:

    POST /v1/collect/token   {sessionId, installId, userRef?} -> {token}
    POST /v1/collect         NDJSON event batch (same envelope as /v1/events)

Both require `X-Tenant-Id` + `X-Site-Key` headers and an allowlisted `Origin`;
CORS is enabled on `/v1/collect*` (unlike the server-to-server `/v1/score`,
which the bank backend calls with the minted token). `/v1/collect` accepts
`Content-Encoding: gzip` and routes into the same `recordBatch` path as mobile
events, so web and Android sessions score through one engine. Web-specific
signals: `HEADLESS_BROWSER` (from `PASSIVE_WEB_FINGERPRINT`) and `MOUSE_ANOMALY`
(mouse strokes vs the user's baseline). Config: `SITE_KEY`, `SITE_ORIGINS`.

Generated keys (`tm_live_…`) are functional: stored as a sha256 hash,
they authenticate the console/ingest API via the same bearer path —
scope `read` acts read-only, `read/write` acts at senior rank — and
each use bumps `last_used_at`.

- An invitation mints a TOTP secret; the invitee scans the `otpauthUri`
  QR (or types the base32 key) and proves a code before the account is
  created. The secret moves onto the analyst row at acceptance.
- `POST /v1/console/login` gains a `code` field: when the analyst has a
  TOTP secret, the server answers `401 {"error":"mfa_required",
  "mfaRequired":true}` until a valid code is supplied. Accounts without
  a secret (bootstrap admin, service keys) are unaffected.
- TOTP is RFC 6238 (SHA-1/30s/6 digits, ±1 window) in `totp.go`,
  mirroring the console's former client module.

## Serving the console

The Vite console (`../../verawall`) talks to this server via
`VITE_API_BASE`. CORS is enabled on `/v1/console/*` only:

    CORS_ORIGIN=http://localhost:5199,http://localhost:5173   # default

Seed demo data (alerts/cases/ledger) into an empty DB by running the
conformance suite once against a live server, then open the console and
sign in as the bootstrap admin.

## Layout

    main.go           config, routing, startup, schema apply, admin seed
    ingest.go         /v1/events  /v1/transactions  /v1/score  /stats
    console.go        console API: login (+MFA), RBAC routes, invitations, webhook
    scoring.go        scoring engine — pure logic, mirrors Node scoring.js
    store.go          ingest/scoring-context/feed SQL (pgx)
    store_console.go  alerts/cases/actions/profiles/analyst-auth/invitations SQL
    totp.go           RFC 6238 TOTP (stdlib), for invitation MFA enrollment
    util.go           HMAC, session-token verify, helpers
    schema.sql        shared with ../fraud-ingest-server — keep in sync

Deps: `pgx/v5`, `golang.org/x/crypto` (scrypt). Everything else stdlib.

## Config (env)

    DATABASE_URL            postgres://localhost/vera_fraud
    PORT                    8080
    CORE_WEBHOOK            http://localhost:8090/core-banking/hooks
    CONSOLE_KEY             dev-console-key   (service key, senior-level)
    CONSOLE_ADMIN_EMAIL     admin@demobank.cz (bootstrap admin, first boot)
    CONSOLE_ADMIN_PASSWORD  admin-dev-password
    SITE_KEY                site_wallet-acme_pub  (public browser-SDK site key)
    SITE_ORIGINS            http://localhost:5199,http://localhost:5173,http://localhost:8099

Tenant HMAC keys live in `main.go` (`TENANTS`) for now, like the Node
server — move to secret storage before production.

## Parity notes

- Password hashes are portable: scrypt N=16384 r=8 p=1, salt used as its
  hex-string bytes — exactly Node's `crypto.scryptSync` defaults, so
  analysts created by either server can log in through the other.
- Endpoint semantics, policy bands (55/85), detector thresholds, RBAC
  ranks and webhook/retry behavior mirror the Node server; consult its
  [README](../fraud-ingest-server/README.md) for the full API reference.
- Webhook delivery is a Postgres-backed outbox: the first attempt is
  synchronous (the console response carries real status); failures are
  scheduled in `actions.webhook_next_attempt_at` (5s·2^n jittered, cap 1h,
  `dead` after 10 attempts) and replayed by a dispatcher that claims rows
  with `FOR UPDATE SKIP LOCKED` — restart-safe, and safe to run on every
  instance. Delivery is at-least-once: receivers must dedupe on the action
  `id` (an `X-Attempt` header aids observability). Remaining hardening
  TODOs: per-tenant key management and a broader horizontal-scale review.
