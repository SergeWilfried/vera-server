-- Fraud ingest server — persistence schema (Postgres 14+).
-- Applied idempotently at boot (db.js). Multi-tenant from day one:
-- every row is scoped by tenant_id, matching SdkConfig.tenantId.

CREATE TABLE IF NOT EXISTS tenants (
  id          text PRIMARY KEY,
  name        text NOT NULL DEFAULT '',
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- Pseudonymous subjects (userRef = per-tenant salted SHA-256, never raw PII).
CREATE TABLE IF NOT EXISTS app_users (
  tenant_id   text NOT NULL REFERENCES tenants(id),
  user_ref    text NOT NULL,
  first_seen  timestamptz NOT NULL DEFAULT now(),
  last_seen   timestamptz NOT NULL DEFAULT now(),
  session_count integer NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, user_ref)
);

-- One row per SDK install (installId survives across sessions).
CREATE TABLE IF NOT EXISTS devices (
  tenant_id   text NOT NULL REFERENCES tenants(id),
  install_id  text NOT NULL,
  first_seen  timestamptz NOT NULL DEFAULT now(),
  last_seen   timestamptz NOT NULL DEFAULT now(),
  fingerprint jsonb,                        -- latest PASSIVE_DEVICE_FINGERPRINT payload
  PRIMARY KEY (tenant_id, install_id)
);

-- Which devices a user has been seen on — powers "known device / NEW device".
CREATE TABLE IF NOT EXISTS user_devices (
  tenant_id   text NOT NULL,
  user_ref    text NOT NULL,
  install_id  text NOT NULL,
  first_seen  timestamptz NOT NULL DEFAULT now(),
  last_seen   timestamptz NOT NULL DEFAULT now(),
  session_count integer NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, user_ref, install_id)
);

CREATE TABLE IF NOT EXISTS sessions (
  tenant_id     text NOT NULL REFERENCES tenants(id),
  session_id    text NOT NULL,
  install_id    text,
  user_ref      text,
  started_at    timestamptz NOT NULL,
  last_event_at timestamptz NOT NULL,
  event_count   integer NOT NULL DEFAULT 0,
  sim_changed   boolean NOT NULL DEFAULT false,   -- SIM-swap flag seen this session
  PRIMARY KEY (tenant_id, session_id)
);

-- Raw event stream (the NDJSON lines, structured).
CREATE TABLE IF NOT EXISTS events (
  id           bigserial PRIMARY KEY,
  tenant_id    text NOT NULL,
  session_id   text NOT NULL,
  install_id   text,
  user_ref     text,
  type         text NOT NULL,
  ts           timestamptz NOT NULL,
  call_signals jsonb,
  payload      jsonb,
  received_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS events_session_idx ON events (tenant_id, session_id, ts);
CREATE INDEX IF NOT EXISTS events_type_idx    ON events (tenant_id, type, ts);
CREATE INDEX IF NOT EXISTS events_user_idx    ON events (tenant_id, user_ref, ts);

-- Every /v1/score call and its outcome (the decision audit trail).
CREATE TABLE IF NOT EXISTS decisions (
  id          bigserial PRIMARY KEY,
  tenant_id   text NOT NULL,
  session_id  text NOT NULL,
  user_ref    text,
  txn_ref     text,
  txn         jsonb NOT NULL,               -- transaction object as submitted
  decision    text NOT NULL,                -- ALLOW | STEP_UP | HOLD
  score       integer NOT NULL,             -- 0–100, console policy bands
  reasons     jsonb NOT NULL DEFAULT '[]',
  signals     jsonb NOT NULL DEFAULT '[]',  -- [{code, label, weight, evidence}]
  alert_id    text,                         -- set when the decision raised an alert
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS decisions_tenant_idx ON decisions (tenant_id, created_at);

-- Bank-side transaction feed: the tenant's core banking pushes settled
-- ledger movements (both directions), account/counterparty refs hashed.
-- This is what makes inbound transfers — and thus mule velocity — visible.
CREATE TABLE IF NOT EXISTS bank_txns (
  id               bigserial PRIMARY KEY,
  tenant_id        text NOT NULL,
  txn_ref          text NOT NULL,
  account_ref      text NOT NULL,
  user_ref         text,                    -- link to behavioral profile, when known
  direction        text NOT NULL,           -- IN | OUT
  amount           numeric NOT NULL,
  currency         text,
  counterparty_ref text,
  channel          text,
  ts               timestamptz NOT NULL,
  received_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, txn_ref)               -- feed replays are idempotent
);
CREATE INDEX IF NOT EXISTS bank_txns_account_idx ON bank_txns (tenant_id, account_ref, ts);
CREATE INDEX IF NOT EXISTS bank_txns_user_idx    ON bank_txns (tenant_id, user_ref, ts);
CREATE INDEX IF NOT EXISTS bank_txns_cp_idx      ON bank_txns (tenant_id, counterparty_ref);

CREATE SEQUENCE IF NOT EXISTS alert_seq START 2001;
CREATE SEQUENCE IF NOT EXISTS case_seq  START 1001;

-- Analyst-facing alert queue.
CREATE TABLE IF NOT EXISTS alerts (
  id          text PRIMARY KEY,             -- ALT-2001, ALT-2002, ...
  tenant_id   text NOT NULL,
  session_id  text,                         -- NULL for feed-originated alerts
  account_ref text,                         -- set for feed-originated alerts
  install_id  text,
  user_ref    text,
  score       integer NOT NULL,
  threat_type text,                         -- classification lands with the scoring engine (step 2)
  signal      text NOT NULL,                -- human-readable reason summary
  state       text NOT NULL DEFAULT 'Open', -- Open | Contained | Resolved
  txn         jsonb,                        -- held transaction, when applicable
  signals     jsonb NOT NULL DEFAULT '[]',  -- behavioral signals that fired
  disposition text,
  case_id     text,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS alerts_queue_idx ON alerts (tenant_id, state, created_at DESC);

CREATE TABLE IF NOT EXISTS cases (
  id          text PRIMARY KEY,             -- C-1001, C-1002, ...
  tenant_id   text NOT NULL,
  user_ref    text,
  threat_type text,
  status      text NOT NULL DEFAULT 'Investigating', -- Investigating | Escalated | Pending | Closed
  assignee    text NOT NULL DEFAULT 'Unassigned',
  summary     text NOT NULL DEFAULT '',
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS case_events (
  id        bigserial PRIMARY KEY,
  case_id   text NOT NULL REFERENCES cases(id),
  event     text NOT NULL,
  at        timestamptz NOT NULL DEFAULT now()
);

CREATE SEQUENCE IF NOT EXISTS action_seq START 1;

-- Analyst actions flowing back out of the platform. Each action has up to
-- two delivery legs: a signed webhook to the tenant's core banking, and —
-- for session termination — a command handed to the device on its next
-- SDK batch upload.
CREATE TABLE IF NOT EXISTS actions (
  id                   text PRIMARY KEY,    -- ACT-1, ACT-2, ...
  tenant_id            text NOT NULL,
  alert_id             text REFERENCES alerts(id),
  kind                 text NOT NULL,       -- RELEASE_PAYMENT | BLOCK_PAYMENT | TERMINATE_SESSION
  target               jsonb NOT NULL,      -- {txnRef?, sessionId?, amount?}
  note                 text,
  requested_by         text,
  webhook_status       text NOT NULL DEFAULT 'pending',  -- pending | delivered | failed | dead
  webhook_attempts     integer NOT NULL DEFAULT 0,
  webhook_delivered_at timestamptz,
  webhook_next_attempt_at timestamptz,   -- outbox: when the dispatcher retries
  last_error           text,
  device_status        text NOT NULL DEFAULT 'n/a',      -- n/a | pending | delivered
  device_delivered_at  timestamptz,
  created_at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS actions_device_idx
  ON actions (tenant_id, device_status) WHERE device_status = 'pending';
-- Outbox migration for pre-existing databases (CREATE TABLE above is a no-op
-- there); the partial index keeps the dispatcher's due-scan cheap.
ALTER TABLE actions ADD COLUMN IF NOT EXISTS webhook_next_attempt_at timestamptz;
CREATE INDEX IF NOT EXISTS actions_webhook_due_idx
  ON actions (webhook_next_attempt_at)
  WHERE webhook_status IN ('pending', 'failed');

-- Analyst accounts for the console API. Passwords are scrypt-hashed with
-- a per-account salt; tokens are opaque, stored server-side (revocable).
CREATE TABLE IF NOT EXISTS analysts (
  id            bigserial PRIMARY KEY,
  tenant_id     text NOT NULL REFERENCES tenants(id),
  email         text NOT NULL,
  name          text NOT NULL DEFAULT '',
  role          text NOT NULL DEFAULT 'analyst',  -- readonly | analyst | senior | admin
  password_salt text NOT NULL,
  password_hash text NOT NULL,
  disabled      boolean NOT NULL DEFAULT false,
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, email)
);

CREATE TABLE IF NOT EXISTS analyst_sessions (
  token       text PRIMARY KEY,
  analyst_id  bigint NOT NULL REFERENCES analysts(id),
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL
);

-- Analyst invitations: the admin invites by email; the invitee sets their
-- password and enrolls TOTP two-factor from the invitation link. The TOTP
-- secret is minted with the invitation and moves onto the analyst row at
-- acceptance. Accepted rows are kept for audit.
CREATE TABLE IF NOT EXISTS invitations (
  token       text PRIMARY KEY,
  tenant_id   text NOT NULL REFERENCES tenants(id),
  email       text NOT NULL,
  role        text NOT NULL,             -- readonly | analyst | senior | admin
  invited_by  text NOT NULL,
  totp_secret text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  accepted_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS invitations_pending_email_idx
  ON invitations (tenant_id, email) WHERE accepted_at IS NULL;

-- Per-tenant console configuration (notifications, module toggles,
-- integrations, editable tenant fields) as one jsonb blob. Derived values
-- (session-ingestion counts, etc.) are computed at read time, not stored.
CREATE TABLE IF NOT EXISTS tenant_settings (
  tenant_id  text PRIMARY KEY REFERENCES tenants(id),
  settings   jsonb NOT NULL DEFAULT '{}',
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- API keys for machine/integration access (SIEM export, core-banking, ...).
-- The full key is shown once at creation; only its salted hash is stored.
-- prefix keeps the first chars for display; scope gates access level.
CREATE TABLE IF NOT EXISTS api_keys (
  id           text PRIMARY KEY,           -- KEY-1, KEY-2, ...
  tenant_id    text NOT NULL REFERENCES tenants(id),
  name         text NOT NULL,
  prefix       text NOT NULL,              -- e.g. tm_live_1a2b (display)
  last4        text NOT NULL,
  key_hash     text NOT NULL,              -- sha256(secret)
  scope        text NOT NULL DEFAULT 'read',  -- read | read/write
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  revoked_at   timestamptz
);
CREATE INDEX IF NOT EXISTS api_keys_lookup_idx ON api_keys (key_hash) WHERE revoked_at IS NULL;
CREATE SEQUENCE IF NOT EXISTS api_key_seq START 1;

-- Idempotent upgrades for databases created before these columns existed.
ALTER TABLE decisions ADD COLUMN IF NOT EXISTS signals jsonb NOT NULL DEFAULT '[]';
ALTER TABLE alerts    ADD COLUMN IF NOT EXISTS signals jsonb NOT NULL DEFAULT '[]';
ALTER TABLE alerts    ADD COLUMN IF NOT EXISTS account_ref text;
ALTER TABLE alerts    ALTER COLUMN session_id DROP NOT NULL;
ALTER TABLE analysts  ADD COLUMN IF NOT EXISTS totp_secret text;  -- NULL = no MFA (bootstrap admin)
