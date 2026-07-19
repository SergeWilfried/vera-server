/**
 * Persistence layer — Postgres behind a small data-access module.
 * server.js never writes SQL; it calls these functions. Swapping the
 * engine later means reimplementing this file only.
 *
 * Connection: DATABASE_URL env, default postgresql://localhost/vera_fraud.
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://localhost/vera_fraud',
  max: 10,
});

async function init(tenantIds) {
  const ddl = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
  await pool.query(ddl);
  for (const id of tenantIds) {
    await pool.query(
      'INSERT INTO tenants (id) VALUES ($1) ON CONFLICT (id) DO NOTHING', [id]);
  }
}

// ---------- analyst auth ----------

const ROLES = ['readonly', 'analyst', 'senior', 'admin'];
const SESSION_TTL_MS = 12 * 3600 * 1000;

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 32).toString('hex');
}

/** Create the bootstrap admin if the tenant has no analysts yet. */
async function seedAdmin(tenantId, email, password) {
  const existing = await pool.query(
    `SELECT 1 FROM analysts WHERE tenant_id=$1 LIMIT 1`, [tenantId]);
  if (existing.rowCount) return false;
  await createAnalyst(tenantId, { email, name: 'Bootstrap admin', role: 'admin', password });
  return true;
}

async function createAnalyst(tenantId, { email, name, role, password }) {
  if (!email || !password || password.length < 8) {
    return { error: 'email and a password of at least 8 characters are required' };
  }
  if (!ROLES.includes(role)) {
    return { error: `role must be one of: ${ROLES.join(', ')}` };
  }
  const salt = crypto.randomBytes(16).toString('hex');
  try {
    const r = await pool.query(
      `INSERT INTO analysts (tenant_id, email, name, role, password_salt, password_hash)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, email, name, role, disabled, created_at`,
      [tenantId, email, name || '', role, salt, hashPassword(password, salt)]);
    return r.rows[0];
  } catch (e) {
    if (e.code === '23505') return { error: 'an analyst with this email already exists' };
    throw e;
  }
}

/** Verify credentials; returns the analyst row or null. */
async function verifyLogin(email, password) {
  const r = await pool.query(
    `SELECT * FROM analysts WHERE email=$1 AND NOT disabled LIMIT 1`, [email]);
  const a = r.rows[0];
  if (!a) { hashPassword(password, 'burn-time-anyway'); return null; }
  const expect = Buffer.from(a.password_hash, 'hex');
  const got = Buffer.from(hashPassword(password, a.password_salt), 'hex');
  return crypto.timingSafeEqual(expect, got) ? a : null;
}

async function createAnalystSession(analystId) {
  const token = crypto.randomBytes(24).toString('hex');
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS);
  await pool.query(
    `INSERT INTO analyst_sessions (token, analyst_id, expires_at) VALUES ($1, $2, $3)`,
    [token, analystId, expiresAt]);
  return { token, expiresAt };
}

/** Resolve a bearer token to {tenant_id, analyst_id, email, name, role}. */
async function resolveAnalystToken(token) {
  const r = await pool.query(
    `SELECT s.token, s.expires_at, a.id AS analyst_id, a.tenant_id,
            a.email, a.name, a.role, a.disabled
     FROM analyst_sessions s JOIN analysts a ON a.id = s.analyst_id
     WHERE s.token = $1`, [token]);
  const s = r.rows[0];
  if (!s) return null;
  if (s.disabled || new Date(s.expires_at) < new Date()) {
    await pool.query(`DELETE FROM analyst_sessions WHERE token=$1`, [token]);
    return null;
  }
  return s;
}

async function deleteAnalystSession(token) {
  await pool.query(`DELETE FROM analyst_sessions WHERE token=$1`, [token]);
}

async function listAnalysts(tenantId) {
  const r = await pool.query(
    `SELECT id, email, name, role, disabled, created_at FROM analysts
     WHERE tenant_id=$1 ORDER BY created_at`, [tenantId]);
  return r.rows;
}

async function updateAnalyst(tenantId, id, { role, disabled }) {
  if (role !== undefined && !ROLES.includes(role)) {
    return { error: `role must be one of: ${ROLES.join(', ')}` };
  }
  const r = await pool.query(
    `UPDATE analysts SET
       role = COALESCE($3, role),
       disabled = COALESCE($4, disabled)
     WHERE tenant_id=$1 AND id=$2
     RETURNING id, email, name, role, disabled`,
    [tenantId, id, role ?? null, disabled ?? null]);
  if (!r.rows[0]) return null;
  if (disabled === true) {
    await pool.query(`DELETE FROM analyst_sessions WHERE analyst_id=$1`, [id]);
  }
  return r.rows[0];
}

// ---------- ingest ----------

/** Persist one verified SDK batch atomically. events: parsed envelope objects. */
async function recordBatch(tenantId, batchInstallId, events) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Group by session to maintain sessions/users/devices incrementally.
    const bySession = new Map();
    for (const ev of events) {
      if (!ev.sessionId) continue;
      if (!bySession.has(ev.sessionId)) bySession.set(ev.sessionId, []);
      bySession.get(ev.sessionId).push(ev);
    }

    for (const [sessionId, evs] of bySession) {
      const tss = evs.map(e => e.ts || Date.now());
      const first = new Date(Math.min(...tss));
      const last = new Date(Math.max(...tss));
      const installId = evs.find(e => e.installId)?.installId || batchInstallId || null;
      const userRef = evs.find(e => e.userRef)?.userRef || null;
      const fingerprint = evs.find(e => e.type === 'PASSIVE_DEVICE_FINGERPRINT')?.payload || null;
      const simChanged = evs.some(e =>
        e.type === 'PASSIVE_SIM_TELEMETRY' && e.payload?.simChangedSinceLastSession === true);

      if (installId) {
        await client.query(
          `INSERT INTO devices (tenant_id, install_id, first_seen, last_seen, fingerprint)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (tenant_id, install_id) DO UPDATE SET
             last_seen = GREATEST(devices.last_seen, EXCLUDED.last_seen),
             fingerprint = COALESCE(EXCLUDED.fingerprint, devices.fingerprint)`,
          [tenantId, installId, first, last, fingerprint]);
      }

      const sess = await client.query(
        `INSERT INTO sessions (tenant_id, session_id, install_id, user_ref,
                               started_at, last_event_at, event_count, sim_changed)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (tenant_id, session_id) DO UPDATE SET
           last_event_at = GREATEST(sessions.last_event_at, EXCLUDED.last_event_at),
           started_at = LEAST(sessions.started_at, EXCLUDED.started_at),
           event_count = sessions.event_count + EXCLUDED.event_count,
           user_ref = COALESCE(sessions.user_ref, EXCLUDED.user_ref),
           install_id = COALESCE(sessions.install_id, EXCLUDED.install_id),
           sim_changed = sessions.sim_changed OR EXCLUDED.sim_changed
         RETURNING (xmax = 0) AS inserted`,
        [tenantId, sessionId, installId, userRef, first, last, evs.length, simChanged]);
      const newSession = sess.rows[0].inserted;

      if (userRef) {
        await client.query(
          `INSERT INTO app_users (tenant_id, user_ref, first_seen, last_seen, session_count)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (tenant_id, user_ref) DO UPDATE SET
             last_seen = GREATEST(app_users.last_seen, EXCLUDED.last_seen),
             session_count = app_users.session_count + EXCLUDED.session_count`,
          [tenantId, userRef, first, last, newSession ? 1 : 0]);
        if (installId) {
          await client.query(
            `INSERT INTO user_devices (tenant_id, user_ref, install_id,
                                       first_seen, last_seen, session_count)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (tenant_id, user_ref, install_id) DO UPDATE SET
               last_seen = GREATEST(user_devices.last_seen, EXCLUDED.last_seen),
               session_count = user_devices.session_count + EXCLUDED.session_count`,
            [tenantId, userRef, installId, first, last, newSession ? 1 : 0]);
        }
      }
    }

    for (const ev of events) {
      await client.query(
        `INSERT INTO events (tenant_id, session_id, install_id, user_ref,
                             type, ts, call_signals, payload)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [tenantId, ev.sessionId || '', ev.installId || batchInstallId || null,
         ev.userRef || null, ev.type || 'UNKNOWN',
         new Date(ev.ts || Date.now()),
         ev.callSignals || null, ev.payload || null]);
    }

    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

// ---------- bank transaction feed ----------

/**
 * Idempotently persist a feed batch (UNIQUE txn_ref absorbs replays).
 * Returns how many were new and which accounts gained an OUT movement —
 * those are the ones worth re-checking for mule velocity.
 */
async function recordBankTxns(tenantId, txns) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    let inserted = 0;
    const outAccounts = new Set();
    for (const t of txns) {
      const r = await client.query(
        `INSERT INTO bank_txns (tenant_id, txn_ref, account_ref, user_ref,
                                direction, amount, currency, counterparty_ref, channel, ts)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         ON CONFLICT (tenant_id, txn_ref) DO NOTHING`,
        [tenantId, t.txnRef, t.accountRef, t.userRef || null, t.direction,
         t.amount, t.currency || null, t.counterpartyRef || null,
         t.channel || null, new Date(t.ts || Date.now())]);
      if (r.rowCount) {
        inserted++;
        if (t.direction === 'OUT') outAccounts.add(t.accountRef);
      }
    }
    await client.query('COMMIT');
    return { inserted, outAccounts: [...outAccounts] };
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

/** Ledger picture of one account for the mule-velocity detector. */
async function getAccountFlow(tenantId, accountRef) {
  const [flow, prior, flagged] = await Promise.all([
    pool.query(
      `SELECT
         coalesce(sum(amount) FILTER (WHERE direction='IN'
                  AND ts > now() - interval '72 hours'), 0)  AS in72,
         max(ts) FILTER (WHERE direction='IN'
                  AND ts > now() - interval '72 hours')      AS last_in,
         coalesce(sum(amount) FILTER (WHERE direction='OUT'
                  AND ts > now() - interval '24 hours'), 0)  AS out24,
         count(DISTINCT counterparty_ref) FILTER (WHERE direction='OUT'
                  AND ts > now() - interval '24 hours')      AS fan
       FROM bank_txns WHERE tenant_id=$1 AND account_ref=$2`,
      [tenantId, accountRef]).then(r => r.rows[0]),
    pool.query(
      `SELECT count(*)::int AS n FROM bank_txns
       WHERE tenant_id=$1 AND account_ref=$2
         AND ts < now() - interval '72 hours'
         AND ts > now() - interval '90 days'`,
      [tenantId, accountRef]).then(r => r.rows[0].n),
    pool.query(
      `SELECT count(*)::int AS n FROM bank_txns t
       JOIN alerts a ON a.tenant_id = t.tenant_id
                    AND a.account_ref = t.counterparty_ref
                    AND a.state = 'Open'
       WHERE t.tenant_id=$1 AND t.account_ref=$2
         AND t.ts > now() - interval '72 hours'`,
      [tenantId, accountRef]).then(r => r.rows[0].n),
  ]);
  return {
    in72: Number(flow.in72), lastInAt: flow.last_in,
    out24: Number(flow.out24), fanOut24: Number(flow.fan),
    priorActivity90d: prior, flaggedCounterparties: flagged,
  };
}

/**
 * 24h activity profile of one account for the agent-commission detector.
 * smallThreshold: amounts at or below it count as commission-tier-sized.
 */
async function getAgentActivity(tenantId, accountRef, smallThreshold = 10000) {
  const [topCp, totals, topAmount] = await Promise.all([
    pool.query(
      `SELECT counterparty_ref, count(*)::int AS n, sum(amount) AS total
       FROM bank_txns
       WHERE tenant_id=$1 AND account_ref=$2
         AND ts > now() - interval '24 hours' AND amount <= $3
         AND counterparty_ref IS NOT NULL
       GROUP BY counterparty_ref ORDER BY n DESC LIMIT 1`,
      [tenantId, accountRef, smallThreshold]).then(r => r.rows[0] || null),
    pool.query(
      `SELECT count(*)::int AS total,
              count(*) FILTER (WHERE amount <= $3)::int AS small
       FROM bank_txns
       WHERE tenant_id=$1 AND account_ref=$2
         AND ts > now() - interval '24 hours'`,
      [tenantId, accountRef, smallThreshold]).then(r => r.rows[0]),
    pool.query(
      `SELECT count(*)::int AS n FROM bank_txns
       WHERE tenant_id=$1 AND account_ref=$2
         AND ts > now() - interval '24 hours'
       GROUP BY amount ORDER BY n DESC LIMIT 1`,
      [tenantId, accountRef]).then(r => r.rows[0]?.n || 0),
  ]);
  return {
    topCpRef: topCp?.counterparty_ref || null,
    topCpCount: topCp ? Number(topCp.n) : 0,
    topCpSum: topCp ? Number(topCp.total) : 0,
    total24: Number(totals.total),
    smallCount: Number(totals.small),
    topAmountShare: totals.total > 0 ? topAmount / Number(totals.total) : 0,
  };
}

/** Raise an alert directly (feed-originated: no session, no /v1/score call). */
async function raiseAlert(tenantId, a) {
  const seq = await pool.query("SELECT 'ALT-' || nextval('alert_seq') AS id");
  const id = seq.rows[0].id;
  await pool.query(
    `INSERT INTO alerts (id, tenant_id, session_id, account_ref, user_ref,
                         score, threat_type, signal, state, txn, signals)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'Open', $9, $10)`,
    [id, tenantId, a.sessionId || null, a.accountRef || null, a.userRef || null,
     a.score, a.threatType || null, a.signal, a.txn || null,
     JSON.stringify(a.signals || [])]);
  return id;
}

/** Dedupe guard: one open mule alert per account per 24h. */
async function hasRecentOpenAlert(tenantId, accountRef, threatType) {
  const r = await pool.query(
    `SELECT 1 FROM alerts
     WHERE tenant_id=$1 AND account_ref=$2 AND threat_type=$3
       AND state='Open' AND created_at > now() - interval '24 hours' LIMIT 1`,
    [tenantId, accountRef, threatType]);
  return r.rowCount > 0;
}

async function listAccountTxns(tenantId, accountRef, limit = 50) {
  const r = await pool.query(
    `SELECT txn_ref, account_ref, user_ref, direction, amount, currency,
            counterparty_ref, channel, ts
     FROM bank_txns WHERE tenant_id=$1 AND account_ref=$2
     ORDER BY ts DESC LIMIT $3`,
    [tenantId, accountRef, Math.min(limit, 200)]);
  return r.rows;
}

// ---------- scoring context ----------

/**
 * Everything the scoring engine needs about a session and its user's
 * history, gathered in parallel. Pure read; scoring.js stays I/O-free.
 */
async function getScoringContext(tenantId, sessionId, userRef, installId) {
  const [session, sessionEvents] = await Promise.all([
    pool.query(`SELECT * FROM sessions WHERE tenant_id=$1 AND session_id=$2`,
               [tenantId, sessionId]).then(r => r.rows[0] || null),
    pool.query(`SELECT type, ts, call_signals, payload FROM events
                WHERE tenant_id=$1 AND session_id=$2 ORDER BY ts LIMIT 1000`,
               [tenantId, sessionId]).then(r => r.rows),
  ]);

  const ctx = { userRef: userRef || null, session, sessionEvents,
                knownDevice: null, prevSessionAt: null,
                baselineStrokes: [], baselineKeys: [],
                historyGeohashes: [], amountHistory: [],
                bankFlow: null };
  if (!userRef) return ctx;

  const startedAt = session ? session.started_at : new Date();
  const [device, prev, strokes, keys, geo, amounts, bankFlow] = await Promise.all([
    installId
      ? pool.query(`SELECT first_seen, last_seen, session_count FROM user_devices
                    WHERE tenant_id=$1 AND user_ref=$2 AND install_id=$3`,
                   [tenantId, userRef, installId]).then(r => r.rows[0] || null)
      : Promise.resolve(null),
    pool.query(`SELECT max(last_event_at) AS at FROM sessions
                WHERE tenant_id=$1 AND user_ref=$2 AND session_id <> $3
                  AND started_at < $4`,
               [tenantId, userRef, sessionId, startedAt]).then(r => r.rows[0].at),
    // Passive events early in a session predate login, so they carry no
    // user_ref — resolve history through the user's *sessions* instead.
    pool.query(`SELECT payload FROM events
                WHERE tenant_id=$1 AND session_id <> $3
                  AND type='PASSIVE_TOUCH_STROKES'
                  AND session_id IN (SELECT session_id FROM sessions
                                     WHERE tenant_id=$1 AND user_ref=$2)
                ORDER BY ts DESC LIMIT 50`,
               [tenantId, userRef, sessionId]).then(r => r.rows),
    pool.query(`SELECT payload FROM events
                WHERE tenant_id=$1 AND session_id <> $3
                  AND type='PASSIVE_KEYSTROKES'
                  AND session_id IN (SELECT session_id FROM sessions
                                     WHERE tenant_id=$1 AND user_ref=$2)
                ORDER BY ts DESC LIMIT 50`,
               [tenantId, userRef, sessionId]).then(r => r.rows),
    pool.query(`SELECT DISTINCT payload->>'geohash' AS g FROM events
                WHERE tenant_id=$1 AND session_id <> $3
                  AND type='PASSIVE_LOCATION_COARSE' AND payload ? 'geohash'
                  AND session_id IN (SELECT session_id FROM sessions
                                     WHERE tenant_id=$1 AND user_ref=$2)`,
               [tenantId, userRef, sessionId]).then(r => r.rows),
    pool.query(`SELECT (txn->>'amount')::numeric AS a FROM decisions
                WHERE tenant_id=$1 AND user_ref=$2 AND decision='ALLOW'
                  AND txn ? 'amount' AND created_at > now() - interval '180 days'
                ORDER BY created_at DESC LIMIT 50`,
               [tenantId, userRef]).then(r => r.rows),
    pool.query(`SELECT
                  coalesce(sum(amount) FILTER (WHERE direction='IN'
                           AND ts > now() - interval '72 hours'), 0) AS in72,
                  max(ts) FILTER (WHERE direction='IN'
                           AND ts > now() - interval '72 hours')     AS last_in,
                  count(DISTINCT counterparty_ref) FILTER (WHERE direction='OUT'
                           AND ts > now() - interval '24 hours')     AS fan
                FROM bank_txns WHERE tenant_id=$1 AND user_ref=$2`,
               [tenantId, userRef]).then(r => r.rows[0]),
  ]);

  ctx.knownDevice = device;
  ctx.prevSessionAt = prev;
  ctx.baselineStrokes = strokes.flatMap(r => r.payload?.strokes || []);
  ctx.baselineKeys = keys.flatMap(r => r.payload?.keys || []);
  ctx.historyGeohashes = geo.map(r => r.g).filter(Boolean);
  ctx.amountHistory = amounts.map(r => Number(r.a)).filter(Number.isFinite);
  ctx.bankFlow = { in72: Number(bankFlow.in72), lastInAt: bankFlow.last_in,
                   fanOut24: Number(bankFlow.fan) };
  return ctx;
}

// ---------- decisions & alerts ----------

async function recordDecision(d) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    let alertId = null;
    if (d.decision === 'HOLD') {
      const seq = await client.query("SELECT 'ALT-' || nextval('alert_seq') AS id");
      alertId = seq.rows[0].id;
      await client.query(
        `INSERT INTO alerts (id, tenant_id, session_id, install_id, user_ref,
                             score, threat_type, signal, state, txn, signals)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'Open', $9, $10)`,
        [alertId, d.tenantId, d.sessionId, d.installId, d.userRef,
         d.score, d.threatType || null, d.signal, d.txn,
         JSON.stringify(d.signals || [])]);
    }
    await client.query(
      `INSERT INTO decisions (tenant_id, session_id, user_ref, txn_ref, txn,
                              decision, score, reasons, signals, alert_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [d.tenantId, d.sessionId, d.userRef, d.txnRef || null, d.txn,
       d.decision, d.score, JSON.stringify(d.reasons),
       JSON.stringify(d.signals || []), alertId]);
    await client.query('COMMIT');
    return alertId;
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

// ---------- console reads ----------

async function overview(tenantId) {
  const q = (sql, args) => pool.query(sql, args).then(r => r.rows[0]);
  const [alerts, sessions, decisions, users] = await Promise.all([
    q(`SELECT count(*)::int AS open FROM alerts WHERE tenant_id=$1 AND state='Open'`, [tenantId]),
    q(`SELECT count(*)::int AS today FROM sessions
       WHERE tenant_id=$1 AND last_event_at > now() - interval '24 hours'`, [tenantId]),
    q(`SELECT count(*) FILTER (WHERE decision='HOLD')::int AS held,
              count(*) FILTER (WHERE decision='STEP_UP')::int AS step_up,
              count(*)::int AS total
       FROM decisions WHERE tenant_id=$1 AND created_at > now() - interval '30 days'`, [tenantId]),
    q(`SELECT count(*)::int AS total FROM app_users WHERE tenant_id=$1`, [tenantId]),
  ]);
  return {
    openAlerts: alerts.open,
    sessionsLast24h: sessions.today,
    decisionsLast30d: decisions,
    knownUsers: users.total,
  };
}

async function listAlerts(tenantId, { state, limit = 50 } = {}) {
  const args = [tenantId];
  let where = 'tenant_id = $1';
  if (state) { args.push(state); where += ` AND state = $${args.length}`; }
  args.push(Math.min(limit, 200));
  const r = await pool.query(
    `SELECT id, session_id, account_ref, user_ref, score, threat_type, signal, state,
            txn, disposition, case_id, created_at, updated_at
     FROM alerts WHERE ${where} ORDER BY created_at DESC LIMIT $${args.length}`, args);
  return r.rows;
}

async function getAlert(tenantId, id) {
  const a = await pool.query(
    `SELECT * FROM alerts WHERE tenant_id=$1 AND id=$2`, [tenantId, id]);
  if (!a.rows[0]) return null;
  const alert = a.rows[0];
  const [timeline, device, history, bankTxns, actions] = await Promise.all([
    alert.session_id
      ? pool.query(
          `SELECT type, ts, call_signals, payload FROM events
           WHERE tenant_id=$1 AND session_id=$2 ORDER BY ts LIMIT 500`,
          [tenantId, alert.session_id])
      : Promise.resolve({ rows: [] }),
    alert.install_id
      ? pool.query(`SELECT install_id, first_seen, last_seen, fingerprint
                    FROM devices WHERE tenant_id=$1 AND install_id=$2`,
                   [tenantId, alert.install_id])
      : Promise.resolve({ rows: [] }),
    alert.user_ref
      ? pool.query(`SELECT id, score, state, signal, created_at FROM alerts
                    WHERE tenant_id=$1 AND user_ref=$2 AND id <> $3
                    ORDER BY created_at DESC LIMIT 10`,
                   [tenantId, alert.user_ref, id])
      : Promise.resolve({ rows: [] }),
    alert.account_ref
      ? listAccountTxns(tenantId, alert.account_ref, 20)
      : Promise.resolve([]),
    pool.query(`SELECT id, kind, target, note, webhook_status, device_status,
                       created_at FROM actions
                WHERE tenant_id=$1 AND alert_id=$2 ORDER BY created_at`,
               [tenantId, id]),
  ]);
  return { ...alert, timeline: timeline.rows, device: device.rows[0] || null,
           priorAlerts: history.rows, bankTxns, actions: actions.rows };
}

async function updateAlert(tenantId, id, { state, disposition }) {
  const r = await pool.query(
    `UPDATE alerts SET
       state = COALESCE($3, state),
       disposition = COALESCE($4, disposition),
       updated_at = now()
     WHERE tenant_id=$1 AND id=$2 RETURNING *`,
    [tenantId, id, state || null, disposition || null]);
  return r.rows[0] || null;
}

// ---------- actions (session kill / payment release) ----------

/**
 * Create an analyst action against an alert and apply its effect to the
 * alert row (txn decision / state). Delivery legs are updated separately
 * as they complete. Returns the action row, or null if the alert doesn't
 * exist, or {error} when the alert can't support the action.
 */
async function createAction(tenantId, alertId, { kind, note, requestedBy }) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const a = await client.query(
      `SELECT * FROM alerts WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, [tenantId, alertId]);
    if (!a.rows[0]) { await client.query('ROLLBACK'); return null; }
    const alert = a.rows[0];

    let target, deviceLeg = false;
    if (kind === 'RELEASE_PAYMENT' || kind === 'BLOCK_PAYMENT') {
      if (!alert.txn?.txnRef) {
        await client.query('ROLLBACK');
        return { error: 'alert has no held payment (txn.txnRef missing)' };
      }
      target = { txnRef: alert.txn.txnRef, amount: alert.txn.amount ?? null };
    } else if (kind === 'TERMINATE_SESSION') {
      if (!alert.session_id) {
        await client.query('ROLLBACK');
        return { error: 'alert has no session to terminate' };
      }
      target = { sessionId: alert.session_id };
      deviceLeg = true;
    } else {
      await client.query('ROLLBACK');
      return { error: 'unknown action kind' };
    }

    const seq = await client.query("SELECT 'ACT-' || nextval('action_seq') AS id");
    const id = seq.rows[0].id;
    await client.query(
      `INSERT INTO actions (id, tenant_id, alert_id, kind, target, note,
                            requested_by, device_status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [id, tenantId, alertId, kind, target, note || null,
       requestedBy || null, deviceLeg ? 'pending' : 'n/a']);

    // Apply the analyst decision to the alert itself.
    const newTxn = alert.txn ? { ...alert.txn } : null;
    let newState = alert.state;
    if (kind === 'RELEASE_PAYMENT') { newTxn.decision = 'Released'; newState = 'Resolved'; }
    if (kind === 'BLOCK_PAYMENT') { newTxn.decision = 'Blocked'; newState = 'Resolved'; }
    if (kind === 'TERMINATE_SESSION') newState = 'Contained';
    await client.query(
      `UPDATE alerts SET txn = COALESCE($3, txn), state = $4, updated_at = now()
       WHERE tenant_id=$1 AND id=$2`,
      [tenantId, alertId, newTxn, newState]);

    if (alert.case_id) {
      await client.query(
        `INSERT INTO case_events (case_id, event) VALUES ($1, $2)`,
        [alert.case_id, `${kind.replace(/_/g, ' ').toLowerCase()} (${id})` +
                        (note ? ` — ${note}` : '')]);
    }

    await client.query('COMMIT');
    const r = await pool.query(`SELECT * FROM actions WHERE id=$1`, [id]);
    return r.rows[0];
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

async function markWebhookResult(actionId, ok, error) {
  await pool.query(
    `UPDATE actions SET
       webhook_status = $2,
       webhook_attempts = webhook_attempts + 1,
       webhook_delivered_at = CASE WHEN $2 = 'delivered' THEN now() END,
       last_error = $3
     WHERE id = $1`,
    [actionId, ok ? 'delivered' : 'failed', error || null]);
}

/** Terminate commands waiting for any of these sessions' devices. */
async function pendingDeviceCommands(tenantId, sessionIds) {
  if (!sessionIds.length) return [];
  const r = await pool.query(
    `SELECT id, kind, target FROM actions
     WHERE tenant_id=$1 AND device_status='pending'
       AND target->>'sessionId' = ANY($2)`,
    [tenantId, sessionIds]);
  return r.rows;
}

async function markDeviceDelivered(actionIds) {
  if (!actionIds.length) return;
  await pool.query(
    `UPDATE actions SET device_status='delivered', device_delivered_at=now()
     WHERE id = ANY($1)`, [actionIds]);
}

async function listActions(tenantId, { limit = 50 } = {}) {
  const r = await pool.query(
    `SELECT * FROM actions WHERE tenant_id=$1
     ORDER BY created_at DESC LIMIT $2`, [tenantId, Math.min(limit, 200)]);
  return r.rows;
}

// ---------- cases ----------

async function createCase(tenantId, alertId, { assignee, summary, actor } = {}) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const a = await client.query(
      `SELECT * FROM alerts WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, [tenantId, alertId]);
    if (!a.rows[0]) { await client.query('ROLLBACK'); return null; }
    const alert = a.rows[0];
    const seq = await client.query("SELECT 'C-' || nextval('case_seq') AS id");
    const caseId = seq.rows[0].id;
    await client.query(
      `INSERT INTO cases (id, tenant_id, user_ref, threat_type, assignee, summary)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [caseId, tenantId, alert.user_ref, alert.threat_type,
       assignee || 'Unassigned', summary || alert.signal]);
    await client.query(
      `INSERT INTO case_events (case_id, event) VALUES ($1, $2)`,
      [caseId, `Case opened from alert ${alertId}` + (actor ? ` by ${actor}` : '')]);
    await client.query(
      `UPDATE alerts SET case_id=$3, updated_at=now() WHERE tenant_id=$1 AND id=$2`,
      [tenantId, alertId, caseId]);
    await client.query('COMMIT');
    return caseId;
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

async function listCases(tenantId, { status, limit = 50 } = {}) {
  const args = [tenantId];
  let where = 'tenant_id = $1';
  if (status) { args.push(status); where += ` AND status = $${args.length}`; }
  args.push(Math.min(limit, 200));
  const r = await pool.query(
    `SELECT * FROM cases WHERE ${where} ORDER BY created_at DESC LIMIT $${args.length}`, args);
  return r.rows;
}

async function getCase(tenantId, id) {
  const c = await pool.query(`SELECT * FROM cases WHERE tenant_id=$1 AND id=$2`, [tenantId, id]);
  if (!c.rows[0]) return null;
  const [timeline, alerts] = await Promise.all([
    pool.query(`SELECT event, at FROM case_events WHERE case_id=$1 ORDER BY at`, [id]),
    pool.query(`SELECT id, score, state, signal FROM alerts
                WHERE tenant_id=$1 AND case_id=$2`, [tenantId, id]),
  ]);
  return { ...c.rows[0], timeline: timeline.rows, alerts: alerts.rows };
}

async function updateCase(tenantId, id, { status, assignee, note, actor }) {
  const r = await pool.query(
    `UPDATE cases SET
       status = COALESCE($3, status),
       assignee = COALESCE($4, assignee),
       updated_at = now()
     WHERE tenant_id=$1 AND id=$2 RETURNING *`,
    [tenantId, id, status || null, assignee || null]);
  if (!r.rows[0]) return null;
  const entries = [];
  if (status) entries.push(`Status changed to ${status}`);
  if (assignee) entries.push(`Assigned to ${assignee}`);
  if (note) entries.push(note);
  const suffix = actor ? ` — by ${actor}` : '';
  for (const e of entries) {
    await pool.query(`INSERT INTO case_events (case_id, event) VALUES ($1, $2)`,
      [id, e + suffix]);
  }
  return r.rows[0];
}

// ---------- profiles & sessions ----------

async function getUserProfile(tenantId, userRef) {
  const u = await pool.query(
    `SELECT * FROM app_users WHERE tenant_id=$1 AND user_ref=$2`, [tenantId, userRef]);
  if (!u.rows[0]) return null;
  const [devices, alerts, sessions] = await Promise.all([
    pool.query(`SELECT ud.install_id, ud.first_seen, ud.last_seen, ud.session_count,
                       d.fingerprint
                FROM user_devices ud
                LEFT JOIN devices d ON d.tenant_id=ud.tenant_id AND d.install_id=ud.install_id
                WHERE ud.tenant_id=$1 AND ud.user_ref=$2 ORDER BY ud.first_seen`,
               [tenantId, userRef]),
    pool.query(`SELECT id, score, state, signal, created_at FROM alerts
                WHERE tenant_id=$1 AND user_ref=$2 ORDER BY created_at DESC LIMIT 20`,
               [tenantId, userRef]),
    pool.query(`SELECT session_id, started_at, last_event_at, event_count, sim_changed
                FROM sessions WHERE tenant_id=$1 AND user_ref=$2
                ORDER BY started_at DESC LIMIT 20`, [tenantId, userRef]),
  ]);
  return { ...u.rows[0], devices: devices.rows, alerts: alerts.rows,
           recentSessions: sessions.rows };
}

async function getSessionEvents(tenantId, sessionId) {
  const r = await pool.query(
    `SELECT type, ts, install_id, user_ref, call_signals, payload FROM events
     WHERE tenant_id=$1 AND session_id=$2 ORDER BY ts LIMIT 1000`,
    [tenantId, sessionId]);
  return r.rows;
}

async function eventTypeCounts() {
  const r = await pool.query(
    `SELECT type, count(*)::int AS n FROM events GROUP BY type ORDER BY n DESC`);
  return Object.fromEntries(r.rows.map(x => [x.type, x.n]));
}

module.exports = {
  init, pool,
  seedAdmin, createAnalyst, verifyLogin, createAnalystSession,
  resolveAnalystToken, deleteAnalystSession, listAnalysts, updateAnalyst,
  recordBatch, recordDecision, getScoringContext,
  recordBankTxns, getAccountFlow, getAgentActivity,
  raiseAlert, hasRecentOpenAlert, listAccountTxns,
  createAction, markWebhookResult, pendingDeviceCommands, markDeviceDelivered, listActions,
  overview, listAlerts, getAlert, updateAlert,
  createCase, listCases, getCase, updateCase,
  getUserProfile, getSessionEvents, eventTypeCounts,
};
