// Data-access layer — the only file that speaks SQL. Mirrors the Node
// server's db.js query-for-query so both implementations share one
// Postgres schema and behave identically.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type IngestEvent struct {
	Type        string          `json:"type"`
	SessionID   string          `json:"sessionId"`
	InstallID   string          `json:"installId"`
	UserRef     string          `json:"userRef"`
	Ts          int64           `json:"ts"`
	CallSignals json.RawMessage `json:"callSignals"`
	Payload     json.RawMessage `json:"payload"`
}

func queryMaps(ctx context.Context, p *pgxpool.Pool, sql string, args ...any) ([]map[string]any, error) {
	rows, err := p.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToMap)
}

func queryMap(ctx context.Context, p *pgxpool.Pool, sql string, args ...any) (map[string]any, error) {
	ms, err := queryMaps(ctx, p, sql, args...)
	if err != nil || len(ms) == 0 {
		return nil, err
	}
	return ms[0], nil
}

// ---------- ingest ----------

func (s *Server) recordBatch(ctx context.Context, tenantID, batchInstallID string, events []IngestEvent) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	bySession := map[string][]IngestEvent{}
	order := []string{}
	for _, ev := range events {
		if ev.SessionID == "" {
			continue
		}
		if _, ok := bySession[ev.SessionID]; !ok {
			order = append(order, ev.SessionID)
		}
		bySession[ev.SessionID] = append(bySession[ev.SessionID], ev)
	}

	for _, sessionID := range order {
		evs := bySession[sessionID]
		minTs, maxTs := evs[0].Ts, evs[0].Ts
		installID, userRef := "", ""
		var fingerprint json.RawMessage
		simChanged := false
		for _, ev := range evs {
			if ev.Ts < minTs {
				minTs = ev.Ts
			}
			if ev.Ts > maxTs {
				maxTs = ev.Ts
			}
			if installID == "" && ev.InstallID != "" {
				installID = ev.InstallID
			}
			if userRef == "" && ev.UserRef != "" {
				userRef = ev.UserRef
			}
			if fingerprint == nil && ev.Type == "PASSIVE_DEVICE_FINGERPRINT" {
				fingerprint = ev.Payload
			}
			if ev.Type == "PASSIVE_SIM_TELEMETRY" {
				var p struct {
					SimChanged bool `json:"simChangedSinceLastSession"`
				}
				if json.Unmarshal(ev.Payload, &p) == nil && p.SimChanged {
					simChanged = true
				}
			}
		}
		if installID == "" {
			installID = batchInstallID
		}
		first, last := msToTime(minTs), msToTime(maxTs)

		if installID != "" {
			if _, err := tx.Exec(ctx,
				`INSERT INTO devices (tenant_id, install_id, first_seen, last_seen, fingerprint)
				 VALUES ($1, $2, $3, $4, $5)
				 ON CONFLICT (tenant_id, install_id) DO UPDATE SET
				   last_seen = GREATEST(devices.last_seen, EXCLUDED.last_seen),
				   fingerprint = COALESCE(EXCLUDED.fingerprint, devices.fingerprint)`,
				tenantID, installID, first, last, jsonArg(fingerprint)); err != nil {
				return err
			}
		}

		var inserted bool
		if err := tx.QueryRow(ctx,
			`INSERT INTO sessions (tenant_id, session_id, install_id, user_ref,
			                       started_at, last_event_at, event_count, sim_changed)
			 VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, ''), $5, $6, $7, $8)
			 ON CONFLICT (tenant_id, session_id) DO UPDATE SET
			   last_event_at = GREATEST(sessions.last_event_at, EXCLUDED.last_event_at),
			   started_at = LEAST(sessions.started_at, EXCLUDED.started_at),
			   event_count = sessions.event_count + EXCLUDED.event_count,
			   user_ref = COALESCE(sessions.user_ref, EXCLUDED.user_ref),
			   install_id = COALESCE(sessions.install_id, EXCLUDED.install_id),
			   sim_changed = sessions.sim_changed OR EXCLUDED.sim_changed
			 RETURNING (xmax = 0) AS inserted`,
			tenantID, sessionID, installID, userRef, first, last, len(evs), simChanged,
		).Scan(&inserted); err != nil {
			return err
		}

		if userRef != "" {
			inc := 0
			if inserted {
				inc = 1
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO app_users (tenant_id, user_ref, first_seen, last_seen, session_count)
				 VALUES ($1, $2, $3, $4, $5)
				 ON CONFLICT (tenant_id, user_ref) DO UPDATE SET
				   last_seen = GREATEST(app_users.last_seen, EXCLUDED.last_seen),
				   session_count = app_users.session_count + EXCLUDED.session_count`,
				tenantID, userRef, first, last, inc); err != nil {
				return err
			}
			if installID != "" {
				if _, err := tx.Exec(ctx,
					`INSERT INTO user_devices (tenant_id, user_ref, install_id,
					                           first_seen, last_seen, session_count)
					 VALUES ($1, $2, $3, $4, $5, $6)
					 ON CONFLICT (tenant_id, user_ref, install_id) DO UPDATE SET
					   last_seen = GREATEST(user_devices.last_seen, EXCLUDED.last_seen),
					   session_count = user_devices.session_count + EXCLUDED.session_count`,
					tenantID, userRef, installID, first, last, inc); err != nil {
					return err
				}
			}
		}
	}

	for _, ev := range events {
		typ := ev.Type
		if typ == "" {
			typ = "UNKNOWN"
		}
		installID := ev.InstallID
		if installID == "" {
			installID = batchInstallID
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO events (tenant_id, session_id, install_id, user_ref,
			                     type, ts, call_signals, payload)
			 VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, ''), $5, $6, $7, $8)`,
			tenantID, ev.SessionID, installID, ev.UserRef, typ,
			msToTime(ev.Ts), jsonArg(ev.CallSignals), jsonArg(ev.Payload)); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Server) pendingDeviceCommands(ctx context.Context, tenantID string, sessionIDs []string) ([]map[string]any, error) {
	if len(sessionIDs) == 0 {
		return []map[string]any{}, nil
	}
	return queryMaps(ctx, s.pool,
		`SELECT id, kind, target FROM actions
		 WHERE tenant_id=$1 AND device_status='pending'
		   AND target->>'sessionId' = ANY($2)`, tenantID, sessionIDs)
}

func (s *Server) markDeviceDelivered(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE actions SET device_status='delivered', device_delivered_at=now()
		 WHERE id = ANY($1)`, ids)
	return err
}

// ---------- scoring context ----------

func (s *Server) getScoringContext(ctx context.Context, tenantID, sessionID, userRef, installID string) (*ScoringCtx, error) {
	sc := &ScoringCtx{UserRef: userRef}

	var startedAt time.Time
	var simChanged bool
	err := s.pool.QueryRow(ctx,
		`SELECT started_at, sim_changed FROM sessions WHERE tenant_id=$1 AND session_id=$2`,
		tenantID, sessionID).Scan(&startedAt, &simChanged)
	haveSession := err == nil
	if haveSession {
		sc.SessionStart = &startedAt
		sc.SimChanged = simChanged
	} else if err != pgx.ErrNoRows {
		return nil, err
	}

	rows, err := s.pool.Query(ctx,
		`SELECT type, ts, call_signals, payload FROM events
		 WHERE tenant_id=$1 AND session_id=$2 ORDER BY ts LIMIT 1000`, tenantID, sessionID)
	if err != nil {
		return nil, err
	}
	sc.Events, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (EventRow, error) {
		var e EventRow
		err := row.Scan(&e.Type, &e.Ts, &e.CallSignals, &e.Payload)
		return e, err
	})
	if err != nil {
		return nil, err
	}
	if userRef == "" {
		return sc, nil
	}

	refTime := time.Now()
	if sc.SessionStart != nil {
		refTime = *sc.SessionStart
	}

	if installID != "" {
		var firstSeen time.Time
		err = s.pool.QueryRow(ctx,
			`SELECT first_seen FROM user_devices
			 WHERE tenant_id=$1 AND user_ref=$2 AND install_id=$3`,
			tenantID, userRef, installID).Scan(&firstSeen)
		if err == nil {
			sc.KnownDeviceFirstSeen = &firstSeen
		} else if err != pgx.ErrNoRows {
			return nil, err
		}
	}

	var prev *time.Time
	if err := s.pool.QueryRow(ctx,
		`SELECT max(last_event_at) FROM sessions
		 WHERE tenant_id=$1 AND user_ref=$2 AND session_id <> $3 AND started_at < $4`,
		tenantID, userRef, sessionID, refTime).Scan(&prev); err != nil {
		return nil, err
	}
	sc.PrevSessionAt = prev

	// Passive events early in a session predate login (no user_ref) —
	// resolve history through the user's sessions instead.
	strokeRows, err := queryMaps(ctx, s.pool,
		`SELECT payload FROM events
		 WHERE tenant_id=$1 AND session_id <> $3 AND type='PASSIVE_TOUCH_STROKES'
		   AND session_id IN (SELECT session_id FROM sessions
		                      WHERE tenant_id=$1 AND user_ref=$2)
		 ORDER BY ts DESC LIMIT 50`, tenantID, userRef, sessionID)
	if err != nil {
		return nil, err
	}
	for _, r := range strokeRows {
		raw, _ := json.Marshal(r["payload"])
		if p, ok := parsePayload[struct {
			Strokes []Stroke `json:"strokes"`
		}](raw); ok {
			sc.BaselineStrokes = append(sc.BaselineStrokes, p.Strokes...)
		}
	}

	// Web mouse baseline (same shape as touch strokes) for MOUSE_ANOMALY.
	mouseRows, err := queryMaps(ctx, s.pool,
		`SELECT payload FROM events
		 WHERE tenant_id=$1 AND session_id <> $3 AND type='PASSIVE_MOUSE_STROKES'
		   AND session_id IN (SELECT session_id FROM sessions
		                      WHERE tenant_id=$1 AND user_ref=$2)
		 ORDER BY ts DESC LIMIT 50`, tenantID, userRef, sessionID)
	if err != nil {
		return nil, err
	}
	for _, r := range mouseRows {
		raw, _ := json.Marshal(r["payload"])
		if p, ok := parsePayload[struct {
			Strokes []Stroke `json:"strokes"`
		}](raw); ok {
			sc.BaselineMouse = append(sc.BaselineMouse, p.Strokes...)
		}
	}

	keyRows, err := queryMaps(ctx, s.pool,
		`SELECT payload FROM events
		 WHERE tenant_id=$1 AND session_id <> $3 AND type='PASSIVE_KEYSTROKES'
		   AND session_id IN (SELECT session_id FROM sessions
		                      WHERE tenant_id=$1 AND user_ref=$2)
		 ORDER BY ts DESC LIMIT 50`, tenantID, userRef, sessionID)
	if err != nil {
		return nil, err
	}
	for _, r := range keyRows {
		raw, _ := json.Marshal(r["payload"])
		if p, ok := parsePayload[keystrokePayload](raw); ok {
			sc.BaselineKeys = append(sc.BaselineKeys, p.Keys...)
		}
	}

	geoRows, err := s.pool.Query(ctx,
		`SELECT DISTINCT payload->>'geohash' FROM events
		 WHERE tenant_id=$1 AND session_id <> $3
		   AND type='PASSIVE_LOCATION_COARSE' AND payload ? 'geohash'
		   AND session_id IN (SELECT session_id FROM sessions
		                      WHERE tenant_id=$1 AND user_ref=$2)`,
		tenantID, userRef, sessionID)
	if err != nil {
		return nil, err
	}
	sc.HistoryGeohashes, err = pgx.CollectRows(geoRows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}

	// Most recent prior fix (geohash + when) → IMPOSSIBLE_TRAVEL velocity.
	var lastGeo *string
	var lastGeoAt *time.Time
	if err := s.pool.QueryRow(ctx,
		`SELECT payload->>'geohash', ts FROM events
		 WHERE tenant_id=$1 AND session_id <> $3
		   AND type='PASSIVE_LOCATION_COARSE' AND payload ? 'geohash'
		   AND session_id IN (SELECT session_id FROM sessions
		                      WHERE tenant_id=$1 AND user_ref=$2)
		 ORDER BY ts DESC LIMIT 1`,
		tenantID, userRef, sessionID).Scan(&lastGeo, &lastGeoAt); err == nil {
		if lastGeo != nil {
			sc.LastFixGeohash = *lastGeo
		}
		sc.LastFixAt = lastGeoAt
	} else if err != pgx.ErrNoRows {
		return nil, err
	}

	amtRows, err := s.pool.Query(ctx,
		`SELECT (txn->>'amount')::float8 FROM decisions
		 WHERE tenant_id=$1 AND user_ref=$2 AND decision='ALLOW'
		   AND txn ? 'amount' AND created_at > now() - interval '180 days'
		 ORDER BY created_at DESC LIMIT 50`, tenantID, userRef)
	if err != nil {
		return nil, err
	}
	sc.AmountHistory, err = pgx.CollectRows(amtRows, pgx.RowTo[float64])
	if err != nil {
		return nil, err
	}

	var in72 float64
	var lastIn *time.Time
	var fan int
	if err := s.pool.QueryRow(ctx,
		`SELECT coalesce(sum(amount) FILTER (WHERE direction='IN'
		          AND ts > now() - interval '72 hours'), 0)::float8,
		        max(ts) FILTER (WHERE direction='IN'
		          AND ts > now() - interval '72 hours'),
		        count(DISTINCT counterparty_ref) FILTER (WHERE direction='OUT'
		          AND ts > now() - interval '24 hours')::int
		 FROM bank_txns WHERE tenant_id=$1 AND user_ref=$2`,
		tenantID, userRef).Scan(&in72, &lastIn, &fan); err != nil {
		return nil, err
	}
	sc.HasBankFlow = true
	sc.FlowIn72, sc.FlowLastInAt, sc.FlowFan = in72, lastIn, fan
	return sc, nil
}

// ---------- decisions & alerts ----------

type DecisionRecord struct {
	TenantID, SessionID, InstallID, UserRef string
	TxnRef                                  string
	Txn                                     json.RawMessage
	Decision                                string
	Result                                  ScoreResult
}

func (s *Server) recordDecision(ctx context.Context, d DecisionRecord) (string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	signalsJSON, _ := json.Marshal(d.Result.Signals)
	reasonsJSON, _ := json.Marshal(d.Result.Reasons)
	alertID := ""
	if d.Decision == "HOLD" {
		if err := tx.QueryRow(ctx,
			`SELECT 'ALT-' || nextval('alert_seq')`).Scan(&alertID); err != nil {
			return "", err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO alerts (id, tenant_id, session_id, install_id, user_ref,
			                     score, threat_type, signal, state, txn, signals)
			 VALUES ($1, $2, $3, NULLIF($4, ''), NULLIF($5, ''),
			         $6, NULLIF($7, ''), $8, 'Open', $9, $10)`,
			alertID, d.TenantID, d.SessionID, d.InstallID, d.UserRef,
			d.Result.Score, d.Result.ThreatType, d.Result.Summary,
			jsonArg(d.Txn), string(signalsJSON)); err != nil {
			return "", err
		}
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO decisions (tenant_id, session_id, user_ref, txn_ref, txn,
		                        decision, score, reasons, signals, threat_type, alert_id)
		 VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, ''), $5, $6, $7, $8, $9,
		         NULLIF($10, ''), NULLIF($11, ''))`,
		d.TenantID, d.SessionID, d.UserRef, d.TxnRef, jsonArg(d.Txn),
		d.Decision, d.Result.Score, string(reasonsJSON), string(signalsJSON),
		d.Result.ThreatType, alertID); err != nil {
		// A concurrent retry beat us to the (tenant, session, txnRef) slot;
		// the rollback also discards our duplicate alert. Caller replays.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return "", ErrDuplicateDecision
		}
		return "", err
	}
	return alertID, tx.Commit(ctx)
}

// ErrDuplicateDecision: this (tenant, session, txnRef) was already decided.
var ErrDuplicateDecision = errors.New("duplicate decision")

// getDecisionReplay returns the stored decision for an idempotent /v1/score
// replay, or nil when this txnRef hasn't been decided in this session.
func (s *Server) getDecisionReplay(ctx context.Context, tenantID, sessionID, txnRef string) (map[string]any, error) {
	rows, err := queryMaps(ctx, s.pool,
		`SELECT decision, score, reasons, signals, threat_type, alert_id
		 FROM decisions
		 WHERE tenant_id=$1 AND session_id=$2 AND txn_ref=$3
		 ORDER BY id LIMIT 1`, tenantID, sessionID, txnRef)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return rows[0], nil
}

// ---------- bank transaction feed ----------

type BankTxn struct {
	TxnRef          string  `json:"txnRef"`
	AccountRef      string  `json:"accountRef"`
	UserRef         string  `json:"userRef"`
	Direction       string  `json:"direction"`
	Amount          float64 `json:"amount"`
	Currency        string  `json:"currency"`
	CounterpartyRef string  `json:"counterpartyRef"`
	Channel         string  `json:"channel"`
	Ts              int64   `json:"ts"`
}

func (s *Server) recordBankTxns(ctx context.Context, tenantID string, txns []BankTxn) (int, []string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, nil, err
	}
	defer tx.Rollback(ctx)
	inserted := 0
	outSeen := map[string]bool{}
	outAccounts := []string{}
	for _, t := range txns {
		tag, err := tx.Exec(ctx,
			`INSERT INTO bank_txns (tenant_id, txn_ref, account_ref, user_ref,
			                        direction, amount, currency, counterparty_ref, channel, ts)
			 VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6, NULLIF($7, ''),
			         NULLIF($8, ''), NULLIF($9, ''), $10)
			 ON CONFLICT (tenant_id, txn_ref) DO NOTHING`,
			tenantID, t.TxnRef, t.AccountRef, t.UserRef, t.Direction, t.Amount,
			t.Currency, t.CounterpartyRef, t.Channel, msToTime(t.Ts))
		if err != nil {
			return 0, nil, err
		}
		if tag.RowsAffected() > 0 {
			inserted++
			if t.Direction == "OUT" && !outSeen[t.AccountRef] {
				outSeen[t.AccountRef] = true
				outAccounts = append(outAccounts, t.AccountRef)
			}
		}
	}
	return inserted, outAccounts, tx.Commit(ctx)
}

func (s *Server) getAccountFlow(ctx context.Context, tenantID, accountRef string) (AccountFlow, error) {
	var f AccountFlow
	if err := s.pool.QueryRow(ctx,
		`SELECT coalesce(sum(amount) FILTER (WHERE direction='IN'
		          AND ts > now() - interval '72 hours'), 0)::float8,
		        max(ts) FILTER (WHERE direction='IN' AND ts > now() - interval '72 hours'),
		        coalesce(sum(amount) FILTER (WHERE direction='OUT'
		          AND ts > now() - interval '24 hours'), 0)::float8,
		        count(DISTINCT counterparty_ref) FILTER (WHERE direction='OUT'
		          AND ts > now() - interval '24 hours')::int
		 FROM bank_txns WHERE tenant_id=$1 AND account_ref=$2`,
		tenantID, accountRef).Scan(&f.In72, &f.LastInAt, &f.Out24, &f.FanOut24); err != nil {
		return f, err
	}
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*)::int FROM bank_txns
		 WHERE tenant_id=$1 AND account_ref=$2
		   AND ts < now() - interval '72 hours' AND ts > now() - interval '90 days'`,
		tenantID, accountRef).Scan(&f.PriorActivity90d); err != nil {
		return f, err
	}
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*)::int FROM bank_txns t
		 JOIN alerts a ON a.tenant_id = t.tenant_id
		              AND a.account_ref = t.counterparty_ref AND a.state = 'Open'
		 WHERE t.tenant_id=$1 AND t.account_ref=$2
		   AND t.ts > now() - interval '72 hours'`,
		tenantID, accountRef).Scan(&f.FlaggedCounterparties); err != nil {
		return f, err
	}
	return f, nil
}

func (s *Server) getAgentActivity(ctx context.Context, tenantID, accountRef string, smallThreshold float64) (AgentStats, error) {
	var st AgentStats
	var cpRef *string
	var cpN *int
	var cpSum *float64
	err := s.pool.QueryRow(ctx,
		`SELECT counterparty_ref, count(*)::int, sum(amount)::float8
		 FROM bank_txns
		 WHERE tenant_id=$1 AND account_ref=$2
		   AND ts > now() - interval '24 hours' AND amount <= $3
		   AND counterparty_ref IS NOT NULL
		 GROUP BY counterparty_ref ORDER BY count(*) DESC LIMIT 1`,
		tenantID, accountRef, smallThreshold).Scan(&cpRef, &cpN, &cpSum)
	if err == nil {
		st.TopCpRef, st.TopCpCount, st.TopCpSum = *cpRef, *cpN, *cpSum
	} else if err != pgx.ErrNoRows {
		return st, err
	}
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*)::int, count(*) FILTER (WHERE amount <= $3)::int
		 FROM bank_txns
		 WHERE tenant_id=$1 AND account_ref=$2 AND ts > now() - interval '24 hours'`,
		tenantID, accountRef, smallThreshold).Scan(&st.Total24, &st.SmallCount); err != nil {
		return st, err
	}
	var topAmount int
	err = s.pool.QueryRow(ctx,
		`SELECT count(*)::int FROM bank_txns
		 WHERE tenant_id=$1 AND account_ref=$2 AND ts > now() - interval '24 hours'
		 GROUP BY amount ORDER BY count(*) DESC LIMIT 1`,
		tenantID, accountRef).Scan(&topAmount)
	if err != nil && err != pgx.ErrNoRows {
		return st, err
	}
	if st.Total24 > 0 {
		st.TopAmountShare = float64(topAmount) / float64(st.Total24)
	}
	return st, nil
}

type AlertDraft struct {
	SessionID, AccountRef, UserRef string
	Score                          int
	ThreatType, Signal             string
	Signals                        []Signal
	Txn                            map[string]any
}

func (s *Server) raiseAlert(ctx context.Context, tenantID string, a AlertDraft) (string, error) {
	var id string
	if err := s.pool.QueryRow(ctx, `SELECT 'ALT-' || nextval('alert_seq')`).Scan(&id); err != nil {
		return "", err
	}
	signalsJSON, _ := json.Marshal(a.Signals)
	_, err := s.pool.Exec(ctx,
		`INSERT INTO alerts (id, tenant_id, session_id, account_ref, user_ref,
		                     score, threat_type, signal, state, txn, signals)
		 VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, ''), NULLIF($5, ''),
		         $6, NULLIF($7, ''), $8, 'Open', $9, $10)`,
		id, tenantID, a.SessionID, a.AccountRef, a.UserRef,
		a.Score, a.ThreatType, a.Signal, a.Txn, string(signalsJSON))
	return id, err
}

func (s *Server) hasRecentOpenAlert(ctx context.Context, tenantID, accountRef, threatType string) (bool, error) {
	var one int
	err := s.pool.QueryRow(ctx,
		`SELECT 1 FROM alerts
		 WHERE tenant_id=$1 AND account_ref=$2 AND threat_type=$3
		   AND state='Open' AND created_at > now() - interval '24 hours' LIMIT 1`,
		tenantID, accountRef, threatType).Scan(&one)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func (s *Server) listAccountTxns(ctx context.Context, tenantID, accountRef string, limit int) ([]map[string]any, error) {
	return queryMaps(ctx, s.pool,
		`SELECT txn_ref, account_ref, user_ref, direction, amount::float8 AS amount,
		        currency, counterparty_ref, channel, ts
		 FROM bank_txns WHERE tenant_id=$1 AND account_ref=$2
		 ORDER BY ts DESC LIMIT $3`, tenantID, accountRef, limit)
}
