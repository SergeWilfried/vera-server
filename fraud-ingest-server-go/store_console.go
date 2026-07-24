// Console-facing store: alerts, cases, profiles, actions, analyst auth.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/scrypt"
)

// ---------- overview / alerts ----------

func (s *Server) overview(ctx context.Context, tenantID string) (map[string]any, error) {
	out := map[string]any{}
	var open, sess24, users int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*)::int FROM alerts WHERE tenant_id=$1 AND state='Open'`,
		tenantID).Scan(&open); err != nil {
		return nil, err
	}
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*)::int FROM sessions
		 WHERE tenant_id=$1 AND last_event_at > now() - interval '24 hours'`,
		tenantID).Scan(&sess24); err != nil {
		return nil, err
	}
	var held, stepUp, total int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE decision='HOLD')::int,
		        count(*) FILTER (WHERE decision='STEP_UP')::int, count(*)::int
		 FROM decisions WHERE tenant_id=$1 AND created_at > now() - interval '30 days'`,
		tenantID).Scan(&held, &stepUp, &total); err != nil {
		return nil, err
	}
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*)::int FROM app_users WHERE tenant_id=$1`, tenantID).Scan(&users); err != nil {
		return nil, err
	}
	out["openAlerts"] = open
	out["sessionsLast24h"] = sess24
	out["decisionsLast30d"] = map[string]any{"held": held, "step_up": stepUp, "total": total}
	out["knownUsers"] = users
	return out, nil
}

// Detection counts per threat type over a window — powers the Detections page.
func (s *Server) detections(ctx context.Context, tenantID string, days int) ([]map[string]any, error) {
	return queryMaps(ctx, s.pool,
		`SELECT coalesce(threat_type, 'Unclassified') AS threat_type,
		        count(*)::int AS count,
		        count(*) FILTER (WHERE state='Open')::int AS open
		 FROM alerts
		 WHERE tenant_id=$1 AND created_at > now() - make_interval(days => $2)
		 GROUP BY coalesce(threat_type, 'Unclassified')
		 ORDER BY count DESC`, tenantID, days)
}

// detectionAnalytics is the richer view behind the Detections page: what the
// engine actually fired (signal frequency), the daily trend, decision
// outcomes, and the threat breakdown — over one window.
func (s *Server) detectionAnalytics(ctx context.Context, tenantID string, days int) (map[string]any, error) {
	byThreat, err := s.detections(ctx, tenantID, days)
	if err != nil {
		return nil, err
	}
	// Which scoring signals fired most, unpacking the signals jsonb array.
	bySignal, err := queryMaps(ctx, s.pool,
		`SELECT s->>'code' AS code,
		        max(s->>'label') AS label,
		        max((s->>'weight')::int) AS weight,
		        count(*)::int AS count
		 FROM decisions, jsonb_array_elements(signals) s
		 WHERE tenant_id=$1 AND created_at > now() - make_interval(days => $2)
		   AND jsonb_typeof(signals) = 'array'
		 GROUP BY s->>'code'
		 ORDER BY count DESC LIMIT 14`, tenantID, days)
	if err != nil {
		return nil, err
	}
	// Detections per day (alerts raised), for the trend.
	trend, err := queryMaps(ctx, s.pool,
		`SELECT to_char(date_trunc('day', created_at), 'YYYY-MM-DD') AS day,
		        count(*)::int AS count
		 FROM alerts
		 WHERE tenant_id=$1 AND created_at > now() - make_interval(days => $2)
		 GROUP BY 1 ORDER BY 1`, tenantID, days)
	if err != nil {
		return nil, err
	}
	var hold, stepUp, allow, total int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE decision='HOLD')::int,
		        count(*) FILTER (WHERE decision='STEP_UP')::int,
		        count(*) FILTER (WHERE decision='ALLOW')::int,
		        count(*)::int
		 FROM decisions WHERE tenant_id=$1 AND created_at > now() - make_interval(days => $2)`,
		tenantID, days).Scan(&hold, &stepUp, &allow, &total); err != nil {
		return nil, err
	}
	return map[string]any{
		"byThreat": byThreat,
		"bySignal": bySignal,
		"trend":    trend,
		"outcomes": map[string]any{"hold": hold, "step_up": stepUp, "allow": allow, "total": total},
	}, nil
}

// Transaction-risk view: recent scored payments + auth-outcome mix, from decisions.
// search backs the console's global search: alert ids (contains), and
// subjects/accounts by ref prefix. Cheap prefix/contains lookups only —
// enough to jump straight to an alert or a subject profile.
func (s *Server) search(ctx context.Context, tenantID, q string) (map[string]any, error) {
	like := q + "%"      // ref prefix
	contains := "%" + q + "%" // alert-id substring, so "2273" finds ALT-2273
	alerts, err := queryMaps(ctx, s.pool,
		`SELECT id, score, threat_type, state, user_ref, account_ref
		 FROM alerts
		 WHERE tenant_id=$1 AND (id ILIKE $2 OR user_ref ILIKE $3 OR account_ref ILIKE $3)
		 ORDER BY created_at DESC LIMIT 6`, tenantID, contains, like)
	if err != nil {
		return nil, err
	}
	subjects, err := queryMaps(ctx, s.pool,
		`SELECT au.user_ref, count(a.id)::int AS alerts
		 FROM app_users au
		 LEFT JOIN alerts a ON a.tenant_id=au.tenant_id AND a.user_ref=au.user_ref
		 WHERE au.tenant_id=$1 AND au.user_ref ILIKE $2
		 GROUP BY au.user_ref ORDER BY alerts DESC LIMIT 5`, tenantID, like)
	if err != nil {
		return nil, err
	}
	return map[string]any{"alerts": alerts, "subjects": subjects}, nil
}

// userLocations returns the subject's recent coarse location fixes (geohash
// only — never raw coordinates) across sessions, newest first. Powers the
// location map shown for geo-driven risk decisions.
func (s *Server) userLocations(ctx context.Context, tenantID, userRef string) ([]map[string]any, error) {
	// Location events carry no user_ref of their own — they're tied to the
	// user through their session (same join the scoring context uses).
	return queryMaps(ctx, s.pool,
		`SELECT e.payload->>'geohash' AS geohash,
		        coalesce((e.payload->>'mock')::bool, false) AS mock,
		        e.session_id, e.ts
		 FROM events e
		 JOIN sessions s ON s.tenant_id = e.tenant_id AND s.session_id = e.session_id
		 WHERE e.tenant_id=$1 AND s.user_ref=$2
		   AND e.type='PASSIVE_LOCATION_COARSE' AND e.payload ? 'geohash'
		 ORDER BY e.ts DESC LIMIT 25`, tenantID, userRef)
}

func (s *Server) transactionRisk(ctx context.Context, tenantID string, limit int) (map[string]any, error) {
	stream, err := queryMaps(ctx, s.pool,
		`SELECT session_id, user_ref, txn_ref, txn, decision, score,
		        signals, reasons, threat_type, created_at
		 FROM decisions WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`,
		tenantID, limit)
	if err != nil {
		return nil, err
	}
	var allow, stepUp, hold, total int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE decision='ALLOW')::int,
		        count(*) FILTER (WHERE decision='STEP_UP')::int,
		        count(*) FILTER (WHERE decision='HOLD')::int,
		        count(*)::int
		 FROM decisions WHERE tenant_id=$1`, tenantID).Scan(&allow, &stepUp, &hold, &total); err != nil {
		return nil, err
	}
	return map[string]any{
		"stream": stream,
		"mix":    map[string]any{"allow": allow, "step_up": stepUp, "hold": hold, "total": total},
	}, nil
}

// Unified recent-activity feed: alerts raised, actions taken, cases opened.
func (s *Server) activity(ctx context.Context, tenantID string, limit int) ([]map[string]any, error) {
	return queryMaps(ctx, s.pool,
		`(SELECT 'alert' AS kind, id, signal AS detail, threat_type, created_at AS at
		    FROM alerts WHERE tenant_id=$1)
		 UNION ALL
		 (SELECT 'action' AS kind, id, actions.kind AS detail, NULL::text AS threat_type, created_at AS at
		    FROM actions WHERE tenant_id=$1)
		 UNION ALL
		 (SELECT 'case' AS kind, id, summary AS detail, threat_type, created_at AS at
		    FROM cases WHERE tenant_id=$1)
		 ORDER BY at DESC LIMIT $2`, tenantID, limit)
}

const alertCols = `id, session_id, account_ref, user_ref, score, threat_type, signal,
	        state, txn, disposition, case_id, assignee, assigned_at,
	        (snoozed_until IS NOT NULL AND snoozed_until > now()) AS snoozed,
	        snoozed_until, created_at, updated_at`

func (s *Server) listAlerts(ctx context.Context, tenantID, state string, limit int) ([]map[string]any, error) {
	if state != "" {
		// The open queue hides currently-snoozed alerts; other states show all.
		snoozeFilter := ""
		if state == "Open" {
			snoozeFilter = " AND (snoozed_until IS NULL OR snoozed_until <= now())"
		}
		return queryMaps(ctx, s.pool,
			`SELECT `+alertCols+`
			 FROM alerts WHERE tenant_id=$1 AND state=$2`+snoozeFilter+`
			 ORDER BY created_at DESC LIMIT $3`, tenantID, state, limit)
	}
	return queryMaps(ctx, s.pool,
		`SELECT `+alertCols+`
		 FROM alerts WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`,
		tenantID, limit)
}

// assignAlert sets (or clears, when assignee is empty) who owns an alert.
func (s *Server) assignAlert(ctx context.Context, tenantID, id, assignee string) (map[string]any, error) {
	return queryMap(ctx, s.pool,
		`UPDATE alerts SET
		   assignee = NULLIF($3, ''),
		   assigned_at = CASE WHEN NULLIF($3,'') IS NULL THEN NULL ELSE now() END,
		   updated_at = now()
		 WHERE tenant_id=$1 AND id=$2 RETURNING `+alertCols, tenantID, id, assignee)
}

// snoozeAlert hides an alert from the open queue for the given minutes (0 clears).
func (s *Server) snoozeAlert(ctx context.Context, tenantID, id string, minutes int) (map[string]any, error) {
	return queryMap(ctx, s.pool,
		`UPDATE alerts SET
		   snoozed_until = CASE WHEN $3 <= 0 THEN NULL
		                        ELSE now() + make_interval(mins => $3) END,
		   updated_at = now()
		 WHERE tenant_id=$1 AND id=$2 RETURNING `+alertCols, tenantID, id, minutes)
}

func (s *Server) getAlert(ctx context.Context, tenantID, id string) (map[string]any, error) {
	alert, err := queryMap(ctx, s.pool,
		`SELECT * FROM alerts WHERE tenant_id=$1 AND id=$2`, tenantID, id)
	if err != nil || alert == nil {
		return nil, err
	}

	timeline := []map[string]any{}
	if sid, _ := alert["session_id"].(string); sid != "" {
		timeline, err = queryMaps(ctx, s.pool,
			`SELECT type, ts, call_signals, payload FROM events
			 WHERE tenant_id=$1 AND session_id=$2 ORDER BY ts LIMIT 500`, tenantID, sid)
		if err != nil {
			return nil, err
		}
	}
	alert["timeline"] = timeline

	alert["device"] = nil
	if iid, _ := alert["install_id"].(string); iid != "" {
		dev, err := queryMap(ctx, s.pool,
			`SELECT install_id, first_seen, last_seen, fingerprint
			 FROM devices WHERE tenant_id=$1 AND install_id=$2`, tenantID, iid)
		if err != nil {
			return nil, err
		}
		if dev != nil {
			alert["device"] = dev
		}
	}

	alert["priorAlerts"] = []map[string]any{}
	if uref, _ := alert["user_ref"].(string); uref != "" {
		prior, err := queryMaps(ctx, s.pool,
			`SELECT id, score, state, signal, created_at FROM alerts
			 WHERE tenant_id=$1 AND user_ref=$2 AND id <> $3
			 ORDER BY created_at DESC LIMIT 10`, tenantID, uref, id)
		if err != nil {
			return nil, err
		}
		alert["priorAlerts"] = prior
	}

	alert["bankTxns"] = []map[string]any{}
	if aref, _ := alert["account_ref"].(string); aref != "" {
		txns, err := s.listAccountTxns(ctx, tenantID, aref, 20)
		if err != nil {
			return nil, err
		}
		alert["bankTxns"] = txns
	}

	actions, err := queryMaps(ctx, s.pool,
		`SELECT id, kind, target, note, webhook_status, device_status, created_at
		 FROM actions WHERE tenant_id=$1 AND alert_id=$2 ORDER BY created_at`,
		tenantID, id)
	if err != nil {
		return nil, err
	}
	alert["actions"] = actions
	return alert, nil
}

func (s *Server) updateAlert(ctx context.Context, tenantID, id, state, disposition string) (map[string]any, error) {
	return queryMap(ctx, s.pool,
		`UPDATE alerts SET
		   state = COALESCE(NULLIF($3, ''), state),
		   disposition = COALESCE(NULLIF($4, ''), disposition),
		   updated_at = now()
		 WHERE tenant_id=$1 AND id=$2 RETURNING *`, tenantID, id, state, disposition)
}

// ---------- actions ----------

func (s *Server) createAction(ctx context.Context, tenantID, alertID, kind, note, requestedBy string) (map[string]any, string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx,
		`SELECT * FROM alerts WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID, alertID)
	if err != nil {
		return nil, "", err
	}
	alerts, err := pgx.CollectRows(rows, pgx.RowToMap)
	if err != nil {
		return nil, "", err
	}
	if len(alerts) == 0 {
		return nil, "", nil // not found
	}
	alert := alerts[0]
	txnMap, _ := alert["txn"].(map[string]any)

	var target map[string]any
	deviceLeg := false
	switch kind {
	case "RELEASE_PAYMENT", "BLOCK_PAYMENT":
		txnRef, _ := txnMap["txnRef"].(string)
		if txnRef == "" {
			return nil, "alert has no held payment (txn.txnRef missing)", nil
		}
		target = map[string]any{"txnRef": txnRef, "amount": txnMap["amount"]}
	case "TERMINATE_SESSION":
		sid, _ := alert["session_id"].(string)
		if sid == "" {
			return nil, "alert has no session to terminate", nil
		}
		target = map[string]any{"sessionId": sid}
		deviceLeg = true
	default:
		return nil, "unknown action kind", nil
	}

	var id string
	if err := tx.QueryRow(ctx, `SELECT 'ACT-' || nextval('action_seq')`).Scan(&id); err != nil {
		return nil, "", err
	}
	deviceStatus := "n/a"
	if deviceLeg {
		deviceStatus = "pending"
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO actions (id, tenant_id, alert_id, kind, target, note,
		                      requested_by, device_status)
		 VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), NULLIF($7, ''), $8)`,
		id, tenantID, alertID, kind, target, note, requestedBy, deviceStatus); err != nil {
		return nil, "", err
	}

	newState, _ := alert["state"].(string)
	switch kind {
	case "RELEASE_PAYMENT":
		txnMap["decision"] = "Released"
		newState = "Resolved"
	case "BLOCK_PAYMENT":
		txnMap["decision"] = "Blocked"
		newState = "Resolved"
	case "TERMINATE_SESSION":
		newState = "Contained"
	}
	var txnArg any
	if txnMap != nil {
		txnArg = txnMap
	}
	if _, err := tx.Exec(ctx,
		`UPDATE alerts SET txn = COALESCE($3, txn), state = $4, updated_at = now()
		 WHERE tenant_id=$1 AND id=$2`, tenantID, alertID, txnArg, newState); err != nil {
		return nil, "", err
	}

	if caseID, _ := alert["case_id"].(string); caseID != "" {
		evt := fmt.Sprintf("%s (%s)", kindLabel(kind), id)
		if note != "" {
			evt += " — " + note
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO case_events (case_id, event) VALUES ($1, $2)`, caseID, evt); err != nil {
			return nil, "", err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, "", err
	}
	row, err := queryMap(ctx, s.pool, `SELECT * FROM actions WHERE id=$1`, id)
	return row, "", err
}

func kindLabel(kind string) string {
	out := []byte{}
	for i := 0; i < len(kind); i++ {
		c := kind[i]
		if c == '_' {
			out = append(out, ' ')
		} else if c >= 'A' && c <= 'Z' {
			out = append(out, c+('a'-'A'))
		} else {
			out = append(out, c)
		}
	}
	return string(out)
}

// Webhook outbox tuning: exponential backoff base^attempts seconds (jittered,
// capped at an hour); after maxWebhookAttempts the action goes 'dead' and is
// surfaced to analysts instead of retried forever.
const maxWebhookAttempts = 10

func (s *Server) markWebhookResult(ctx context.Context, actionID string, ok bool, errMsg string) error {
	// Failure schedules the next attempt: 5s·2^n ± 20% jitter, capped at 1h.
	// Success or exhaustion clears the schedule; exhaustion goes 'dead'.
	_, err := s.pool.Exec(ctx,
		`UPDATE actions SET
		   webhook_attempts = webhook_attempts + 1,
		   webhook_status = CASE
		     WHEN $2 THEN 'delivered'
		     WHEN webhook_attempts + 1 >= $4 THEN 'dead'
		     ELSE 'failed' END,
		   webhook_delivered_at = CASE WHEN $2 THEN now() END,
		   webhook_next_attempt_at = CASE
		     WHEN $2 OR webhook_attempts + 1 >= $4 THEN NULL
		     ELSE now() + least(5 * power(2, webhook_attempts), 3600)
		            * (0.8 + random() * 0.4) * interval '1 second' END,
		   last_error = NULLIF($3, '')
		 WHERE id = $1`, actionID, ok, errMsg, maxWebhookAttempts)
	return err
}

// claimDueWebhooks atomically leases up to `limit` actions due for
// (re)delivery. FOR UPDATE SKIP LOCKED makes concurrent server instances
// safe (no double-claims); the lease bump keeps a slow delivery from being
// re-claimed mid-flight — a crash mid-delivery simply retries at lease end.
// Rows with zero attempts are the synchronous first attempt's business for
// the first minute; after that they're treated as orphaned by a crash.
func (s *Server) claimDueWebhooks(ctx context.Context, limit int) ([]map[string]any, error) {
	return queryMaps(ctx, s.pool,
		`UPDATE actions a SET webhook_next_attempt_at = now() + interval '2 minutes'
		 WHERE a.id IN (
		   SELECT id FROM actions
		   WHERE webhook_status IN ('pending', 'failed')
		     AND webhook_attempts < $2
		     AND (webhook_next_attempt_at IS NULL OR webhook_next_attempt_at <= now())
		     AND (webhook_attempts >= 1 OR created_at <= now() - interval '60 seconds')
		   ORDER BY created_at
		   LIMIT $1
		   FOR UPDATE SKIP LOCKED)
		 RETURNING a.id, a.tenant_id, a.kind, a.alert_id, a.target, a.note,
		           a.webhook_attempts`, limit, maxWebhookAttempts)
}

func (s *Server) listActions(ctx context.Context, tenantID string, limit int) ([]map[string]any, error) {
	return queryMaps(ctx, s.pool,
		`SELECT * FROM actions WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`,
		tenantID, limit)
}

// ---------- cases ----------

func (s *Server) createCase(ctx context.Context, tenantID, alertID, assignee, summary, actor string) (string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx,
		`SELECT * FROM alerts WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID, alertID)
	if err != nil {
		return "", err
	}
	alerts, err := pgx.CollectRows(rows, pgx.RowToMap)
	if err != nil {
		return "", err
	}
	if len(alerts) == 0 {
		return "", nil
	}
	alert := alerts[0]
	var caseID string
	if err := tx.QueryRow(ctx, `SELECT 'C-' || nextval('case_seq')`).Scan(&caseID); err != nil {
		return "", err
	}
	if assignee == "" {
		assignee = "Unassigned"
	}
	if summary == "" {
		summary, _ = alert["signal"].(string)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO cases (id, tenant_id, user_ref, threat_type, assignee, summary, alert_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		caseID, tenantID, alert["user_ref"], alert["threat_type"], assignee, summary, alertID); err != nil {
		return "", err
	}
	evt := "Case opened from alert " + alertID
	if actor != "" {
		evt += " by " + actor
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO case_events (case_id, event) VALUES ($1, $2)`, caseID, evt); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE alerts SET case_id=$3, updated_at=now() WHERE tenant_id=$1 AND id=$2`,
		tenantID, alertID, caseID); err != nil {
		return "", err
	}
	return caseID, tx.Commit(ctx)
}

// maybeOpenAmlCase implements the "two files" doctrine: a proceeds-capturing
// fraud is also a money-laundering predicate, so confirming the fraud must
// open the AML file — but only when funds actually MOVED (a swap caught
// before cash-out has no laundering leg). Idempotent per alert. Returns the
// AML case id, or "" when no file is warranted.
func (s *Server) maybeOpenAmlCase(ctx context.Context, tenantID, alertID, actor string) (string, error) {
	alert, err := queryMap(ctx, s.pool,
		`SELECT user_ref, threat_type, created_at, case_id FROM alerts
		 WHERE tenant_id=$1 AND id=$2`, tenantID, alertID)
	if err != nil || alert == nil {
		return "", err
	}
	userRef, _ := alert["user_ref"].(string)
	if userRef == "" {
		return "", nil
	}
	// One AML file per alert, however many times the disposition is saved.
	if existing, err := queryMap(ctx, s.pool,
		`SELECT id FROM cases WHERE tenant_id=$1 AND alert_id=$2 AND case_type='AML'`,
		tenantID, alertID); err != nil {
		return "", err
	} else if existing != nil {
		id, _ := existing["id"].(string)
		return id, nil
	}
	// The laundering leg: outbound movement on the subject's accounts since
	// the compromise. No movement -> no Event 2 -> no file (the triage that
	// keeps case volume sane).
	createdAt, _ := alert["created_at"].(time.Time)
	flows, err := queryMaps(ctx, s.pool,
		`SELECT txn_ref, amount::float8 AS amount, coalesce(currency,'') AS currency,
		        coalesce(counterparty_ref,'') AS counterparty_ref, ts
		 FROM bank_txns
		 WHERE tenant_id=$1 AND user_ref=$2 AND direction='OUT' AND ts >= $3
		 ORDER BY ts LIMIT 20`, tenantID, userRef, createdAt)
	if err != nil || len(flows) == 0 {
		return "", err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	var caseID string
	if err := tx.QueryRow(ctx, `SELECT 'C-' || nextval('case_seq')`).Scan(&caseID); err != nil {
		return "", err
	}
	total := 0.0
	currency := ""
	for _, f := range flows {
		if a, ok := f["amount"].(float64); ok {
			total += a
		}
		if currency == "" {
			currency, _ = f["currency"].(string)
		}
	}
	threat, _ := alert["threat_type"].(string)
	fraudCase, _ := alert["case_id"].(string)
	summary := fmt.Sprintf(
		"Trace proceeds of %s (%s): %d outbound transfer(s), %.0f %s moved after compromise",
		alertID, threat, len(flows), total, currency)
	if _, err := tx.Exec(ctx,
		`INSERT INTO cases (id, tenant_id, user_ref, threat_type, assignee, summary,
		                    case_type, alert_id, linked_case_id)
		 VALUES ($1, $2, $3, 'Money Laundering', 'Unassigned', $4, 'AML', $5, NULLIF($6, ''))`,
		caseID, tenantID, userRef, summary, alertID, fraudCase); err != nil {
		return "", err
	}
	events := []string{fmt.Sprintf(
		"AML file auto-opened: %s resolved as confirmed fraud with post-compromise fund movement (by %s)",
		alertID, actor)}
	for _, f := range flows {
		ts, _ := f["ts"].(time.Time)
		events = append(events, fmt.Sprintf("Flow: %.0f %s -> %v (%v) at %s",
			f["amount"], f["currency"], f["counterparty_ref"], f["txn_ref"],
			ts.Format("2006-01-02 15:04")))
	}
	events = append(events,
		"Next: identify the mule account layer and assess STR threshold for the traced flows")
	for _, evt := range events {
		if _, err := tx.Exec(ctx,
			`INSERT INTO case_events (case_id, event) VALUES ($1, $2)`, caseID, evt); err != nil {
			return "", err
		}
	}
	return caseID, tx.Commit(ctx)
}

func (s *Server) listCases(ctx context.Context, tenantID, status string, limit int) ([]map[string]any, error) {
	if status != "" {
		return queryMaps(ctx, s.pool,
			`SELECT * FROM cases WHERE tenant_id=$1 AND status=$2
			 ORDER BY created_at DESC LIMIT $3`, tenantID, status, limit)
	}
	return queryMaps(ctx, s.pool,
		`SELECT * FROM cases WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`,
		tenantID, limit)
}

func (s *Server) getCase(ctx context.Context, tenantID, id string) (map[string]any, error) {
	c, err := queryMap(ctx, s.pool,
		`SELECT * FROM cases WHERE tenant_id=$1 AND id=$2`, tenantID, id)
	if err != nil || c == nil {
		return nil, err
	}
	timeline, err := queryMaps(ctx, s.pool,
		`SELECT event, at FROM case_events WHERE case_id=$1 ORDER BY at`, id)
	if err != nil {
		return nil, err
	}
	alerts, err := queryMaps(ctx, s.pool,
		`SELECT id, score, state, signal FROM alerts WHERE tenant_id=$1 AND case_id=$2`,
		tenantID, id)
	if err != nil {
		return nil, err
	}
	c["timeline"] = timeline
	c["alerts"] = alerts
	return c, nil
}

func (s *Server) updateCase(ctx context.Context, tenantID, id, status, assignee, note, actor string) (map[string]any, error) {
	c, err := queryMap(ctx, s.pool,
		`UPDATE cases SET
		   status = COALESCE(NULLIF($3, ''), status),
		   assignee = COALESCE(NULLIF($4, ''), assignee),
		   updated_at = now()
		 WHERE tenant_id=$1 AND id=$2 RETURNING *`, tenantID, id, status, assignee)
	if err != nil || c == nil {
		return nil, err
	}
	entries := []string{}
	if status != "" {
		entries = append(entries, "Status changed to "+status)
	}
	if assignee != "" {
		entries = append(entries, "Assigned to "+assignee)
	}
	if note != "" {
		entries = append(entries, note)
	}
	for _, e := range entries {
		if actor != "" {
			e += " — by " + actor
		}
		if _, err := s.pool.Exec(ctx,
			`INSERT INTO case_events (case_id, event) VALUES ($1, $2)`, id, e); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// ---------- profiles & sessions ----------

func (s *Server) getUserProfile(ctx context.Context, tenantID, userRef string) (map[string]any, error) {
	u, err := queryMap(ctx, s.pool,
		`SELECT * FROM app_users WHERE tenant_id=$1 AND user_ref=$2`, tenantID, userRef)
	if err != nil || u == nil {
		return nil, err
	}
	devices, err := queryMaps(ctx, s.pool,
		`SELECT ud.install_id, ud.first_seen, ud.last_seen, ud.session_count, d.fingerprint
		 FROM user_devices ud
		 LEFT JOIN devices d ON d.tenant_id=ud.tenant_id AND d.install_id=ud.install_id
		 WHERE ud.tenant_id=$1 AND ud.user_ref=$2 ORDER BY ud.first_seen`,
		tenantID, userRef)
	if err != nil {
		return nil, err
	}
	alerts, err := queryMaps(ctx, s.pool,
		`SELECT id, score, state, signal, created_at FROM alerts
		 WHERE tenant_id=$1 AND user_ref=$2 ORDER BY created_at DESC LIMIT 20`,
		tenantID, userRef)
	if err != nil {
		return nil, err
	}
	sessions, err := queryMaps(ctx, s.pool,
		`SELECT session_id, started_at, last_event_at, event_count, sim_changed
		 FROM sessions WHERE tenant_id=$1 AND user_ref=$2
		 ORDER BY started_at DESC LIMIT 20`, tenantID, userRef)
	if err != nil {
		return nil, err
	}
	u["devices"] = devices
	u["alerts"] = alerts
	u["recentSessions"] = sessions
	return u, nil
}

func (s *Server) getSessionEvents(ctx context.Context, tenantID, sessionID string) ([]map[string]any, error) {
	return queryMaps(ctx, s.pool,
		`SELECT type, ts, install_id, user_ref, call_signals, payload FROM events
		 WHERE tenant_id=$1 AND session_id=$2 ORDER BY ts LIMIT 1000`,
		tenantID, sessionID)
}

func (s *Server) eventTypeCounts(ctx context.Context) (map[string]int, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT type, count(*)::int FROM events GROUP BY type ORDER BY count(*) DESC`)
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	var typ string
	var n int
	_, err = pgx.ForEachRow(rows, []any{&typ, &n}, func() error {
		out[typ] = n
		return nil
	})
	return out, err
}

// ---------- analyst auth ----------

var analystRoles = map[string]bool{"readonly": true, "analyst": true, "senior": true, "admin": true}

// Node's crypto.scryptSync defaults: N=16384, r=8, p=1 — matched here so
// hashes are portable between the Node and Go servers (shared database).
func hashPassword(password, saltHex string) (string, error) {
	key, err := scrypt.Key([]byte(password), []byte(saltHex), 16384, 8, 1, 32)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

func (s *Server) seedAdmin(ctx context.Context, tenantID, email, password string) (bool, error) {
	var one int
	err := s.pool.QueryRow(ctx,
		`SELECT 1 FROM analysts WHERE tenant_id=$1 LIMIT 1`, tenantID).Scan(&one)
	if err == nil {
		return false, nil
	}
	if err != pgx.ErrNoRows {
		return false, err
	}
	_, errStr, err := s.createAnalyst(ctx, tenantID, email, "Bootstrap admin", "admin", password, "")
	if errStr != "" {
		return false, fmt.Errorf("%s", errStr)
	}
	return err == nil, err
}

func (s *Server) createAnalyst(ctx context.Context, tenantID, email, name, role, password, totpSecret string) (map[string]any, string, error) {
	if email == "" || len(password) < 8 {
		return nil, "email and a password of at least 8 characters are required", nil
	}
	if !analystRoles[role] {
		return nil, "role must be one of: readonly, analyst, senior, admin", nil
	}
	saltBytes := make([]byte, 16)
	if _, err := rand.Read(saltBytes); err != nil {
		return nil, "", err
	}
	salt := hex.EncodeToString(saltBytes)
	hash, err := hashPassword(password, salt)
	if err != nil {
		return nil, "", err
	}
	var secretArg any
	if totpSecret != "" {
		secretArg = totpSecret
	}
	row, err := queryMap(ctx, s.pool,
		`INSERT INTO analysts (tenant_id, email, name, role, password_salt, password_hash, totp_secret)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING id, email, name, role, disabled, created_at,
		           (totp_secret IS NOT NULL) AS mfa_enrolled`,
		tenantID, email, name, role, salt, hash, secretArg)
	if err != nil {
		return nil, "an analyst with this email already exists", nil
	}
	return row, "", nil
}

func (s *Server) verifyLogin(ctx context.Context, email, password string) (map[string]any, error) {
	a, err := queryMap(ctx, s.pool,
		`SELECT * FROM analysts WHERE email=$1 AND NOT disabled LIMIT 1`, email)
	if err != nil {
		return nil, err
	}
	if a == nil {
		hashPassword(password, "burn-time-anyway")
		return nil, nil
	}
	salt, _ := a["password_salt"].(string)
	expect, _ := a["password_hash"].(string)
	got, err := hashPassword(password, salt)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(expect), []byte(got)) != 1 {
		return nil, nil
	}
	return a, nil
}

func (s *Server) createAnalystSession(ctx context.Context, analystID any) (string, time.Time, error) {
	tokenBytes := make([]byte, 24)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", time.Time{}, err
	}
	token := hex.EncodeToString(tokenBytes)
	expires := time.Now().Add(12 * time.Hour)
	_, err := s.pool.Exec(ctx,
		`INSERT INTO analyst_sessions (token, analyst_id, expires_at) VALUES ($1, $2, $3)`,
		token, analystID, expires)
	return token, expires, err
}

func (s *Server) resolveAnalystToken(ctx context.Context, token string) (map[string]any, error) {
	row, err := queryMap(ctx, s.pool,
		`SELECT s.token, s.expires_at, a.id AS analyst_id, a.tenant_id,
		        a.email, a.name, a.role, a.disabled,
		        (a.totp_secret IS NOT NULL) AS mfa_enrolled
		 FROM analyst_sessions s JOIN analysts a ON a.id = s.analyst_id
		 WHERE s.token = $1`, token)
	if err != nil || row == nil {
		return nil, err
	}
	disabled, _ := row["disabled"].(bool)
	exp, _ := row["expires_at"].(time.Time)
	if disabled || exp.Before(time.Now()) {
		s.pool.Exec(ctx, `DELETE FROM analyst_sessions WHERE token=$1`, token)
		return nil, nil
	}
	return row, nil
}

func (s *Server) deleteAnalystSession(ctx context.Context, token string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM analyst_sessions WHERE token=$1`, token)
	return err
}

func (s *Server) listAnalysts(ctx context.Context, tenantID string) ([]map[string]any, error) {
	return queryMaps(ctx, s.pool,
		`SELECT id, email, name, role, disabled, created_at,
		        (totp_secret IS NOT NULL) AS mfa_enrolled
		 FROM analysts WHERE tenant_id=$1 ORDER BY created_at`, tenantID)
}

// ---------- tenant settings ----------

// Default console settings for a tenant with no stored overrides.
// defaultHighAmount is the per-currency "high amount, no spending history"
// cutoff, keyed by ISO currency code (uppercase) plus a DEFAULT fallback.
// Roughly a few hundred EUR of purchasing power each — a low bar, since it
// only fires when there is no history to compare the amount against. Tenants
// override via settings.risk.highAmount.
func defaultHighAmount() map[string]float64 {
	return map[string]float64{
		"XOF": 500000, "XAF": 500000, // BCEAO / BEAC CFA franc — ~€760
		"NGN":     1000000, // Nigerian naira
		"GHS":     8000,    // Ghanaian cedi
		"KES":     80000,   // Kenyan shilling
		"CZK":     50000,   // Czech koruna (demo)
		"EUR":     2000,
		"USD":     2000,
		"GBP":     2000,
		"DEFAULT": 500000,
	}
}

func defaultHighAmountAny() map[string]any {
	out := map[string]any{}
	for k, v := range defaultHighAmount() {
		out[k] = v
	}
	return out
}

// highAmountThreshold resolves the "high amount, no history" cutoff for a
// tenant + currency: settings.risk.highAmount[CCY], else that map's DEFAULT,
// else the baked per-currency default, else the global default. Currency
// codes are matched case-insensitively. Never errors — a missing/garbled
// override falls back to the defaults so scoring always has a sane cutoff.
//
// riskSettings is the resolved per-tenant risk config for one score call:
// the high-amount cutoff for the txn currency plus the TXN_VELOCITY knobs.
type riskSettings struct {
	highAmount                                    float64
	velWindowMin, velThreshold, velBase, velSlope int
}

// resolveRisk reads tenant_settings.risk once and resolves both the currency
// cutoff and the velocity tuning, applying defaults for anything unset.
func (s *Server) resolveRisk(ctx context.Context, tenantID, currency string) riskSettings {
	rs := riskSettings{
		highAmount:   defaultHighAmountCutoff,
		velWindowMin: defaultVelWindowMin, velThreshold: defaultVelThreshold,
		velBase: defaultVelBase, velSlope: defaultVelSlope,
	}
	table := defaultHighAmount()
	var raw []byte
	if err := s.pool.QueryRow(ctx,
		`SELECT settings FROM tenant_settings WHERE tenant_id=$1`, tenantID).Scan(&raw); err == nil && len(raw) > 0 {
		var stored map[string]any
		if json.Unmarshal(raw, &stored) == nil {
			if risk, ok := stored["risk"].(map[string]any); ok {
				if ha, ok := risk["highAmount"].(map[string]any); ok {
					for k, v := range ha {
						if f, ok := toFloat(v); ok {
							table[strings.ToUpper(k)] = f
						}
					}
				}
				if vel, ok := risk["velocity"].(map[string]any); ok {
					if f, ok := toFloat(vel["windowMin"]); ok && f > 0 {
						rs.velWindowMin = int(f)
					}
					if f, ok := toFloat(vel["threshold"]); ok && f > 0 {
						rs.velThreshold = int(f)
					}
					if f, ok := toFloat(vel["baseWeight"]); ok && f > 0 {
						rs.velBase = int(f)
					}
					if f, ok := toFloat(vel["slope"]); ok && f > 0 {
						rs.velSlope = int(f)
					}
				}
			}
		}
	}
	if t, ok := table[strings.ToUpper(currency)]; ok {
		rs.highAmount = t
	} else if t, ok := table["DEFAULT"]; ok {
		rs.highAmount = t
	}
	return rs
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

func defaultSettings() map[string]any {
	return map[string]any{
		"tenant": map[string]any{
			"name": "Demo Bank", "environment": "Production", "dataRegion": "EU (Frankfurt)",
			"dataRetention": "13 months", "platformVersion": "BIP 8.4.2",
			"currency": "XOF", // primary operating currency (most tenants are single-currency)
		},
		"risk": map[string]any{
			"highAmount": defaultHighAmountAny(),
			"velocity": map[string]any{
				"windowMin":  defaultVelWindowMin,
				"threshold":  defaultVelThreshold,
				"baseWeight": defaultVelBase,
				"slope":      defaultVelSlope,
			},
		},
		"notifications": map[string]any{
			"digest": true, "webhook": true, "sms": true, "weekly": true,
		},
		"modules": map[string]any{
			"bip": true, "scamflag": true, "insights": true, "fraudintel": true, "cffc": true,
		},
		"integrations": []any{
			map[string]any{"name": "Core banking API", "detail": "Payment holds & releases · v2.4", "status": "Connected", "ok": true},
			map[string]any{"name": "3DS Access Control Server", "detail": "Step-up challenge routing", "status": "Connected", "ok": true},
			map[string]any{"name": "SIEM export", "detail": "Splunk HEC · alerts & audit trail", "status": "Connected", "ok": true},
			map[string]any{"name": "KYC / onboarding provider", "detail": "Document & liveness checks", "status": "Action needed", "ok": false},
		},
	}
}

// deepMerge overlays src onto dst (maps merged recursively, other values replaced).
func deepMerge(dst, src map[string]any) map[string]any {
	for k, v := range src {
		if sm, ok := v.(map[string]any); ok {
			if dm, ok := dst[k].(map[string]any); ok {
				dst[k] = deepMerge(dm, sm)
				continue
			}
		}
		dst[k] = v
	}
	return dst
}

// getSettings merges stored overrides over defaults and adds derived,
// read-only tenant facts (name, live session-ingestion counts).
func (s *Server) getSettings(ctx context.Context, tenantID string) (map[string]any, error) {
	merged := defaultSettings()
	var raw []byte
	err := s.pool.QueryRow(ctx,
		`SELECT settings FROM tenant_settings WHERE tenant_id=$1`, tenantID).Scan(&raw)
	if err == nil && len(raw) > 0 {
		var stored map[string]any
		if json.Unmarshal(raw, &stored) == nil {
			merged = deepMerge(merged, stored)
		}
	} else if err != nil && err != pgx.ErrNoRows {
		return nil, err
	}

	// Session-ingestion is a derived, read-only fact (events in the last 24h).
	var perDay int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*)::int FROM events
		 WHERE tenant_id=$1 AND received_at > now() - interval '24 hours'`,
		tenantID).Scan(&perDay); err != nil {
		return nil, err
	}
	tenant, _ := merged["tenant"].(map[string]any)
	if tenant == nil {
		tenant = map[string]any{}
		merged["tenant"] = tenant
	}
	tenant["sessionIngestion"] = perDay
	return merged, nil
}

// patchSettings merges a partial update into the stored overrides. Only
// the writable sub-trees are accepted; derived tenant facts are ignored.
func (s *Server) patchSettings(ctx context.Context, tenantID string, patch map[string]any) (map[string]any, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx,
		`SELECT settings FROM tenant_settings WHERE tenant_id=$1`, tenantID).Scan(&raw)
	stored := map[string]any{}
	if err == nil && len(raw) > 0 {
		json.Unmarshal(raw, &stored)
	} else if err != nil && err != pgx.ErrNoRows {
		return nil, err
	}
	// Never persist derived tenant facts.
	if t, ok := patch["tenant"].(map[string]any); ok {
		delete(t, "tenant")
		delete(t, "sessionIngestion")
	}
	stored = deepMerge(stored, patch)
	blob, _ := json.Marshal(stored)
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO tenant_settings (tenant_id, settings, updated_at)
		 VALUES ($1, $2, now())
		 ON CONFLICT (tenant_id) DO UPDATE SET settings=$2, updated_at=now()`,
		tenantID, string(blob)); err != nil {
		return nil, err
	}
	return s.getSettings(ctx, tenantID)
}

// ---------- api keys ----------

func hashKey(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func (s *Server) listApiKeys(ctx context.Context, tenantID string) ([]map[string]any, error) {
	return queryMaps(ctx, s.pool,
		`SELECT id, name, prefix, last4, scope, created_at, last_used_at,
		        (revoked_at IS NOT NULL) AS revoked
		 FROM api_keys WHERE tenant_id=$1 ORDER BY created_at DESC`, tenantID)
}

// createApiKey mints a key, stores its hash, and returns the full secret
// ONCE (never retrievable again).
func (s *Server) createApiKey(ctx context.Context, tenantID, name, scope string) (map[string]any, string, error) {
	if name == "" {
		return nil, "a key name is required", nil
	}
	if scope != "read" && scope != "read/write" {
		scope = "read"
	}
	rawBytes := make([]byte, 24)
	if _, err := rand.Read(rawBytes); err != nil {
		return nil, "", err
	}
	env := "tm_live_"
	secret := env + hex.EncodeToString(rawBytes)
	prefix := secret[:len(env)+4]
	last4 := secret[len(secret)-4:]
	var id string
	if err := s.pool.QueryRow(ctx, `SELECT 'KEY-' || nextval('api_key_seq')`).Scan(&id); err != nil {
		return nil, "", err
	}
	row, err := queryMap(ctx, s.pool,
		`INSERT INTO api_keys (id, tenant_id, name, prefix, last4, key_hash, scope)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING id, name, prefix, last4, scope, created_at, last_used_at,
		           false AS revoked`,
		id, tenantID, name, prefix, last4, hashKey(secret), scope)
	if err != nil {
		return nil, "", err
	}
	row["key"] = secret // one-time reveal
	return row, "", nil
}

func (s *Server) revokeApiKey(ctx context.Context, tenantID, id string) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE api_keys SET revoked_at=now()
		 WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL`, tenantID, id)
	return tag.RowsAffected() > 0, err
}

// resolveApiKey authenticates a bearer credential against stored API keys.
// Returns the tenant + scope and bumps last_used_at. Empty tenant on miss.
func (s *Server) resolveApiKey(ctx context.Context, secret string) (tenantID, scope string) {
	if !strings.HasPrefix(secret, "tm_live_") {
		return "", ""
	}
	err := s.pool.QueryRow(ctx,
		`UPDATE api_keys SET last_used_at=now()
		 WHERE key_hash=$1 AND revoked_at IS NULL
		 RETURNING tenant_id, scope`, hashKey(secret)).Scan(&tenantID, &scope)
	if err != nil {
		return "", ""
	}
	return tenantID, scope
}

// ---------- invitations ----------

func (s *Server) createInvitation(ctx context.Context, tenantID, email, role, invitedBy string) (map[string]any, string, error) {
	if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
		return nil, "enter a valid email address", nil
	}
	if !analystRoles[role] {
		return nil, "role must be one of: readonly, analyst, senior, admin", nil
	}
	var one int
	if err := s.pool.QueryRow(ctx,
		`SELECT 1 FROM analysts WHERE tenant_id=$1 AND lower(email)=lower($2)`,
		tenantID, email).Scan(&one); err == nil {
		return nil, "this person already has an analyst account", nil
	} else if err != pgx.ErrNoRows {
		return nil, "", err
	}

	tokenBytes := make([]byte, 24)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, "", err
	}
	secret, err := generateTotpSecret()
	if err != nil {
		return nil, "", err
	}
	row, err := queryMap(ctx, s.pool,
		`INSERT INTO invitations (token, tenant_id, email, role, invited_by,
		                          totp_secret, expires_at)
		 VALUES ($1, $2, lower($3), $4, $5, $6, now() + interval '7 days')
		 RETURNING token, email, role, invited_by, created_at, expires_at`,
		hex.EncodeToString(tokenBytes), tenantID, email, role, invitedBy, secret)
	if err != nil {
		return nil, "an invitation for this email is already pending", nil
	}
	return row, "", nil
}

func (s *Server) listInvitations(ctx context.Context, tenantID string) ([]map[string]any, error) {
	return queryMaps(ctx, s.pool,
		`SELECT token, email, role, invited_by, created_at, expires_at,
		        (expires_at < now()) AS expired
		 FROM invitations WHERE tenant_id=$1 AND accepted_at IS NULL
		 ORDER BY created_at DESC`, tenantID)
}

func (s *Server) revokeInvitation(ctx context.Context, tenantID, token string) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM invitations WHERE tenant_id=$1 AND token=$2 AND accepted_at IS NULL`,
		tenantID, token)
	return tag.RowsAffected() > 0, err
}

func (s *Server) resendInvitation(ctx context.Context, tenantID, token string) (map[string]any, error) {
	return queryMap(ctx, s.pool,
		`UPDATE invitations SET expires_at = now() + interval '7 days', created_at = now()
		 WHERE tenant_id=$1 AND token=$2 AND accepted_at IS NULL
		 RETURNING token, email, role, invited_by, created_at, expires_at,
		           false AS expired`, tenantID, token)
}

/** Public lookup by token (the invitee is not authenticated). */
func (s *Server) getInvitation(ctx context.Context, token string) (map[string]any, error) {
	return queryMap(ctx, s.pool,
		`SELECT token, tenant_id, email, role, invited_by, totp_secret,
		        created_at, expires_at, accepted_at,
		        (expires_at < now()) AS expired
		 FROM invitations WHERE token=$1`, token)
}

// acceptInvitation creates the analyst (with the invitation's TOTP secret),
// marks the invitation accepted, and opens a session — atomic enough for the
// demo: analyst creation is the guarded step (unique email), acceptance
// marking follows.
func (s *Server) acceptInvitation(ctx context.Context, inv map[string]any, name, password string) (map[string]any, string, time.Time, string, error) {
	tenantID, _ := inv["tenant_id"].(string)
	email, _ := inv["email"].(string)
	role, _ := inv["role"].(string)
	secret, _ := inv["totp_secret"].(string)

	analyst, errStr, err := s.createAnalyst(ctx, tenantID, email, name, role, password, secret)
	if err != nil || errStr != "" {
		return nil, "", time.Time{}, errStr, err
	}
	if _, err := s.pool.Exec(ctx,
		`UPDATE invitations SET accepted_at = now() WHERE token=$1`, inv["token"]); err != nil {
		return nil, "", time.Time{}, "", err
	}
	token, expires, err := s.createAnalystSession(ctx, analyst["id"])
	if err != nil {
		return nil, "", time.Time{}, "", err
	}
	return analyst, token, expires, "", nil
}

func (s *Server) updateAnalyst(ctx context.Context, tenantID string, id int, role string, disabled *bool) (map[string]any, string, error) {
	if role != "" && !analystRoles[role] {
		return nil, "role must be one of: readonly, analyst, senior, admin", nil
	}
	row, err := queryMap(ctx, s.pool,
		`UPDATE analysts SET
		   role = COALESCE(NULLIF($3, ''), role),
		   disabled = COALESCE($4, disabled)
		 WHERE tenant_id=$1 AND id=$2
		 RETURNING id, email, name, role, disabled`, tenantID, id, role, disabled)
	if err != nil || row == nil {
		return nil, "", err
	}
	if disabled != nil && *disabled {
		s.pool.Exec(ctx, `DELETE FROM analyst_sessions WHERE analyst_id=$1`, id)
	}
	return row, "", nil
}
