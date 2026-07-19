// Console-facing store: alerts, cases, profiles, actions, analyst auth.
package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
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

// Transaction-risk view: recent scored payments + auth-outcome mix, from decisions.
func (s *Server) transactionRisk(ctx context.Context, tenantID string, limit int) (map[string]any, error) {
	stream, err := queryMaps(ctx, s.pool,
		`SELECT session_id, user_ref, txn_ref, txn, decision, score, created_at
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

func (s *Server) listAlerts(ctx context.Context, tenantID, state string, limit int) ([]map[string]any, error) {
	if state != "" {
		return queryMaps(ctx, s.pool,
			`SELECT id, session_id, account_ref, user_ref, score, threat_type, signal,
			        state, txn, disposition, case_id, created_at, updated_at
			 FROM alerts WHERE tenant_id=$1 AND state=$2
			 ORDER BY created_at DESC LIMIT $3`, tenantID, state, limit)
	}
	return queryMaps(ctx, s.pool,
		`SELECT id, session_id, account_ref, user_ref, score, threat_type, signal,
		        state, txn, disposition, case_id, created_at, updated_at
		 FROM alerts WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`,
		tenantID, limit)
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

func (s *Server) markWebhookResult(ctx context.Context, actionID string, ok bool, errMsg string) error {
	status := "failed"
	if ok {
		status = "delivered"
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE actions SET
		   webhook_status = $2,
		   webhook_attempts = webhook_attempts + 1,
		   webhook_delivered_at = CASE WHEN $2 = 'delivered' THEN now() END,
		   last_error = NULLIF($3, '')
		 WHERE id = $1`, actionID, status, errMsg)
	return err
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
		`INSERT INTO cases (id, tenant_id, user_ref, threat_type, assignee, summary)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		caseID, tenantID, alert["user_ref"], alert["threat_type"], assignee, summary); err != nil {
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
