// SDK-facing and bank-facing endpoints: /v1/events, /v1/transactions,
// /v1/score, /stats. Wire contracts identical to the Node server.
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
)

func readBody(r *http.Request) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r.Body, 8<<20))
}

// ---------- POST /v1/events ----------

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	raw, err := readBody(r)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "read failed"})
		return
	}
	tenantID := r.Header.Get("X-Tenant-Id")
	if _, ok := s.getTenant(tenantID); !ok {
		writeJSON(w, 400, map[string]any{"error": "unknown tenant: " + tenantID})
		return
	}
	if !s.verifyTenantSig(tenantID, raw, r.Header.Get("X-Signature")) {
		log.Printf("✗ signature mismatch tenant=%s", tenantID)
		writeJSON(w, 401, map[string]any{"error": "bad signature"})
		return
	}

	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "not gzip"})
		return
	}
	text, err := io.ReadAll(gz)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "not gzip"})
		return
	}

	installID := r.Header.Get("X-Install-Id")
	events := []IngestEvent{}
	sc := bufio.NewScanner(bytes.NewReader(text))
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev IngestEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			log.Printf("  unparseable line")
			continue
		}
		events = append(events, ev)
	}
	log.Printf("✓ batch tenant=%s sdk=%s install=%s events=%d",
		tenantID, r.Header.Get("X-Sdk"), short(installID, 8), len(events))
	for _, ev := range events {
		bits := ""
		if ev.UserRef != "" {
			bits += " user=" + short(ev.UserRef, 8)
		}
		if ev.SessionID != "" {
			bits += " sess=" + short(ev.SessionID, 8)
		}
		if cs, ok := parsePayload[callSignals](ev.CallSignals); ok {
			if cs.InGsmCall {
				bits += " IN GSM CALL"
			}
			if cs.InVoipCall {
				bits += " IN VOIP CALL"
			}
			if cs.SpeakerOn {
				bits += " speaker"
			}
		}
		log.Printf("  %s%s", ev.Type, bits)
	}

	if err := s.recordBatch(ctx, tenantID, installID, events); err != nil {
		log.Printf("recordBatch: %v", err)
		writeJSON(w, 500, map[string]any{"error": "internal"})
		return
	}

	// Device leg of the action channel: hand pending terminate commands
	// for these sessions back to the SDK in the batch response.
	seen := map[string]bool{}
	sessionIDs := []string{}
	for _, ev := range events {
		if ev.SessionID != "" && !seen[ev.SessionID] {
			seen[ev.SessionID] = true
			sessionIDs = append(sessionIDs, ev.SessionID)
		}
	}
	commands, err := s.pendingDeviceCommands(ctx, tenantID, sessionIDs)
	if err != nil {
		log.Printf("pendingDeviceCommands: %v", err)
		writeJSON(w, 500, map[string]any{"error": "internal"})
		return
	}
	out := []map[string]any{}
	ids := []string{}
	for _, c := range commands {
		id, _ := c["id"].(string)
		ids = append(ids, id)
		item := map[string]any{"id": id, "kind": c["kind"]}
		if target, ok := c["target"].(map[string]any); ok {
			for k, v := range target {
				item[k] = v
			}
		}
		out = append(out, item)
		log.Printf("  ⇠ command %v -> device", c["kind"])
	}
	if err := s.markDeviceDelivered(ctx, ids); err != nil {
		log.Printf("markDeviceDelivered: %v", err)
	}
	writeJSON(w, 200, map[string]any{"accepted": len(events), "commands": out})
}

// ---------- POST /v1/transactions ----------

func (s *Server) handleTransactions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	raw, err := readBody(r)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "read failed"})
		return
	}
	tenantID := r.Header.Get("X-Tenant-Id")
	if _, ok := s.getTenant(tenantID); !ok {
		writeJSON(w, 400, map[string]any{"error": "unknown tenant: " + tenantID})
		return
	}
	if !s.verifyTenantSig(tenantID, raw, r.Header.Get("X-Signature")) {
		log.Printf("✗ feed signature mismatch tenant=%s", tenantID)
		writeJSON(w, 401, map[string]any{"error": "bad signature"})
		return
	}

	var txns []BankTxn
	var wrapped struct {
		Transactions []BankTxn `json:"transactions"`
	}
	if err := json.Unmarshal(raw, &wrapped); err == nil && wrapped.Transactions != nil {
		txns = wrapped.Transactions
	} else if err := json.Unmarshal(raw, &txns); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad json"})
		return
	}
	if txns == nil {
		writeJSON(w, 400, map[string]any{"error": "transactions must be an array"})
		return
	}
	for _, t := range txns {
		if t.TxnRef == "" || t.AccountRef == "" ||
			(t.Direction != "IN" && t.Direction != "OUT") || t.Amount <= 0 {
			writeJSON(w, 400, map[string]any{
				"error": "each txn needs txnRef, accountRef, direction IN|OUT, amount > 0"})
			return
		}
	}

	inserted, outAccounts, err := s.recordBankTxns(ctx, tenantID, txns)
	if err != nil {
		log.Printf("recordBankTxns: %v", err)
		writeJSON(w, 500, map[string]any{"error": "internal"})
		return
	}
	log.Printf("⇄ feed tenant=%s txns=%d new=%d outAccounts=%d",
		tenantID, len(txns), inserted, len(outAccounts))

	// Ledger detectors, each with its own typology and 24h dedupe.
	alerts := []string{}
	for _, accountRef := range outAccounts {
		userRef := ""
		for _, t := range txns {
			if t.AccountRef == accountRef && t.UserRef != "" {
				userRef = t.UserRef
				break
			}
		}
		type detector struct {
			threatType, label string
			run               func() (ScoreResult, map[string]any, error)
		}
		detectors := []detector{
			{"Money Mule", "mule pattern", func() (ScoreResult, map[string]any, error) {
				flow, err := s.getAccountFlow(ctx, tenantID, accountRef)
				if err != nil {
					return ScoreResult{}, nil, err
				}
				return scoreAccountFlow(flow), map[string]any{
					"accountRef": accountRef, "in72": flow.In72,
					"out24": flow.Out24, "fanOut24": flow.FanOut24}, nil
			}},
			{"Agent Commission Fraud", "commission pattern", func() (ScoreResult, map[string]any, error) {
				st, err := s.getAgentActivity(ctx, tenantID, accountRef, 10000)
				if err != nil {
					return ScoreResult{}, nil, err
				}
				return scoreAgentActivity(st), map[string]any{
					"accountRef": accountRef, "txns24h": st.Total24,
					"topCounterparty": st.TopCpRef, "splitSum": st.TopCpSum}, nil
			}},
		}
		for _, d := range detectors {
			dup, err := s.hasRecentOpenAlert(ctx, tenantID, accountRef, d.threatType)
			if err != nil {
				log.Printf("dedupe check: %v", err)
				continue
			}
			if dup {
				continue
			}
			result, txnInfo, err := d.run()
			if err != nil {
				log.Printf("detector %s: %v", d.label, err)
				continue
			}
			if result.Score < 85 {
				continue
			}
			id, err := s.raiseAlert(ctx, tenantID, AlertDraft{
				AccountRef: accountRef, UserRef: userRef, Score: result.Score,
				ThreatType: d.threatType, Signal: result.Summary,
				Signals: result.Signals, Txn: txnInfo})
			if err != nil {
				log.Printf("raiseAlert: %v", err)
				continue
			}
			alerts = append(alerts, id)
			log.Printf("  ▲ %s account=%s score=%d alert=%s",
				d.label, short(accountRef, 8), result.Score, id)
			for _, sig := range result.Signals {
				log.Printf("    +%d %s — %s", sig.Weight, sig.Code, sig.Evidence)
			}
		}
	}
	writeJSON(w, 200, map[string]any{
		"accepted": inserted, "duplicates": len(txns) - inserted, "alerts": alerts})
}

// ---------- POST /v1/score ----------

func (s *Server) handleScore(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	raw, err := readBody(r)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "read failed"})
		return
	}
	var body struct {
		SessionToken string          `json:"sessionToken"`
		Transaction  json.RawMessage `json:"transaction"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad json"})
		return
	}
	payload, err := s.verifySessionToken(body.SessionToken)
	if err != nil {
		writeJSON(w, 401, map[string]any{"error": "invalid session token: " + err.Error()})
		return
	}

	var txn ScoreTxn
	if len(body.Transaction) > 0 {
		json.Unmarshal(body.Transaction, &txn)
	}

	// Idempotent per (tenant, session, txnRef): a bank retrying a timed-out
	// call gets the stored decision back — same alert, no re-score. The
	// txnRef is the idempotency key; calls without one are never deduped.
	if txn.TxnRef != "" {
		if prior, err := s.getDecisionReplay(ctx, payload.Tenant,
			payload.SessionID, txn.TxnRef); err != nil {
			log.Printf("decision replay lookup: %v", err)
			writeJSON(w, 500, map[string]any{"error": "internal"})
			return
		} else if prior != nil {
			log.Printf("⚖ score txn=%s tenant=%s session=%s -> replay (%v)",
				txn.TxnRef, payload.Tenant, short(payload.SessionID, 8), prior["decision"])
			s.writeScoreReplay(w, payload, txn.TxnRef, prior)
			return
		}
	}

	sc, err := s.getScoringContext(ctx, payload.Tenant, payload.SessionID,
		payload.UserRef, payload.InstallID)
	if err != nil {
		log.Printf("getScoringContext: %v", err)
		writeJSON(w, 500, map[string]any{"error": "internal"})
		return
	}
	result := scoreSession(sc, txn)

	// Policy bands: 0–54 approve · 55–84 step-up · 85–100 hold for analyst
	decision := "ALLOW"
	if result.Score >= 85 {
		decision = "HOLD"
	} else if result.Score >= 55 {
		decision = "STEP_UP"
	}

	alertID, err := s.recordDecision(ctx, DecisionRecord{
		TenantID: payload.Tenant, SessionID: payload.SessionID,
		InstallID: payload.InstallID, UserRef: payload.UserRef,
		TxnRef: txn.TxnRef, Txn: body.Transaction,
		Decision: decision, Result: result})
	if err == ErrDuplicateDecision {
		// Concurrent retry won the insert race — serve its stored decision.
		prior, perr := s.getDecisionReplay(ctx, payload.Tenant, payload.SessionID, txn.TxnRef)
		if perr != nil || prior == nil {
			log.Printf("decision replay after conflict: %v", perr)
			writeJSON(w, 500, map[string]any{"error": "internal"})
			return
		}
		s.writeScoreReplay(w, payload, txn.TxnRef, prior)
		return
	}
	if err != nil {
		log.Printf("recordDecision: %v", err)
		writeJSON(w, 500, map[string]any{"error": "internal"})
		return
	}

	suffix := ""
	if result.ThreatType != "" {
		suffix += " " + result.ThreatType
	}
	if alertID != "" {
		suffix += "  alert " + alertID
	}
	log.Printf("⚖ score txn=%s tenant=%s session=%s -> %s (%d)%s",
		txn.TxnRef, payload.Tenant, short(payload.SessionID, 8),
		decision, result.Score, suffix)
	for _, sig := range result.Signals {
		log.Printf("    +%d %s — %s", sig.Weight, sig.Code, sig.Evidence)
	}

	var alertOut any
	if alertID != "" {
		alertOut = alertID
	}
	var threatOut any
	if result.ThreatType != "" {
		threatOut = result.ThreatType
	}
	var userOut any
	if payload.UserRef != "" {
		userOut = payload.UserRef
	}
	writeJSON(w, 200, map[string]any{
		"decision":   decision,
		"riskScore":  result.Score,
		"reasons":    result.Reasons,
		"signals":    result.Signals,
		"threatType": threatOut,
		"alertId":    alertOut,
		"session": map[string]any{
			"tenantId": payload.Tenant, "sessionId": payload.SessionID,
			"installId": payload.InstallID, "userRef": userOut,
		},
	})
}

// writeScoreReplay serves a stored decision in the exact shape of a fresh
// /v1/score response (plus "replay": true for observability), so bank
// retries are indistinguishable from the original call.
func (s *Server) writeScoreReplay(w http.ResponseWriter, payload *TokenPayload,
	txnRef string, prior map[string]any) {
	var userOut any
	if payload.UserRef != "" {
		userOut = payload.UserRef
	}
	writeJSON(w, 200, map[string]any{
		"decision":   prior["decision"],
		"riskScore":  prior["score"],
		"reasons":    prior["reasons"],
		"signals":    prior["signals"],
		"threatType": prior["threat_type"],
		"alertId":    prior["alert_id"],
		"replay":     true,
		"session": map[string]any{
			"tenantId": payload.Tenant, "sessionId": payload.SessionID,
			"installId": payload.InstallID, "userRef": userOut,
		},
	})
}

// ---------- GET /stats ----------

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	counts, err := s.eventTypeCounts(r.Context())
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "internal"})
		return
	}
	writeJSON(w, 200, counts)
}
