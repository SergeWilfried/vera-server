// Console API: analyst login + RBAC, alert/case workflow, action channel
// with signed webhook delivery into the tenant's core banking.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	rankRead    = 0
	rankAnalyst = 1
	rankSenior  = 2
	rankAdmin   = 3
)

var roleRank = map[string]int{
	"readonly": 0, "analyst": 1, "senior": 2, "admin": 3, "service": 2,
}

var rankName = map[int]string{
	rankRead: "read", rankAnalyst: "analyst", rankSenior: "senior", rankAdmin: "admin",
}

type Actor struct {
	ID          any    `json:"id,omitempty"`
	Email       string `json:"email"`
	Name        string `json:"name,omitempty"`
	Role        string `json:"role"`
	Rank        int    `json:"rank"`
	MfaEnrolled bool   `json:"mfaEnrolled"`
}

type authInfo struct {
	tenantID string
	token    string
	actor    Actor
}

func (s *Server) resolveAuth(ctx context.Context, r *http.Request) (*authInfo, error) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return nil, nil
	}
	cred := auth[len("Bearer "):]
	if tenantID, ok := s.consoleKeys[cred]; ok {
		return &authInfo{tenantID: tenantID, token: cred,
			actor: Actor{Email: "service-key", Role: "service", Rank: roleRank["service"]}}, nil
	}
	// Generated API keys (tm_live_…): read scope → read-only, read/write → senior.
	if strings.HasPrefix(cred, "tm_live_") {
		if tenantID, scope := s.resolveApiKey(ctx, cred); tenantID != "" {
			rank := rankRead
			if scope == "read/write" {
				rank = rankSenior
			}
			return &authInfo{tenantID: tenantID, token: cred,
				actor: Actor{Email: "api-key", Role: "service", Rank: rank}}, nil
		}
	}
	row, err := s.resolveAnalystToken(ctx, cred)
	if err != nil || row == nil {
		return nil, err
	}
	role, _ := row["role"].(string)
	email, _ := row["email"].(string)
	name, _ := row["name"].(string)
	mfa, _ := row["mfa_enrolled"].(bool)
	return &authInfo{
		tenantID: row["tenant_id"].(string), token: cred,
		actor: Actor{ID: row["analyst_id"], Email: email, Name: name,
			Role: role, Rank: roleRank[role], MfaEnrolled: mfa},
	}, nil
}

// consoleRoute handlers return (payload, httpStatus). payload==nil with
// status 404 means "not found"; a payload with "error" uses the status.
type consoleHandler func(ctx context.Context, tenantID string, m []string,
	q url.Values, body map[string]any, actor Actor) (any, int)

type consoleRoute struct {
	method  string
	re      *regexp.Regexp
	minRank int
	fn      consoleHandler
}

func limitOf(q url.Values, def, max int) int {
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			if n > max {
				return max
			}
			return n
		}
	}
	return def
}

func str(body map[string]any, key string) string {
	v, _ := body[key].(string)
	return v
}

func (s *Server) consoleRoutes() []consoleRoute {
	R := func(method, pattern string, minRank int, fn consoleHandler) consoleRoute {
		return consoleRoute{method, regexp.MustCompile(pattern), minRank, fn}
	}
	ok := func(v any, err error) (any, int) {
		if err != nil {
			log.Printf("console: %v", err)
			return map[string]any{"error": "internal"}, 500
		}
		if isNil(v) {
			return nil, 404
		}
		return v, 200
	}
	return []consoleRoute{
		R("GET", `^/v1/console/me$`, rankRead,
			func(ctx context.Context, t string, m []string, q url.Values, b map[string]any, actor Actor) (any, int) {
				return actor, 200
			}),
		R("GET", `^/v1/console/overview$`, rankRead,
			func(ctx context.Context, t string, m []string, q url.Values, b map[string]any, actor Actor) (any, int) {
				return ok(s.overview(ctx, t))
			}),
		R("GET", `^/v1/console/detections$`, rankRead,
			func(ctx context.Context, t string, m []string, q url.Values, b map[string]any, actor Actor) (any, int) {
				days := 30
				if v, err := strconv.Atoi(q.Get("days")); err == nil && v > 0 && v <= 365 {
					days = v
				}
				return ok(s.detections(ctx, t, days))
			}),
		R("GET", `^/v1/console/transaction-risk$`, rankRead,
			func(ctx context.Context, t string, m []string, q url.Values, b map[string]any, actor Actor) (any, int) {
				return ok(s.transactionRisk(ctx, t, limitOf(q, 25, 100)))
			}),
		R("GET", `^/v1/console/activity$`, rankRead,
			func(ctx context.Context, t string, m []string, q url.Values, b map[string]any, actor Actor) (any, int) {
				return ok(s.activity(ctx, t, limitOf(q, 8, 30)))
			}),
		R("GET", `^/v1/console/alerts$`, rankRead,
			func(ctx context.Context, t string, m []string, q url.Values, b map[string]any, actor Actor) (any, int) {
				return ok(s.listAlerts(ctx, t, q.Get("state"), limitOf(q, 50, 200)))
			}),
		R("GET", `^/v1/console/alerts/([\w-]+)$`, rankRead,
			func(ctx context.Context, t string, m []string, q url.Values, b map[string]any, actor Actor) (any, int) {
				return ok(s.getAlert(ctx, t, m[1]))
			}),
		R("PATCH", `^/v1/console/alerts/([\w-]+)$`, rankAnalyst,
			func(ctx context.Context, t string, m []string, q url.Values, b map[string]any, actor Actor) (any, int) {
				alert, err := s.updateAlert(ctx, t, m[1], str(b, "state"), str(b, "disposition"))
				if err != nil || alert == nil {
					return ok(alert, err)
				}
				// Two-files doctrine: confirming a proceeds-capturing fraud
				// opens the parallel AML file when funds moved post-compromise.
				disp := strings.ToLower(str(b, "disposition"))
				if str(b, "state") == "Resolved" &&
					strings.Contains(disp, "fraud") && !strings.Contains(disp, "false") {
					amlID, aerr := s.maybeOpenAmlCase(ctx, t, m[1], actor.Email)
					if aerr != nil {
						log.Printf("maybeOpenAmlCase %s: %v", m[1], aerr)
					} else if amlID != "" {
						alert["aml_case_id"] = amlID
						log.Printf("⚖ AML file %s auto-opened from %s", amlID, m[1])
					}
				}
				return alert, 200
			}),
		R("POST", `^/v1/console/alerts/([\w-]+)/case$`, rankAnalyst,
			func(ctx context.Context, t string, m []string, q url.Values, b map[string]any, actor Actor) (any, int) {
				caseID, err := s.createCase(ctx, t, m[1], str(b, "assignee"), str(b, "summary"), actor.Email)
				if err != nil {
					log.Printf("createCase: %v", err)
					return map[string]any{"error": "internal"}, 500
				}
				if caseID == "" {
					return nil, 404
				}
				return map[string]any{"caseId": caseID}, 200
			}),
		R("GET", `^/v1/console/cases$`, rankRead,
			func(ctx context.Context, t string, m []string, q url.Values, b map[string]any, actor Actor) (any, int) {
				return ok(s.listCases(ctx, t, q.Get("status"), limitOf(q, 50, 200)))
			}),
		R("GET", `^/v1/console/cases/([\w-]+)$`, rankRead,
			func(ctx context.Context, t string, m []string, q url.Values, b map[string]any, actor Actor) (any, int) {
				return ok(s.getCase(ctx, t, m[1]))
			}),
		R("PATCH", `^/v1/console/cases/([\w-]+)$`, rankAnalyst,
			func(ctx context.Context, t string, m []string, q url.Values, b map[string]any, actor Actor) (any, int) {
				return ok(s.updateCase(ctx, t, m[1], str(b, "status"), str(b, "assignee"),
					str(b, "note"), actor.Email))
			}),
		R("GET", `^/v1/console/users/([\w-]+)$`, rankRead,
			func(ctx context.Context, t string, m []string, q url.Values, b map[string]any, actor Actor) (any, int) {
				return ok(s.getUserProfile(ctx, t, m[1]))
			}),
		R("GET", `^/v1/console/users/([\w-]+)/locations$`, rankRead,
			func(ctx context.Context, t string, m []string, q url.Values, b map[string]any, actor Actor) (any, int) {
				return ok(s.userLocations(ctx, t, m[1]))
			}),
		R("GET", `^/v1/console/sessions/([\w-]+)/events$`, rankRead,
			func(ctx context.Context, t string, m []string, q url.Values, b map[string]any, actor Actor) (any, int) {
				return ok(s.getSessionEvents(ctx, t, m[1]))
			}),
		R("GET", `^/v1/console/accounts/([\w-]+)/transactions$`, rankRead,
			func(ctx context.Context, t string, m []string, q url.Values, b map[string]any, actor Actor) (any, int) {
				return ok(s.listAccountTxns(ctx, t, m[1], 50))
			}),
		R("GET", `^/v1/console/graph/([\w.:-]+)$`, rankRead,
			func(ctx context.Context, t string, m []string, q url.Values, b map[string]any, actor Actor) (any, int) {
				return ok(s.getGraph(ctx, t, m[1]))
			}),
		R("GET", `^/v1/console/actions$`, rankRead,
			func(ctx context.Context, t string, m []string, q url.Values, b map[string]any, actor Actor) (any, int) {
				return ok(s.listActions(ctx, t, limitOf(q, 50, 200)))
			}),
		R("POST", `^/v1/console/alerts/([\w-]+)/actions$`, rankSenior,
			func(ctx context.Context, t string, m []string, q url.Values, b map[string]any, actor Actor) (any, int) {
				action, errStr, err := s.createAction(ctx, t, m[1],
					str(b, "kind"), str(b, "note"), actor.Email)
				if err != nil {
					log.Printf("createAction: %v", err)
					return map[string]any{"error": "internal"}, 500
				}
				if errStr != "" {
					return map[string]any{"error": errStr}, 400
				}
				if action == nil {
					return nil, 404
				}
				action["webhook_status"] = s.deliverAction(t, action, 1)
				return action, 200
			}),
		// Tenant settings — readable by any analyst, writable by admins.
		R("GET", `^/v1/console/settings$`, rankRead,
			func(ctx context.Context, t string, m []string, q url.Values, b map[string]any, actor Actor) (any, int) {
				return ok(s.getSettings(ctx, t))
			}),
		R("PATCH", `^/v1/console/settings$`, rankAdmin,
			func(ctx context.Context, t string, m []string, q url.Values, b map[string]any, actor Actor) (any, int) {
				return ok(s.patchSettings(ctx, t, b))
			}),
		// API keys — admin only, never service keys (see rank guard below).
		R("GET", `^/v1/console/api-keys$`, rankAdmin,
			func(ctx context.Context, t string, m []string, q url.Values, b map[string]any, actor Actor) (any, int) {
				return ok(s.listApiKeys(ctx, t))
			}),
		R("POST", `^/v1/console/api-keys$`, rankAdmin,
			func(ctx context.Context, t string, m []string, q url.Values, b map[string]any, actor Actor) (any, int) {
				row, errStr, err := s.createApiKey(ctx, t, str(b, "name"), str(b, "scope"))
				if err != nil {
					log.Printf("createApiKey: %v", err)
					return map[string]any{"error": "internal"}, 500
				}
				if errStr != "" {
					return map[string]any{"error": errStr}, 400
				}
				return row, 200
			}),
		R("DELETE", `^/v1/console/api-keys/([\w-]+)$`, rankAdmin,
			func(ctx context.Context, t string, m []string, q url.Values, b map[string]any, actor Actor) (any, int) {
				found, err := s.revokeApiKey(ctx, t, m[1])
				if err != nil {
					log.Printf("revokeApiKey: %v", err)
					return map[string]any{"error": "internal"}, 500
				}
				if !found {
					return nil, 404
				}
				return map[string]any{"ok": true}, 200
			}),
		// Team management — admin only, never service keys.
		R("GET", `^/v1/console/team$`, rankAdmin,
			func(ctx context.Context, t string, m []string, q url.Values, b map[string]any, actor Actor) (any, int) {
				return ok(s.listAnalysts(ctx, t))
			}),
		R("POST", `^/v1/console/team$`, rankAdmin,
			func(ctx context.Context, t string, m []string, q url.Values, b map[string]any, actor Actor) (any, int) {
				row, errStr, err := s.createAnalyst(ctx, t, str(b, "email"),
					str(b, "name"), str(b, "role"), str(b, "password"), "")
				if err != nil {
					log.Printf("createAnalyst: %v", err)
					return map[string]any{"error": "internal"}, 500
				}
				if errStr != "" {
					return map[string]any{"error": errStr}, 400
				}
				return row, 200
			}),
		R("GET", `^/v1/console/team/invitations$`, rankAdmin,
			func(ctx context.Context, t string, m []string, q url.Values, b map[string]any, actor Actor) (any, int) {
				return ok(s.listInvitations(ctx, t))
			}),
		R("POST", `^/v1/console/team/invitations$`, rankAdmin,
			func(ctx context.Context, t string, m []string, q url.Values, b map[string]any, actor Actor) (any, int) {
				invitedBy := actor.Name
				if invitedBy == "" {
					invitedBy = actor.Email
				}
				row, errStr, err := s.createInvitation(ctx, t, str(b, "email"),
					str(b, "role"), invitedBy)
				if err != nil {
					log.Printf("createInvitation: %v", err)
					return map[string]any{"error": "internal"}, 500
				}
				if errStr != "" {
					return map[string]any{"error": errStr}, 400
				}
				return row, 200
			}),
		R("DELETE", `^/v1/console/team/invitations/([\w-]+)$`, rankAdmin,
			func(ctx context.Context, t string, m []string, q url.Values, b map[string]any, actor Actor) (any, int) {
				found, err := s.revokeInvitation(ctx, t, m[1])
				if err != nil {
					log.Printf("revokeInvitation: %v", err)
					return map[string]any{"error": "internal"}, 500
				}
				if !found {
					return nil, 404
				}
				return map[string]any{"ok": true}, 200
			}),
		R("POST", `^/v1/console/team/invitations/([\w-]+)/resend$`, rankAdmin,
			func(ctx context.Context, t string, m []string, q url.Values, b map[string]any, actor Actor) (any, int) {
				return ok(s.resendInvitation(ctx, t, m[1]))
			}),
		R("PATCH", `^/v1/console/team/(\d+)$`, rankAdmin,
			func(ctx context.Context, t string, m []string, q url.Values, b map[string]any, actor Actor) (any, int) {
				id, _ := strconv.Atoi(m[1])
				var disabled *bool
				if v, has := b["disabled"].(bool); has {
					disabled = &v
				}
				row, errStr, err := s.updateAnalyst(ctx, t, id, str(b, "role"), disabled)
				if err != nil {
					log.Printf("updateAnalyst: %v", err)
					return map[string]any{"error": "internal"}, 500
				}
				if errStr != "" {
					return map[string]any{"error": errStr}, 400
				}
				return ok(row, nil)
			}),
	}
}

func isNil(v any) bool {
	if v == nil {
		return true
	}
	if m, ok := v.(map[string]any); ok {
		return m == nil
	}
	return false
}

func (s *Server) handleConsole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	path := r.URL.Path

	// Unauthenticated console routes: login and the invitee-facing
	// invitation endpoints (the invitee has no account yet).
	if r.Method == "POST" && path == "/v1/console/login" {
		s.handleLogin(ctx, w, r)
		return
	}
	if m := regexp.MustCompile(`^/v1/console/invitations/([\w-]+)$`).FindStringSubmatch(path); m != nil && r.Method == "GET" {
		s.handleInvitationContext(ctx, w, m[1])
		return
	}
	if m := regexp.MustCompile(`^/v1/console/invitations/([\w-]+)/accept$`).FindStringSubmatch(path); m != nil && r.Method == "POST" {
		s.handleInvitationAccept(ctx, w, r, m[1])
		return
	}

	auth, err := s.resolveAuth(ctx, r)
	if err != nil {
		log.Printf("auth: %v", err)
		writeJSON(w, 500, map[string]any{"error": "internal"})
		return
	}
	if auth == nil {
		writeJSON(w, 401, map[string]any{"error": "missing or invalid credentials"})
		return
	}

	if r.Method == "POST" && path == "/v1/console/logout" {
		if auth.actor.Role != "service" {
			s.deleteAnalystSession(ctx, auth.token)
		}
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}

	for _, route := range s.consoleRoutes() {
		m := route.re.FindStringSubmatch(path)
		if m == nil || r.Method != route.method {
			continue
		}
		if auth.actor.Rank < route.minRank {
			writeJSON(w, 403, map[string]any{
				"error": "requires " + rankName[route.minRank] + " role or higher",
				"role":  auth.actor.Role})
			return
		}
		body := map[string]any{}
		if route.method != "GET" {
			raw, _ := readBody(r)
			if len(raw) > 0 {
				if err := json.Unmarshal(raw, &body); err != nil {
					writeJSON(w, 400, map[string]any{"error": "bad json"})
					return
				}
			}
		}
		out, status := route.fn(ctx, auth.tenantID, m, r.URL.Query(), body, auth.actor)
		if out == nil && status == 404 {
			writeJSON(w, 404, map[string]any{"error": "not found"})
			return
		}
		writeJSON(w, status, out)
		return
	}
	writeJSON(w, 404, map[string]any{"error": "not found"})
}

// ---------- login & invitation handlers (unauthenticated) ----------

func analystPublic(a map[string]any) map[string]any {
	mfa, _ := a["mfa_enrolled"].(bool)
	if !mfa {
		// verifyLogin returns the raw row: derive from totp_secret.
		mfa = a["totp_secret"] != nil
	}
	return map[string]any{"email": a["email"], "name": a["name"],
		"role": a["role"], "mfaEnrolled": mfa}
}

func (s *Server) handleLogin(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	raw, _ := readBody(r)
	var body struct{ Email, Password, Code string }
	if err := json.Unmarshal(raw, &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad json"})
		return
	}
	analyst, err := s.verifyLogin(ctx, body.Email, body.Password)
	if err != nil {
		log.Printf("login: %v", err)
		writeJSON(w, 500, map[string]any{"error": "internal"})
		return
	}
	if analyst == nil {
		writeJSON(w, 401, map[string]any{"error": "invalid credentials"})
		return
	}
	// Second factor: required whenever the analyst has enrolled TOTP.
	if secret, _ := analyst["totp_secret"].(string); secret != "" {
		if body.Code == "" {
			writeJSON(w, 401, map[string]any{"error": "mfa_required", "mfaRequired": true})
			return
		}
		if !verifyTotp(secret, body.Code) {
			writeJSON(w, 401, map[string]any{"error": "invalid two-factor code", "mfaRequired": true})
			return
		}
	}
	token, expires, err := s.createAnalystSession(ctx, analyst["id"])
	if err != nil {
		log.Printf("session: %v", err)
		writeJSON(w, 500, map[string]any{"error": "internal"})
		return
	}
	log.Printf("⚿ login %v (%v)", analyst["email"], analyst["role"])
	writeJSON(w, 200, map[string]any{
		"token": token, "expiresAt": expires, "analyst": analystPublic(analyst),
	})
}

func (s *Server) handleInvitationContext(ctx context.Context, w http.ResponseWriter, token string) {
	inv, err := s.getInvitation(ctx, token)
	if err != nil {
		log.Printf("invitation: %v", err)
		writeJSON(w, 500, map[string]any{"error": "internal"})
		return
	}
	if inv == nil || inv["accepted_at"] != nil {
		writeJSON(w, 404, map[string]any{"error": "invitation not found or revoked"})
		return
	}
	if expired, _ := inv["expired"].(bool); expired {
		writeJSON(w, 410, map[string]any{"error": "invitation expired",
			"email": inv["email"], "invitedBy": inv["invited_by"]})
		return
	}
	secret, _ := inv["totp_secret"].(string)
	email, _ := inv["email"].(string)
	writeJSON(w, 200, map[string]any{
		"email": inv["email"], "role": inv["role"], "invitedBy": inv["invited_by"],
		"expiresAt": inv["expires_at"], "secret": secret,
		"otpauthUri": totpURI(secret, email, "VeraWall"),
	})
}

func (s *Server) handleInvitationAccept(ctx context.Context, w http.ResponseWriter, r *http.Request, token string) {
	raw, _ := readBody(r)
	var body struct{ Name, Password, Code string }
	if err := json.Unmarshal(raw, &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad json"})
		return
	}
	inv, err := s.getInvitation(ctx, token)
	if err != nil {
		log.Printf("invitation: %v", err)
		writeJSON(w, 500, map[string]any{"error": "internal"})
		return
	}
	if inv == nil || inv["accepted_at"] != nil {
		writeJSON(w, 404, map[string]any{"error": "invitation not found or revoked"})
		return
	}
	if expired, _ := inv["expired"].(bool); expired {
		writeJSON(w, 410, map[string]any{"error": "invitation expired"})
		return
	}
	if len(body.Name) < 2 {
		writeJSON(w, 400, map[string]any{"error": "enter your full name"})
		return
	}
	secret, _ := inv["totp_secret"].(string)
	if !verifyTotp(secret, body.Code) {
		writeJSON(w, 400, map[string]any{"error": "invalid two-factor code"})
		return
	}
	analyst, sessToken, expires, errStr, err := s.acceptInvitation(ctx, inv, body.Name, body.Password)
	if err != nil {
		log.Printf("accept: %v", err)
		writeJSON(w, 500, map[string]any{"error": "internal"})
		return
	}
	if errStr != "" {
		writeJSON(w, 400, map[string]any{"error": errStr})
		return
	}
	log.Printf("⚿ invitation accepted %v (%v)", analyst["email"], analyst["role"])
	writeJSON(w, 200, map[string]any{
		"token": sessToken, "expiresAt": expires, "analyst": analystPublic(analyst),
	})
}

// ---------- action delivery (webhook into core banking) ----------

var webhookTypes = map[string]string{
	"RELEASE_PAYMENT":   "payment.release",
	"BLOCK_PAYMENT":     "payment.block",
	"TERMINATE_SESSION": "session.terminate",
}

// deliverAction pushes one action to the tenant's core-banking webhook,
// signed with the tenant key over the raw body. The first attempt is
// awaited (the console response carries real delivery status); afterwards
// the outbox dispatcher owns redelivery — this function never schedules.
// Delivery is at-least-once: receivers must dedupe on the action `id`.
func (s *Server) deliverAction(tenantID string, action map[string]any, attempt int) string {
	tenant, ok := s.getTenant(tenantID)
	actionID, _ := action["id"].(string)
	kind, _ := action["kind"].(string)
	signing, keyOK := tenant.activeKey()
	if !ok || !keyOK {
		s.markWebhookResult(context.Background(), actionID, false, "tenant has no active key")
		return "failed"
	}

	payload := map[string]any{
		"id": actionID, "type": webhookTypes[kind], "tenantId": tenantID,
		"alertId": action["alert_id"], "note": action["note"],
		"ts": time.Now().UnixMilli(),
	}
	if target, ok := action["target"].(map[string]any); ok {
		for k, v := range target {
			payload[k] = v
		}
	}
	raw, _ := json.Marshal(payload)
	sig := hmacB64(signing.Key, raw)

	client := &http.Client{Timeout: 3 * time.Second}
	req, _ := http.NewRequest("POST", tenant.Webhook, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-Id", tenantID)
	req.Header.Set("X-Signature", sig)
	// The signing key's id lets the receiver rotate its verify key in step.
	req.Header.Set("X-Key-Id", signing.Kid)
	req.Header.Set("X-Attempt", strconv.Itoa(attempt))

	resp, err := client.Do(req)
	if err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		resp.Body.Close()
		s.markWebhookResult(context.Background(), actionID, true, "")
		log.Printf("  → delivered %s %s to core banking", actionID, webhookTypes[kind])
		return "delivered"
	}
	errMsg := "webhook error"
	if err != nil {
		errMsg = err.Error()
	} else {
		errMsg = "webhook returned " + strconv.Itoa(resp.StatusCode)
		resp.Body.Close()
	}
	s.markWebhookResult(context.Background(), actionID, false, errMsg)
	log.Printf("  → webhook failed %s attempt %d (%s)", actionID, attempt, errMsg)
	return "failed"
}

// webhookDispatcher is the outbox worker: every tick it leases actions due
// for redelivery (crash-safe — the schedule lives in Postgres, so restarts
// lose nothing) and replays them. Safe to run on every instance thanks to
// SKIP LOCKED in the claim.
func (s *Server) webhookDispatcher(ctx context.Context) {
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		due, err := s.claimDueWebhooks(ctx, 20)
		if err != nil {
			log.Printf("webhook dispatcher: claim: %v", err)
			continue
		}
		for _, action := range due {
			tenantID, _ := action["tenant_id"].(string)
			attempts := asInt(action["webhook_attempts"])
			id, _ := action["id"].(string)
			log.Printf("  → redelivering %s (attempt %d)", id, attempts+1)
			s.deliverAction(tenantID, action, attempts+1)
		}
	}
}

func asInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int32:
		return int(n)
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
}
