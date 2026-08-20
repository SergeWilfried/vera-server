// Browser SDK collector — the web analogue of /v1/events.
//
// A browser can't hold the tenant HMAC secret, so the web SDK authenticates
// with a PUBLIC per-tenant site key + an Origin allowlist (the model used by
// real browser fraud/RUM SDKs). The server never trusts browser input for the
// decision — scoring runs server-side exactly as for the signed device path.
// The session token (needed by the bank backend to call /v1/score) is minted
// here, server-side, since the browser has no key.
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

// originAllowed reports whether any tenant permits this browser Origin.
func (s *Server) originAllowed(origin string) bool {
	if origin == "" {
		return false
	}
	s.tenantMu.RLock()
	defer s.tenantMu.RUnlock()
	for _, t := range s.tenants {
		for _, o := range t.AllowedOrigins {
			if strings.TrimSpace(o) == origin {
				return true
			}
		}
	}
	return false
}

// authSite validates a /v1/collect* request and returns the tenant id.
//
// Two paths:
//   - Browser (Origin present): the PUBLIC site key + the tenant Origin
//     allowlist — the model of real browser fraud/RUM SDKs. The allowlist is
//     what defends the public key against other websites.
//   - Native (no Origin): mobile SDKs must present the tenant APP key
//     (X-App-Key). Unlike the site key it is never served to web visitors —
//     it ships inside app binaries, so it is extractable by determined
//     reverse engineering, but it turns "anyone who viewed the web page can
//     write telemetry for any user" into "someone who unpacked the APK",
//     and it is rotatable per tenant (tenant rotate-app-key). The forward
//     path is device attestation (Play Integrity / App Attest) presented in
//     this same slot.
//
// Residual (accepted until attestation): Origin is client-asserted, so a
// non-browser client that forges an allowlisted Origin still reaches the
// browser path with the public site key. Attestation closes this by
// requiring a verifiable device credential regardless of Origin.
func (s *Server) authSite(r *http.Request) (string, bool) {
	tenantID := r.Header.Get("X-Tenant-Id")
	origin := r.Header.Get("Origin")
	t, ok := s.getTenant(tenantID)
	if !ok {
		return "", false
	}
	if origin == "" {
		// Native path: app key required — the site key alone no longer
		// authenticates (it is public; this was the H1 ingest hole).
		appKey := r.Header.Get("X-App-Key")
		if appKey == "" || t.AppKey == "" || t.AppKey != appKey {
			return "", false
		}
		return tenantID, true
	}
	siteKey := r.Header.Get("X-Site-Key")
	if siteKey == "" || t.SiteKey != siteKey {
		return "", false
	}
	allowed := false
	for _, o := range t.AllowedOrigins {
		if strings.TrimSpace(o) == origin {
			allowed = true
			break
		}
	}
	if !allowed {
		return "", false
	}
	return tenantID, true
}

// POST /v1/collect/token — mint a session token for a browser session.
func (s *Server) handleCollectToken(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.authSite(r)
	if !ok {
		writeJSON(w, 401, map[string]any{"error": "invalid site key or origin"})
		return
	}
	raw, _ := readBody(r)
	var b struct{ SessionID, InstallID, UserRef string }
	if err := json.Unmarshal(raw, &b); err != nil || b.SessionID == "" || b.InstallID == "" {
		writeJSON(w, 400, map[string]any{"error": "sessionId and installId are required"})
		return
	}
	token, err := s.mintToken(tenantID, b.SessionID, b.InstallID, b.UserRef)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "internal"})
		return
	}
	writeJSON(w, 200, map[string]any{"token": token})
}

// POST /v1/collect — browser telemetry batch (NDJSON, optional gzip).
func (s *Server) handleCollect(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID, ok := s.authSite(r)
	if !ok {
		writeJSON(w, 401, map[string]any{"error": "invalid site key or origin"})
		return
	}
	raw, err := readBody(r)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "read failed"})
		return
	}

	// Optional gzip (browsers can compress via CompressionStream).
	text := raw
	if strings.Contains(strings.ToLower(r.Header.Get("Content-Encoding")), "gzip") {
		gz, gerr := gzip.NewReader(bytes.NewReader(raw))
		if gerr != nil {
			writeJSON(w, 400, map[string]any{"error": "not gzip"})
			return
		}
		if text, err = io.ReadAll(gz); err != nil {
			writeJSON(w, 400, map[string]any{"error": "not gzip"})
			return
		}
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
		if json.Unmarshal([]byte(line), &ev) == nil {
			events = append(events, ev)
		}
	}
	// Log the session too: an idle heartbeat carries no events, so the header
	// is the only clue to which session a poll belongs to.
	log.Printf("⇢ collect tenant=%s sdk=%s install=%s sess=%s events=%d",
		tenantID, r.Header.Get("X-Sdk"), short(installID, 8),
		short(r.Header.Get("X-Session-Id"), 8), len(events))

	stored, err := s.recordBatch(ctx, tenantID, installID, events)
	if err != nil {
		log.Printf("collect recordBatch: %v", err)
		writeJSON(w, 500, map[string]any{"error": "internal"})
		return
	}
	if dup := len(events) - stored; dup > 0 {
		log.Printf("  ↻ %d duplicate event(s) dropped (resent batch)", dup)
	}

	// Device leg of the action channel — same contract as /v1/events, so the
	// analyst kill switch reaches browser and React Native sessions too (they
	// upload via the site-key path and were previously unreachable: their
	// TERMINATE_SESSION actions sat 'pending' forever).
	out := s.deviceCommandLeg(ctx, tenantID, events, r.Header.Get("X-Session-Id"))
	writeJSON(w, 200, map[string]any{
		"accepted": stored, "duplicates": len(events) - stored, "commands": out})
}
