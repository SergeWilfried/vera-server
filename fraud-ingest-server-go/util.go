package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

func jsonEncode(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

func hmacB64(key, body []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write(body)
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

func hmacEqual(key, body []byte, sigB64 string) bool {
	m := hmac.New(sha256.New, key)
	m.Write(body)
	got, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}
	return hmac.Equal(m.Sum(nil), got)
}

func b64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// TokenPayload is the compact session token minted by the SDK:
// b64url(payload).b64url(hmac).
type TokenPayload struct {
	Tenant    string `json:"t"`
	SessionID string `json:"s"`
	InstallID string `json:"d"`
	UserRef   string `json:"u"`
	Iat       int64  `json:"iat"`
}

func (s *Server) verifySessionToken(token string) (*TokenPayload, error) {
	dot := -1
	for i := len(token) - 1; i >= 0; i-- {
		if token[i] == '.' {
			dot = i
			break
		}
	}
	if dot < 0 {
		return nil, fmt.Errorf("malformed")
	}
	body, sig := token[:dot], token[dot+1:]
	raw, err := b64urlDecode(body)
	if err != nil {
		return nil, fmt.Errorf("bad payload")
	}
	var p TokenPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("bad payload")
	}
	tenant, ok := s.tenants[p.Tenant]
	if !ok {
		return nil, fmt.Errorf("unknown tenant %s", p.Tenant)
	}
	m := hmac.New(sha256.New, tenant.Key)
	m.Write([]byte(body))
	got, err := b64urlDecode(sig)
	if err != nil || !hmac.Equal(m.Sum(nil), got) {
		return nil, fmt.Errorf("bad signature")
	}
	age := time.Now().Unix() - p.Iat
	if age > 3600 {
		return nil, fmt.Errorf("expired (%ds)", age)
	}
	return &p, nil
}

// jsonArg prepares a raw JSON value for a jsonb parameter (pgx would
// treat []byte as bytea); nil stays NULL.
func jsonArg(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	return string(raw)
}

func msToTime(ms int64) time.Time {
	if ms <= 0 {
		return time.Now()
	}
	return time.UnixMilli(ms)
}

func short(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
