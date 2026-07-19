// Minimal real TOTP (RFC 6238, SHA-1, 30s steps, 6 digits) — stdlib only.
// Mirrors the console's src/console/totp.ts so the QR the invitee scans
// and the code the server verifies agree with any authenticator app.
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func generateTotpSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return b32.EncodeToString(raw), nil
}

func totpURI(secret, account, issuer string) string {
	return fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		url.PathEscape(issuer), url.PathEscape(account), secret, url.QueryEscape(issuer))
}

func totpAt(secret string, counter int64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.ReplaceAll(secret, " ", "")))
	if err != nil {
		return "", err
	}
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, uint64(counter))
	m := hmac.New(sha1.New, key)
	m.Write(msg)
	h := m.Sum(nil)
	off := h[len(h)-1] & 0xf
	code := (uint32(h[off]&0x7f)<<24 | uint32(h[off+1])<<16 |
		uint32(h[off+2])<<8 | uint32(h[off+3])) % 1_000_000
	return fmt.Sprintf("%06d", code), nil
}

var totpCodeRe = regexp.MustCompile(`^\d{6}$`)

// verifyTotp accepts the current 30s step ±1 for clock drift/typing time.
func verifyTotp(secret, code string) bool {
	input := strings.ReplaceAll(code, " ", "")
	if !totpCodeRe.MatchString(input) {
		return false
	}
	step := time.Now().Unix() / 30
	for _, w := range []int64{0, -1, 1} {
		if c, err := totpAt(secret, step+w); err == nil && c == input {
			return true
		}
	}
	return false
}
