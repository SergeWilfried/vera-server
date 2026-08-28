// Server-side verification of device attestation (PASSIVE_ATTESTATION).
//
// Play Integrity: the SDK forwards Google's opaque integrity token; this file
// decodes it via playintegrity.googleapis.com using a service-account
// credential, checks the verdict AND that the token's embedded nonce matches
// base64url(SHA-256(sessionId|installId)) recomputed from the event envelope
// (so a token captured on one device/session cannot vouch for another), and
// embeds the result into the stored payload as "verdict". Scoring then reads
// the verdict without any network call on the /score path.
//
// Configuration (both required to enable verification):
//   PLAY_INTEGRITY_CREDENTIALS_FILE  path to a Google service-account JSON
//   PLAY_INTEGRITY_PACKAGE           expected Android applicationId
// Unconfigured -> events are stored unverified (verdict absent) and scoring
// treats them as informational only.
//
// App Attest (iOS): stored as-is for now. Full verification (CBOR attestation
// object + Apple certificate chain) is the follow-up step; until then the
// event's presence/absence still feeds ATTESTATION_MISSING scoring.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type attestationVerdict struct {
	Verified       bool     `json:"verified"`
	Reason         string   `json:"reason,omitempty"`
	NonceOK        bool     `json:"nonceOk"`
	DeviceVerdicts []string `json:"deviceVerdicts,omitempty"`
	AppVerdict     string   `json:"appVerdict,omitempty"`
	LicenseVerdict string   `json:"licenseVerdict,omitempty"`
}

type attestationPayload struct {
	Provider string              `json:"provider"`
	Status   string              `json:"status"`
	Token    string              `json:"token,omitempty"`
	Nonce    string              `json:"nonce,omitempty"`
	Verdict  *attestationVerdict `json:"verdict,omitempty"`
}

// ---------- Google service-account OAuth (std-lib only) ----------

type playIntegrityVerifier struct {
	clientEmail string
	key         *rsa.PrivateKey
	tokenURI    string
	pkg         string
	http        *http.Client

	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

var (
	verifierOnce sync.Once
	verifier     *playIntegrityVerifier
)

func playVerifier() *playIntegrityVerifier {
	verifierOnce.Do(func() {
		path := os.Getenv("PLAY_INTEGRITY_CREDENTIALS_FILE")
		pkg := os.Getenv("PLAY_INTEGRITY_PACKAGE")
		if path == "" || pkg == "" {
			return
		}
		v, err := newPlayIntegrityVerifier(path, pkg)
		if err != nil {
			log.Printf("play integrity: credentials unusable, verification disabled: %v", err)
			return
		}
		verifier = v
		log.Printf("play integrity: verification enabled for %s", pkg)
	})
	return verifier
}

func newPlayIntegrityVerifier(credsPath, pkg string) (*playIntegrityVerifier, error) {
	raw, err := os.ReadFile(credsPath)
	if err != nil {
		return nil, err
	}
	var sa struct {
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
		TokenURI    string `json:"token_uri"`
	}
	if err := json.Unmarshal(raw, &sa); err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(sa.PrivateKey))
	if block == nil {
		return nil, errors.New("no PEM block in private_key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private_key is not RSA")
	}
	uri := sa.TokenURI
	if uri == "" {
		uri = "https://oauth2.googleapis.com/token"
	}
	return &playIntegrityVerifier{
		clientEmail: sa.ClientEmail, key: rsaKey, tokenURI: uri, pkg: pkg,
		http: &http.Client{Timeout: 5 * time.Second},
	}, nil
}

func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func (v *playIntegrityVerifier) accessToken(ctx context.Context) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.token != "" && time.Now().Before(v.tokenExp.Add(-time.Minute)) {
		return v.token, nil
	}
	now := time.Now()
	header := b64url([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{
		"iss":   v.clientEmail,
		"scope": "https://www.googleapis.com/auth/playintegrity",
		"aud":   v.tokenURI,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	})
	signingInput := header + "." + b64url(claims)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, v.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {signingInput + "." + b64url(sig)},
	}
	req, err := http.NewRequestWithContext(ctx, "POST", v.tokenURI,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := v.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("token endpoint returned %d without access_token", resp.StatusCode)
	}
	v.token = out.AccessToken
	v.tokenExp = now.Add(time.Duration(out.ExpiresIn) * time.Second)
	return v.token, nil
}

// decode calls decodeIntegrityToken and returns the token payload.
func (v *playIntegrityVerifier) decode(ctx context.Context, integrityToken string) (*playTokenPayload, error) {
	tok, err := v.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]string{"integrityToken": integrityToken})
	u := "https://playintegrity.googleapis.com/v1/" + url.PathEscape(v.pkg) + ":decodeIntegrityToken"
	req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("decodeIntegrityToken: HTTP %d", resp.StatusCode)
	}
	var out struct {
		TokenPayloadExternal playTokenPayload `json:"tokenPayloadExternal"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out.TokenPayloadExternal, nil
}

type playTokenPayload struct {
	RequestDetails struct {
		Nonce              string `json:"nonce"`
		RequestPackageName string `json:"requestPackageName"`
	} `json:"requestDetails"`
	AppIntegrity struct {
		AppRecognitionVerdict string `json:"appRecognitionVerdict"`
		PackageName           string `json:"packageName"`
	} `json:"appIntegrity"`
	DeviceIntegrity struct {
		DeviceRecognitionVerdict []string `json:"deviceRecognitionVerdict"`
	} `json:"deviceIntegrity"`
	AccountDetails struct {
		AppLicensingVerdict string `json:"appLicensingVerdict"`
	} `json:"accountDetails"`
}

// expectedNonce recomputes the SDK-side request binding from the envelope.
func expectedNonce(sessionID, installID string) string {
	d := sha256.Sum256([]byte(sessionID + "|" + installID))
	return b64url(d[:])
}

// verifyAttestations decodes Play Integrity tokens in the batch (when a
// verifier is configured) and embeds the verdict into each event's payload
// before storage. Failures never block ingest — an unverifiable token is
// stored with verified=false and a reason.
func (s *Server) verifyAttestations(ctx context.Context, events []IngestEvent) {
	v := playVerifier()
	for i := range events {
		e := &events[i]
		if e.Type != "PASSIVE_ATTESTATION" {
			continue
		}
		var p attestationPayload
		if json.Unmarshal(e.Payload, &p) != nil {
			continue
		}
		if p.Provider != "PLAY_INTEGRITY" || p.Status != "OK" || p.Token == "" {
			continue
		}
		verdict := &attestationVerdict{}
		if v == nil {
			verdict.Reason = "verification not configured"
		} else {
			vctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			decoded, err := v.decode(vctx, p.Token)
			cancel()
			if err != nil {
				verdict.Reason = "decode failed: " + err.Error()
			} else {
				verdict.Verified = true
				verdict.NonceOK = decoded.RequestDetails.Nonce == expectedNonce(e.SessionID, e.InstallID)
				verdict.DeviceVerdicts = decoded.DeviceIntegrity.DeviceRecognitionVerdict
				verdict.AppVerdict = decoded.AppIntegrity.AppRecognitionVerdict
				verdict.LicenseVerdict = decoded.AccountDetails.AppLicensingVerdict
			}
		}
		p.Verdict = verdict
		p.Token = "" // decoded; no need to store the raw token
		if raw, err := json.Marshal(p); err == nil {
			e.Payload = raw
		}
	}
}

func hasVerdict(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
