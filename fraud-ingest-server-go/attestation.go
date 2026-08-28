// Server-side verification of device attestation (PASSIVE_ATTESTATION).
//
// Play Integrity (Android): the SDK forwards Google's opaque integrity token;
// it is decoded via playintegrity.googleapis.com using the tenant's
// service-account credential and checked against the expected package and the
// session-bound nonce.
//
// App Attest (iOS): the SDK forwards the Secure-Enclave attestation object;
// it is verified locally — certificate chain to Apple's App Attestation root
// CA, the composite nonce extension binding it to this session's challenge,
// the key id, and the authenticator data (App ID hash, counter, environment).
//
// Both run at INGEST with the result embedded into the stored payload as
// "verdict" (verified, fail reason, evidence); the /score path never makes a
// network call. Failures never block ingest — an unverifiable token is stored
// with verified=false and a reason.
//
// Per-tenant configuration (the tenant registry):
//   tenant_settings.settings.attestation = {
//     "playPackage":    "com.tenant.app",        // Android applicationId
//     "appAttestAppId": "TEAMID.com.tenant.app", // iOS App ID
//     "appAttestEnv":   "production"             // or "development"
//   }
//   tenants.play_sa_enc = AES-GCM(service-account JSON) under MASTER_KEY
//     (set by ops; the console upload endpoint is a follow-up)
// Env fallback (dev / single-tenant): PLAY_INTEGRITY_CREDENTIALS_FILE +
// PLAY_INTEGRITY_PACKAGE, APP_ATTEST_APP_ID (+ APP_ATTEST_ENV=development).
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
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
	Verified bool   `json:"verified"`
	Reason   string `json:"reason,omitempty"` // why verification could not run
	// Fail is set when verification RAN and the attestation is not good:
	// empty string on a verified-genuine device/app. Provider-agnostic —
	// scoring keys off this one field.
	Fail           string   `json:"fail,omitempty"`
	NonceOK        bool     `json:"nonceOk"`
	DeviceVerdicts []string `json:"deviceVerdicts,omitempty"`
	AppVerdict     string   `json:"appVerdict,omitempty"`
	LicenseVerdict string   `json:"licenseVerdict,omitempty"`
	Environment    string   `json:"environment,omitempty"` // App Attest aaguid env
}

type attestationPayload struct {
	Provider    string              `json:"provider"`
	Status      string              `json:"status"`
	Token       string              `json:"token,omitempty"`
	Nonce       string              `json:"nonce,omitempty"`
	KeyID       string              `json:"keyId,omitempty"`
	Attestation string              `json:"attestation,omitempty"`
	Verdict     *attestationVerdict `json:"verdict,omitempty"`
}

// expectedNonce recomputes the SDK-side request binding from the envelope.
func expectedNonce(sessionID, installID string) string {
	d := sha256.Sum256([]byte(sessionID + "|" + installID))
	return base64.RawURLEncoding.EncodeToString(d[:])
}

func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// ---------- per-tenant attestation config ----------

type attestationConfig struct {
	PlayPackage    string
	PlaySA         []byte // decrypted service-account JSON; nil = none
	AppAttestAppID string
	AppAttestDev   bool
}

// attestationConfigFor resolves the tenant's attestation config, falling back
// to the env-global settings for anything the tenant has not set.
func (s *Server) attestationConfigFor(tenantID string) attestationConfig {
	cfg := attestationConfig{
		PlayPackage:    os.Getenv("PLAY_INTEGRITY_PACKAGE"),
		AppAttestAppID: os.Getenv("APP_ATTEST_APP_ID"),
		AppAttestDev:   os.Getenv("APP_ATTEST_ENV") == "development",
	}
	if path := os.Getenv("PLAY_INTEGRITY_CREDENTIALS_FILE"); path != "" {
		if raw, err := os.ReadFile(path); err == nil {
			cfg.PlaySA = raw
		}
	}
	if t, ok := s.getTenant(tenantID); ok {
		if t.PlayPackage != "" {
			cfg.PlayPackage = t.PlayPackage
		}
		if len(t.PlaySA) > 0 {
			cfg.PlaySA = t.PlaySA
		}
		if t.AppAttestAppID != "" {
			cfg.AppAttestAppID = t.AppAttestAppID
			cfg.AppAttestDev = t.AppAttestDev
		}
	}
	return cfg
}

// ---------- Play Integrity: Google service-account OAuth (std-lib only) ----------

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

// Verifiers are cached per (tenant, package, credential fingerprint) so a
// rotated credential or changed package builds a fresh one.
var (
	playCacheMu sync.Mutex
	playCache   = map[string]*playIntegrityVerifier{}
)

func playVerifierFor(cfg attestationConfig) *playIntegrityVerifier {
	if len(cfg.PlaySA) == 0 || cfg.PlayPackage == "" {
		return nil
	}
	fp := sha256.Sum256(cfg.PlaySA)
	key := cfg.PlayPackage + "|" + b64url(fp[:8])
	playCacheMu.Lock()
	defer playCacheMu.Unlock()
	if v, ok := playCache[key]; ok {
		return v
	}
	v, err := newPlayIntegrityVerifier(cfg.PlaySA, cfg.PlayPackage)
	if err != nil {
		log.Printf("play integrity: credentials unusable for %s: %v", cfg.PlayPackage, err)
		playCache[key] = nil
		return nil
	}
	playCache[key] = v
	return v
}

func newPlayIntegrityVerifier(saJSON []byte, pkg string) (*playIntegrityVerifier, error) {
	var sa struct {
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
		TokenURI    string `json:"token_uri"`
	}
	if err := json.Unmarshal(saJSON, &sa); err != nil {
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

func verifyPlay(ctx context.Context, cfg attestationConfig, p *attestationPayload, sessionID, installID string) *attestationVerdict {
	verdict := &attestationVerdict{}
	v := playVerifierFor(cfg)
	if v == nil {
		verdict.Reason = "verification not configured"
		return verdict
	}
	vctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	decoded, err := v.decode(vctx, p.Token)
	cancel()
	if err != nil {
		verdict.Reason = "decode failed: " + err.Error()
		return verdict
	}
	verdict.Verified = true
	verdict.NonceOK = decoded.RequestDetails.Nonce == expectedNonce(sessionID, installID)
	verdict.DeviceVerdicts = decoded.DeviceIntegrity.DeviceRecognitionVerdict
	verdict.AppVerdict = decoded.AppIntegrity.AppRecognitionVerdict
	verdict.LicenseVerdict = decoded.AccountDetails.AppLicensingVerdict
	switch {
	case !verdict.NonceOK:
		verdict.Fail = "nonce mismatch (possible token replay)"
	case !hasVerdict(verdict.DeviceVerdicts, "MEETS_DEVICE_INTEGRITY"):
		verdict.Fail = "device verdict: " + strings.Join(verdict.DeviceVerdicts, ",")
	case verdict.AppVerdict != "PLAY_RECOGNIZED":
		verdict.Fail = "app verdict: " + verdict.AppVerdict
	}
	return verdict
}

// ---------- App Attest: local verification (std-lib only) ----------

// Apple App Attestation Root CA (apple.com/certificateauthority), exp. 2045.
const appleAppAttestRootPEM = `-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----`

var appleRootPool = func() *x509.CertPool {
	p := x509.NewCertPool()
	p.AppendCertsFromPEM([]byte(appleAppAttestRootPEM))
	return p
}()

// credCertNonceOID is the credential-certificate extension carrying the
// composite nonce: 1.2.840.113635.100.8.2.
var credCertNonceOID = []int{1, 2, 840, 113635, 100, 8, 2}

var (
	aaguidProd = append([]byte("appattest"), 0, 0, 0, 0, 0, 0, 0)
	aaguidDev  = []byte("appattestdevelop")
)

// verifyAppAttest checks an App Attest attestation object per Apple's
// documented steps: CBOR shape, certificate chain to Apple's root, composite
// nonce (SHA-256(authData || clientDataHash)) in the credential certificate,
// key id = SHA-256(credential public key), and authenticator data (App ID
// hash, counter 0, aaguid environment, credential id).
func verifyAppAttest(cfg attestationConfig, p *attestationPayload, challenge string) *attestationVerdict {
	verdict := &attestationVerdict{}
	if cfg.AppAttestAppID == "" {
		verdict.Reason = "verification not configured"
		return verdict
	}
	blob, err := base64.StdEncoding.DecodeString(p.Attestation)
	if err != nil {
		verdict.Reason = "attestation not base64"
		return verdict
	}
	obj, err := cborDecode(blob)
	if err != nil {
		verdict.Reason = "cbor: " + err.Error()
		return verdict
	}
	m, _ := obj.(map[string]any)
	fmtStr, _ := m["fmt"].(string)
	attStmt, _ := m["attStmt"].(map[string]any)
	authData, _ := m["authData"].([]byte)
	if fmtStr != "apple-appattest" || attStmt == nil || len(authData) < 55 {
		verdict.Reason = "not an apple-appattest object"
		return verdict
	}
	x5c, _ := attStmt["x5c"].([]any)
	if len(x5c) < 2 {
		verdict.Reason = "x5c chain too short"
		return verdict
	}
	credDER, _ := x5c[0].([]byte)
	credCert, err := x509.ParseCertificate(credDER)
	if err != nil {
		verdict.Reason = "credCert parse: " + err.Error()
		return verdict
	}
	inters := x509.NewCertPool()
	for _, c := range x5c[1:] {
		der, _ := c.([]byte)
		if ic, err := x509.ParseCertificate(der); err == nil {
			inters.AddCert(ic)
		}
	}

	// From here on, problems are FAILURES (verification ran), not reasons.
	verdict.Verified = true
	fail := func(f string) *attestationVerdict { verdict.Fail = f; return verdict }

	if _, err := credCert.Verify(x509.VerifyOptions{
		Roots: appleRootPool, Intermediates: inters,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fail("chain: " + err.Error())
	}

	// Composite nonce binds the attestation to our session challenge.
	clientDataHash := sha256.Sum256([]byte(challenge))
	composite := sha256.Sum256(append(append([]byte{}, authData...), clientDataHash[:]...))
	nonceOK := false
	for _, ext := range credCert.Extensions {
		if !oidEqual(ext.Id, credCertNonceOID) {
			continue
		}
		// The extension wraps the 32-byte nonce in a small DER structure;
		// match the octet-string content rather than re-parsing the ASN.1.
		if bytes.Contains(ext.Value, composite[:]) {
			nonceOK = true
		}
	}
	verdict.NonceOK = nonceOK
	if !nonceOK {
		return fail("composite nonce mismatch (possible replay)")
	}

	// Key id = SHA-256 of the credential public key (X9.62 uncompressed).
	ec, ok := credCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fail("credential key is not ECDSA")
	}
	pub := elliptic.Marshal(ec.Curve, ec.X, ec.Y)
	keyID := sha256.Sum256(pub)
	if base64.StdEncoding.EncodeToString(keyID[:]) != p.KeyID {
		return fail("keyId mismatch")
	}

	// Authenticator data: rpIdHash | flags(1) | counter(4) | aaguid(16) |
	// credIdLen(2) | credId.
	appIDHash := sha256.Sum256([]byte(cfg.AppAttestAppID))
	if !bytes.Equal(authData[:32], appIDHash[:]) {
		return fail("app id hash mismatch")
	}
	if counter := uint32(authData[33])<<24 | uint32(authData[34])<<16 |
		uint32(authData[35])<<8 | uint32(authData[36]); counter != 0 {
		return fail(fmt.Sprintf("counter %d at attestation", counter))
	}
	aaguid := authData[37:53]
	switch {
	case bytes.Equal(aaguid, aaguidProd):
		verdict.Environment = "production"
	case bytes.Equal(aaguid, aaguidDev):
		verdict.Environment = "development"
		if !cfg.AppAttestDev {
			return fail("development-environment attestation on a production tenant")
		}
	default:
		return fail("unknown aaguid")
	}
	credIDLen := int(authData[53])<<8 | int(authData[54])
	if 55+credIDLen > len(authData) || !bytes.Equal(authData[55:55+credIDLen], keyID[:]) {
		return fail("credential id mismatch")
	}
	verdict.AppVerdict = "APP_ATTEST_" + strings.ToUpper(verdict.Environment)
	return verdict
}

func oidEqual(oid []int, want []int) bool {
	if len(oid) != len(want) {
		return false
	}
	for i := range oid {
		if oid[i] != want[i] {
			return false
		}
	}
	return true
}

// ---------- minimal CBOR decoder ----------
//
// Decodes exactly the subset an App Attest attestation object uses: definite-
// length maps with text keys, byte strings, text strings, arrays, and small
// unsigned integers. Anything else is an error — this is a validator's
// decoder, not a general one.

func cborDecode(b []byte) (any, error) {
	v, rest, err := cborItem(b)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("trailing bytes")
	}
	return v, nil
}

func cborHead(b []byte) (major byte, length uint64, rest []byte, err error) {
	if len(b) == 0 {
		return 0, 0, nil, errors.New("truncated")
	}
	major = b[0] >> 5
	info := b[0] & 0x1f
	rest = b[1:]
	switch {
	case info < 24:
		return major, uint64(info), rest, nil
	case info == 24, info == 25, info == 26, info == 27:
		n := 1 << (info - 24)
		if len(rest) < n {
			return 0, 0, nil, errors.New("truncated length")
		}
		length = 0
		for i := 0; i < n; i++ {
			length = length<<8 | uint64(rest[i])
		}
		return major, length, rest[n:], nil
	default:
		return 0, 0, nil, errors.New("indefinite/reserved length")
	}
}

func cborItem(b []byte) (any, []byte, error) {
	major, n, rest, err := cborHead(b)
	if err != nil {
		return nil, nil, err
	}
	switch major {
	case 0: // unsigned int
		return n, rest, nil
	case 2: // byte string
		if uint64(len(rest)) < n {
			return nil, nil, errors.New("truncated bytes")
		}
		return append([]byte{}, rest[:n]...), rest[n:], nil
	case 3: // text string
		if uint64(len(rest)) < n {
			return nil, nil, errors.New("truncated text")
		}
		return string(rest[:n]), rest[n:], nil
	case 4: // array
		out := make([]any, 0, n)
		for i := uint64(0); i < n; i++ {
			var v any
			v, rest, err = cborItem(rest)
			if err != nil {
				return nil, nil, err
			}
			out = append(out, v)
		}
		return out, rest, nil
	case 5: // map (text keys only)
		out := make(map[string]any, n)
		for i := uint64(0); i < n; i++ {
			var k, v any
			k, rest, err = cborItem(rest)
			if err != nil {
				return nil, nil, err
			}
			ks, ok := k.(string)
			if !ok {
				return nil, nil, errors.New("non-text map key")
			}
			v, rest, err = cborItem(rest)
			if err != nil {
				return nil, nil, err
			}
			out[ks] = v
		}
		return out, rest, nil
	default:
		return nil, nil, fmt.Errorf("unsupported major type %d", major)
	}
}

// ---------- ingest hook ----------

// verifyAttestations verifies attestation events in the batch against the
// tenant's configuration and embeds the verdict into each event's payload
// before storage.
func (s *Server) verifyAttestations(ctx context.Context, tenantID string, events []IngestEvent) {
	var cfg *attestationConfig
	for i := range events {
		e := &events[i]
		if e.Type != "PASSIVE_ATTESTATION" {
			continue
		}
		var p attestationPayload
		if json.Unmarshal(e.Payload, &p) != nil {
			continue
		}
		if p.Status != "OK" {
			continue
		}
		if cfg == nil {
			c := s.attestationConfigFor(tenantID)
			cfg = &c
		}
		switch {
		case p.Provider == "PLAY_INTEGRITY" && p.Token != "":
			p.Verdict = verifyPlay(ctx, *cfg, &p, e.SessionID, e.InstallID)
			p.Token = "" // decoded; no need to store the raw token
		case p.Provider == "APP_ATTEST" && p.Attestation != "":
			p.Verdict = verifyAppAttest(*cfg, &p, expectedNonce(e.SessionID, e.InstallID))
			p.Attestation = "" // verified; the blob is large and spent
		default:
			continue
		}
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
