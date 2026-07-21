// Per-tenant key management. Tenant config and versioned HMAC keys live in
// Postgres (keys AES-GCM-encrypted under MASTER_KEY); the server keeps a
// read-through cache refreshed on a ticker and — rate-limited — on auth
// misses, so a key rotated via the CLI takes effect on a running server
// without a restart. Signing always uses the tenant's single 'active' key;
// verification accepts 'active' + 'retiring' (zero-downtime rotation for
// SDK fleets that upgrade slowly).
package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type TenantKey struct {
	Kid   string
	Key   []byte
	State string // active | retiring
}

// Tenant is the cached, decrypted view of one tenant's config.
type Tenant struct {
	ID             string
	Name           string
	Webhook        string
	SiteKey        string
	AllowedOrigins []string
	Keys           []TenantKey // active first
}

// activeKey returns the signing key (mint tokens, sign webhooks).
func (t Tenant) activeKey() (TenantKey, bool) {
	for _, k := range t.Keys {
		if k.State == "active" {
			return k, true
		}
	}
	return TenantKey{}, false
}

// ---------- master-key envelope encryption ----------

// masterKey derives the 32-byte AES key from MASTER_KEY. The env var is the
// dev/bootstrap tier; production swaps it for a KMS-wrapped secret without
// touching the table schema (the point of envelope encryption).
func masterKey() []byte {
	h := sha256.Sum256([]byte(env("MASTER_KEY", "dev-master-key-not-for-prod")))
	return h[:]
}

func encryptKey(plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey())
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return append(nonce, gcm.Seal(nil, nonce, plain, nil)...), nil
}

func decryptKey(enc []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey())
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(enc) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return gcm.Open(nil, enc[:gcm.NonceSize()], enc[gcm.NonceSize():], nil)
}

// ---------- cache ----------

func (s *Server) loadTenants(ctx context.Context) error {
	rows, err := queryMaps(ctx, s.pool,
		`SELECT id, name, coalesce(webhook_url,'') AS webhook_url,
		        coalesce(site_key,'') AS site_key,
		        coalesce(allowed_origins,'') AS allowed_origins
		 FROM tenants WHERE status='active'`)
	if err != nil {
		return err
	}
	out := map[string]Tenant{}
	for _, r := range rows {
		id, _ := r["id"].(string)
		name, _ := r["name"].(string)
		webhook, _ := r["webhook_url"].(string)
		siteKey, _ := r["site_key"].(string)
		originsCSV, _ := r["allowed_origins"].(string)
		var origins []string
		for _, o := range strings.Split(originsCSV, ",") {
			if o = strings.TrimSpace(o); o != "" {
				origins = append(origins, o)
			}
		}
		out[id] = Tenant{ID: id, Name: name, Webhook: webhook,
			SiteKey: siteKey, AllowedOrigins: origins}
	}

	keyRows, err := queryMaps(ctx, s.pool,
		`SELECT tenant_id, kid, key_enc, state FROM tenant_keys
		 WHERE state IN ('active','retiring')
		 ORDER BY (state='active') DESC, created_at DESC`)
	if err != nil {
		return err
	}
	for _, r := range keyRows {
		tid, _ := r["tenant_id"].(string)
		t, ok := out[tid]
		if !ok {
			continue
		}
		enc, _ := r["key_enc"].([]byte)
		key, derr := decryptKey(enc)
		if derr != nil {
			log.Printf("tenant %s key %v: decrypt failed (wrong MASTER_KEY?): %v",
				tid, r["kid"], derr)
			continue
		}
		kid, _ := r["kid"].(string)
		state, _ := r["state"].(string)
		t.Keys = append(t.Keys, TenantKey{Kid: kid, Key: key, State: state})
		out[tid] = t
	}

	s.tenantMu.Lock()
	s.tenants = out
	s.lastTenantLoad = time.Now()
	s.tenantMu.Unlock()
	return nil
}

func (s *Server) getTenant(id string) (Tenant, bool) {
	s.tenantMu.RLock()
	t, ok := s.tenants[id]
	stale := time.Since(s.lastTenantLoad) > 5*time.Second
	s.tenantMu.RUnlock()
	// Bounded staleness: auth config (and crucially key REVOCATION, which
	// never trips a signature failure) is at most ~5s stale under traffic.
	if (!ok || stale) && s.tryReloadTenants() {
		s.tenantMu.RLock()
		t, ok = s.tenants[id]
		s.tenantMu.RUnlock()
	}
	return t, ok
}

// tryReloadTenants force-refreshes the cache, rate-limited to once per
// second — the auth-miss path calls this so a just-rotated or just-created
// tenant works immediately.
func (s *Server) tryReloadTenants() bool {
	s.tenantMu.RLock()
	recent := time.Since(s.lastTenantLoad) < time.Second
	s.tenantMu.RUnlock()
	if recent {
		return false
	}
	if err := s.loadTenants(context.Background()); err != nil {
		log.Printf("tenant reload: %v", err)
		return false
	}
	return true
}

func (s *Server) tenantRefresher(ctx context.Context) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if err := s.loadTenants(ctx); err != nil {
				log.Printf("tenant refresh: %v", err)
			}
		}
	}
}

// verifyTenantSig checks an HMAC signature against every live key version
// (active + retiring), reloading the cache once on failure so rotations
// apply without a restart.
func (s *Server) verifyTenantSig(tenantID string, body []byte, sigB64 string) bool {
	check := func() bool {
		t, ok := s.getTenant(tenantID)
		if !ok {
			return false
		}
		for _, k := range t.Keys {
			if hmacEqual(k.Key, body, sigB64) {
				return true
			}
		}
		return false
	}
	if check() {
		return true
	}
	if s.tryReloadTenants() {
		return check()
	}
	return false
}

// ---------- seeding (dev bootstrap) ----------

// seedTenant keeps the dev tenant + simulator working out of the box:
// config columns fill only when NULL (CLI edits win), and the env SDK key
// becomes key 'k1' only when the tenant has no keys at all.
func (s *Server) seedTenant(ctx context.Context) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO tenants (id, name, webhook_url, site_key, allowed_origins)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (id) DO UPDATE SET
		   webhook_url     = COALESCE(tenants.webhook_url, EXCLUDED.webhook_url),
		   site_key        = COALESCE(tenants.site_key, EXCLUDED.site_key),
		   allowed_origins = COALESCE(tenants.allowed_origins, EXCLUDED.allowed_origins)`,
		"wallet-acme", "Wallet Acme (dev)",
		env("CORE_WEBHOOK", "http://localhost:8090/core-banking/hooks"),
		env("SITE_KEY", "site_wallet-acme_pub"),
		env("SITE_ORIGINS", "http://localhost:5199,http://localhost:5173,http://localhost:8099"))
	if err != nil {
		return err
	}
	var n int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM tenant_keys WHERE tenant_id=$1`, "wallet-acme").Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		enc, err := encryptKey([]byte(env("SDK_KEY", "0123456789abcdef0123456789abcdef")))
		if err != nil {
			return err
		}
		if _, err := s.pool.Exec(ctx,
			`INSERT INTO tenant_keys (tenant_id, kid, key_enc, state)
			 VALUES ($1, 'k1', $2, 'active')`, "wallet-acme", enc); err != nil {
			return err
		}
	}
	return nil
}

// ---------- operator CLI ----------

// runTenantCLI implements `vera-go tenant <create|list|rotate-key|revoke-key>`.
// Operator actions are deliberately NOT console endpoints: tenant analysts
// manage their tenant, the platform operator manages tenants. Secrets print
// exactly once, at generation.
func runTenantCLI(pool *pgxpool.Pool, args []string) error {
	ctx := context.Background()
	if len(args) == 0 {
		return fmt.Errorf("usage: tenant <create|list|rotate-key|revoke-key> …")
	}
	newKeyHex := func() string {
		b := make([]byte, 16)
		rand.Read(b)
		return hex.EncodeToString(b) // 32 chars; its ASCII bytes are the HMAC key
	}
	newKid := func() string {
		b := make([]byte, 3)
		rand.Read(b)
		return "k" + hex.EncodeToString(b)
	}
	switch args[0] {
	case "create":
		if len(args) < 2 {
			return fmt.Errorf("usage: tenant create <id> [name] [webhook] [siteKey] [originsCSV]")
		}
		id := args[1]
		get := func(i int, def string) string {
			if len(args) > i && args[i] != "" {
				return args[i]
			}
			return def
		}
		name := get(2, id)
		webhook := get(3, "http://localhost:8090/core-banking/hooks")
		siteKey := get(4, "site_"+id+"_pub")
		origins := get(5, "")
		if _, err := pool.Exec(ctx,
			`INSERT INTO tenants (id, name, webhook_url, site_key, allowed_origins)
			 VALUES ($1, $2, $3, $4, NULLIF($5, ''))`,
			id, name, webhook, siteKey, origins); err != nil {
			return err
		}
		key := newKeyHex()
		enc, err := encryptKey([]byte(key))
		if err != nil {
			return err
		}
		kid := newKid()
		if _, err := pool.Exec(ctx,
			`INSERT INTO tenant_keys (tenant_id, kid, key_enc, state)
			 VALUES ($1, $2, $3, 'active')`, id, kid, enc); err != nil {
			return err
		}
		fmt.Printf("created tenant=%s siteKey=%s\nkid=%s key=%s\n(store the key now — it is not shown again)\n",
			id, siteKey, kid, key)
	case "list":
		rows, err := queryMaps(ctx, pool,
			`SELECT t.id, t.status, coalesce(t.site_key,'') AS site_key,
			        coalesce(string_agg(k.kid || ':' || k.state, ', ' ORDER BY k.created_at), '—') AS keys
			 FROM tenants t LEFT JOIN tenant_keys k ON k.tenant_id = t.id
			 GROUP BY t.id ORDER BY t.id`)
		if err != nil {
			return err
		}
		for _, r := range rows {
			fmt.Printf("%-20s %-8s site=%-24s keys: %s\n",
				r["id"], r["status"], r["site_key"], r["keys"])
		}
	case "rotate-key":
		if len(args) < 2 {
			return fmt.Errorf("usage: tenant rotate-key <id>")
		}
		id := args[1]
		if _, err := pool.Exec(ctx,
			`UPDATE tenant_keys SET state='retiring'
			 WHERE tenant_id=$1 AND state='active'`, id); err != nil {
			return err
		}
		key := newKeyHex()
		enc, err := encryptKey([]byte(key))
		if err != nil {
			return err
		}
		kid := newKid()
		if _, err := pool.Exec(ctx,
			`INSERT INTO tenant_keys (tenant_id, kid, key_enc, state)
			 VALUES ($1, $2, $3, 'active')`, id, kid, enc); err != nil {
			return err
		}
		fmt.Printf("rotated tenant=%s\nkid=%s key=%s\n(previous active key is now 'retiring' — still verifies; revoke it once the fleet upgrades)\n",
			id, kid, key)
	case "revoke-key":
		if len(args) < 3 {
			return fmt.Errorf("usage: tenant revoke-key <id> <kid>")
		}
		tag, err := pool.Exec(ctx,
			`UPDATE tenant_keys SET state='revoked'
			 WHERE tenant_id=$1 AND kid=$2`, args[1], args[2])
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("no such key %s/%s", args[1], args[2])
		}
		fmt.Printf("revoked tenant=%s kid=%s\n", args[1], args[2])
	default:
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
	return nil
}
