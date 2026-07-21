// Fraud ingest server — Go port of ../fraud-ingest-server (Node).
// Same Postgres schema, same wire contracts (HMAC gzip NDJSON ingest,
// bank feed, session-token scoring, console API with analyst RBAC,
// action channel). Conformance criterion: the Node simulator passes
// unchanged:  node ../fraud-ingest-server/simulate-sdk.js all <baseUrl>
package main

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schemaSQL string

// Tenant config and versioned HMAC keys live in Postgres (see tenants.go);
// the in-memory map is a cache, refreshed periodically and on auth misses.
type Server struct {
	pool           *pgxpool.Pool
	tenantMu       sync.RWMutex
	tenants        map[string]Tenant
	lastTenantLoad time.Time
	consoleKeys    map[string]string // machine/service keys -> tenant
	corsOrigins    map[string]bool   // allowed browser origins for /v1/console/*
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	ctx := context.Background()
	dbURL := env("DATABASE_URL", "postgres://localhost/vera_fraud")

	// Fail fast and loud: PaaS port scanners (Render etc.) only see a healthy
	// service once ListenAndServe runs, so a silent hang on an unreachable DB
	// looks like "no open ports" with no clue. pgx has NO connect timeout by
	// default — set one, and log the target (never the credentials).
	dbCfg, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		log.Fatalf("DATABASE_URL: %v", err)
	}
	if dbCfg.ConnConfig.ConnectTimeout == 0 {
		dbCfg.ConnConfig.ConnectTimeout = 10 * time.Second
	}
	log.Printf("Connecting to Postgres at %s:%d/%s …",
		dbCfg.ConnConfig.Host, dbCfg.ConnConfig.Port, dbCfg.ConnConfig.Database)
	pool, err := pgxpool.NewWithConfig(ctx, dbCfg)
	if err != nil {
		log.Fatalf("db pool: %v", err)
	}
	if _, err := pool.Exec(ctx, schemaSQL); err != nil {
		log.Fatalf("schema apply failed — is Postgres reachable and the db created? %v", err)
	}
	log.Printf("Postgres OK, schema applied")

	s := &Server{
		pool:    pool,
		tenants: map[string]Tenant{},
		consoleKeys: map[string]string{
			env("CONSOLE_KEY", "dev-console-key"): "wallet-acme",
		},
		corsOrigins: map[string]bool{},
	}

	// Operator CLI: `vera-go tenant create|list|rotate-key|revoke-key …`
	if len(os.Args) > 1 && os.Args[1] == "tenant" {
		if err := runTenantCLI(pool, os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}

	if err := s.seedTenant(ctx); err != nil {
		log.Fatalf("tenant seed: %v", err)
	}
	if err := s.loadTenants(ctx); err != nil {
		log.Fatalf("tenant load: %v", err)
	}
	go s.tenantRefresher(ctx)
	// CORS_ORIGIN may be a comma-separated list; Vite dev is 5199 or 5173.
	for _, o := range strings.Split(env("CORS_ORIGIN", "http://localhost:5199,http://localhost:5173"), ",") {
		if o = strings.TrimSpace(o); o != "" {
			s.corsOrigins[o] = true
		}
	}

	adminEmail := env("CONSOLE_ADMIN_EMAIL", "admin@demobank.cz")
	seeded, err := s.seedAdmin(ctx, "wallet-acme", adminEmail,
		env("CONSOLE_ADMIN_PASSWORD", "admin-dev-password"))
	if err != nil {
		log.Fatalf("admin seed: %v", err)
	}
	if seeded {
		log.Printf("Seeded bootstrap admin %s (password from CONSOLE_ADMIN_PASSWORD)", adminEmail)
	}

	// Outbox worker: replays webhook deliveries scheduled in Postgres.
	go s.webhookDispatcher(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.route)

	port := env("PORT", "8080")
	log.Printf("Fraud ingest server (Go) on http://localhost:%s", port)
	log.Printf("  POST /v1/events  /v1/transactions  /v1/score   GET /v1/console/*  /stats")
	log.Printf("  Tenants: %s  ->  %s", strings.Join(tenantIDs(s.tenants), ", "), dbURL)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

func tenantIDs(m map[string]Tenant) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("panic: %v", rec)
			writeJSON(w, 500, map[string]any{"error": "internal"})
		}
	}()
	path := r.URL.Path
	switch {
	case r.Method == "POST" && path == "/v1/events":
		s.handleEvents(w, r)
	case r.Method == "POST" && path == "/v1/transactions":
		s.handleTransactions(w, r)
	case r.Method == "POST" && path == "/v1/score":
		s.handleScore(w, r)
	case strings.HasPrefix(path, "/v1/collect"):
		// Browser SDK: public site-key + Origin auth, so CORS is required.
		// Echo the tenant's allowed origin; the site key is validated per-request.
		origin := r.Header.Get("Origin")
		if s.originAllowed(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Encoding, X-Tenant-Id, X-Site-Key, X-Install-Id, X-Sdk")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		switch {
		case r.Method == "POST" && path == "/v1/collect/token":
			s.handleCollectToken(w, r)
		case r.Method == "POST" && path == "/v1/collect":
			s.handleCollect(w, r)
		default:
			writeJSON(w, 404, map[string]any{"error": "not found"})
		}
	case strings.HasPrefix(path, "/v1/console/"):
		// CORS for the browser console (SDK/bank endpoints stay server-to-server).
		if origin := r.Header.Get("Origin"); s.corsOrigins[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		s.handleConsole(w, r)
	case r.Method == "GET" && path == "/stats":
		s.handleStats(w, r)
	default:
		writeJSON(w, 404, map[string]any{"error": "not found"})
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := jsonEncode(w, v); err != nil {
		fmt.Fprintf(os.Stderr, "json encode: %v\n", err)
	}
}
