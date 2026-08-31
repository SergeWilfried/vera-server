// Counterparty typing — what KIND of counterparty is this?
//
// Payee intelligence answers "is this payee known-bad?"; typing answers a
// different question, and the type is context, not verdict. Betting is
// legal, crypto P2P is mostly remittances — so the score-time signals are
// deliberately low-weight corroboration (the VPN_ACTIVE philosophy), and
// the real detections live in the ledger ratios: gambling outflow as a
// share of inflow (typology #32's reasoning without needing declared
// income) and crypto inflow concentration (#31 made countable).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

var counterpartyCategories = map[string]bool{
	"GAMBLING": true, "CRYPTO_P2P": true, "INFORMAL_FX": true, "BENIGN": true,
}

// ---------- registry ----------

func (s *Server) listCounterpartyTypes(ctx context.Context, tenantID string) ([]map[string]any, error) {
	return queryMaps(ctx, s.pool,
		`SELECT counterparty_ref, category, label, source, created_by, created_at
		 FROM counterparty_types WHERE tenant_id=$1
		 ORDER BY created_at DESC LIMIT 500`, tenantID)
}

func (s *Server) upsertCounterpartyType(ctx context.Context, tenantID, ref, category, label, source, by string) error {
	category = strings.ToUpper(strings.TrimSpace(category))
	if !counterpartyCategories[category] {
		return fmt.Errorf("unknown category %q (GAMBLING | CRYPTO_P2P | INFORMAL_FX | BENIGN)", category)
	}
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return fmt.Errorf("counterpartyRef is required")
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO counterparty_types (tenant_id, counterparty_ref, category, label, source, created_by)
		 VALUES ($1,$2,$3,$4,$5,$6)
		 ON CONFLICT (tenant_id, counterparty_ref)
		 DO UPDATE SET category=$3, label=$4, source=$5, created_by=$6, created_at=now()`,
		tenantID, ref, category, strings.TrimSpace(label), source, by)
	return err
}

func (s *Server) deleteCounterpartyType(ctx context.Context, tenantID, ref string) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM counterparty_types WHERE tenant_id=$1 AND counterparty_ref=$2`, tenantID, ref)
	return err == nil && tag.RowsAffected() > 0, err
}

// counterpartyCategory resolves one ref at score time. "" = untyped.
func (s *Server) counterpartyCategory(ctx context.Context, tenantID, ref string) string {
	if ref == "" {
		return ""
	}
	var cat string
	_ = s.pool.QueryRow(ctx,
		`SELECT category FROM counterparty_types
		 WHERE tenant_id=$1 AND counterparty_ref=$2`, tenantID, ref).Scan(&cat)
	return cat
}

// ---------- ledger ratio checks (feed ingest, advisory) ----------

// counterpartyFlowSettings resolves tenant_settings.risk.counterpartyFlows.
type counterpartyFlowSettings struct {
	enabled bool
	// gambling outflow / total inflow over the window fires above this
	gamblingRatio float64
	// crypto-typed inflow / total inflow fires above this
	cryptoRatio float64
	windowDays  int
	// currency-free floor: at least this many typed transactions in the
	// window, so one stray bet cannot trip a ratio on a quiet account
	minTypedTxns int
	cooldownDays int
}

func (s *Server) resolveCounterpartyFlows(ctx context.Context, tenantID string) counterpartyFlowSettings {
	c := counterpartyFlowSettings{
		enabled: true, gamblingRatio: 0.4, cryptoRatio: 0.5,
		windowDays: 30, minTypedTxns: 3, cooldownDays: 30,
	}
	var raw []byte
	if err := s.pool.QueryRow(ctx,
		`SELECT settings FROM tenant_settings WHERE tenant_id=$1`, tenantID).Scan(&raw); err != nil || len(raw) == 0 {
		return c
	}
	stored := map[string]any{}
	if json.Unmarshal(raw, &stored) != nil {
		return c
	}
	risk, _ := stored["risk"].(map[string]any)
	cfg, _ := risk["counterpartyFlows"].(map[string]any)
	if cfg == nil {
		return c
	}
	if v, ok := cfg["enabled"].(bool); ok {
		c.enabled = v
	}
	if f, ok := toFloat(cfg["gamblingRatio"]); ok && f > 0 && f <= 1 {
		c.gamblingRatio = f
	}
	if f, ok := toFloat(cfg["cryptoRatio"]); ok && f > 0 && f <= 1 {
		c.cryptoRatio = f
	}
	if f, ok := toFloat(cfg["windowDays"]); ok && f >= 7 {
		c.windowDays = int(f)
	}
	if f, ok := toFloat(cfg["minTypedTxns"]); ok && f > 0 {
		c.minTypedTxns = int(f)
	}
	if f, ok := toFloat(cfg["cooldownDays"]); ok && f > 0 {
		c.cooldownDays = int(f)
	}
	return c
}

// checkCounterpartyFlows evaluates one account after a feed batch. Advisory
// by contract: the alerts inform an analyst, they never hold a payment, and
// like KYC drift they run outside the fraud detector loop. Best-effort — a
// failure here must never break feed ingestion.
func (s *Server) checkCounterpartyFlows(ctx context.Context, tenantID, accountRef, userRef string) []string {
	cfg := s.resolveCounterpartyFlows(ctx, tenantID)
	if !cfg.enabled {
		return nil
	}

	// Cooldown: one Counterparty Exposure alert per account per window,
	// whatever its state.
	var recent int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM alerts
		 WHERE tenant_id=$1 AND account_ref=$2 AND threat_type='Counterparty Exposure'
		   AND created_at > now() - ($3 || ' days')::interval`,
		tenantID, accountRef, fmt.Sprint(cfg.cooldownDays)).Scan(&recent); err != nil || recent > 0 {
		return nil
	}

	// One pass over the window: totals plus typed slices, joined against the
	// registry. Counts let the floor stay currency-free.
	var inflow, gamblingOut, cryptoIn float64
	var gamblingOutN, cryptoInN int
	if err := s.pool.QueryRow(ctx, `
		SELECT
		  coalesce(sum(t.amount) FILTER (WHERE t.direction='IN'), 0),
		  coalesce(sum(t.amount) FILTER (WHERE t.direction='OUT' AND ct.category='GAMBLING'), 0),
		  count(*)               FILTER (WHERE t.direction='OUT' AND ct.category='GAMBLING'),
		  coalesce(sum(t.amount) FILTER (WHERE t.direction='IN'  AND ct.category='CRYPTO_P2P'), 0),
		  count(*)               FILTER (WHERE t.direction='IN'  AND ct.category='CRYPTO_P2P')
		FROM bank_txns t
		LEFT JOIN counterparty_types ct
		  ON ct.tenant_id = t.tenant_id AND ct.counterparty_ref = t.counterparty_ref
		WHERE t.tenant_id=$1 AND t.account_ref=$2
		  AND t.ts > now() - ($3 || ' days')::interval`,
		tenantID, accountRef, fmt.Sprint(cfg.windowDays)).
		Scan(&inflow, &gamblingOut, &gamblingOutN, &cryptoIn, &cryptoInN); err != nil || inflow <= 0 {
		return nil
	}

	var signals []Signal
	if gamblingOutN >= cfg.minTypedTxns && gamblingOut >= cfg.gamblingRatio*inflow {
		signals = append(signals, Signal{
			Code: "GAMBLING_FLOW", Label: "Outflow concentrated on gambling counterparties", Weight: 25,
			Evidence: fmt.Sprintf("%s to %d gambling-typed txns = %.0f%% of %dd inflow (%s)",
				compactAmount(gamblingOut), gamblingOutN, 100*gamblingOut/inflow, cfg.windowDays, compactAmount(inflow)),
		})
	}
	if cryptoInN >= cfg.minTypedTxns && cryptoIn >= cfg.cryptoRatio*inflow {
		signals = append(signals, Signal{
			Code: "CRYPTO_INFLOW_CONCENTRATION", Label: "Inflow concentrated from crypto P2P counterparties", Weight: 25,
			Evidence: fmt.Sprintf("%s over %d crypto-typed txns = %.0f%% of %dd inflow",
				compactAmount(cryptoIn), cryptoInN, 100*cryptoIn/inflow, cfg.windowDays),
		})
	}
	if len(signals) == 0 {
		return nil
	}

	alertID, err := s.raiseAlert(ctx, tenantID, AlertDraft{
		AccountRef: accountRef, UserRef: userRef,
		Score:      45,
		ThreatType: "Counterparty Exposure",
		Signal:     signals[0].Label,
		Signals:    signals,
		Txn: map[string]any{"accountRef": accountRef, "windowDays": cfg.windowDays,
			"inflow": inflow, "gamblingOut": gamblingOut, "cryptoIn": cryptoIn},
	})
	if err != nil {
		log.Printf("counterparty-exposure raiseAlert: %v", err)
		return nil
	}
	return []string{alertID}
}
