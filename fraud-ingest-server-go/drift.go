// KYC drift — the behavioral trigger for perpetual KYC.
//
// Typology: an account's observed behavior departs its declared profile
// while the KYC file stays untouched ("les dépôts passent de 10 à 34
// millions, le KYC n'a pas été actualisé"). Periodic reviews miss it by
// construction; the ledger sees it as it happens.
//
// This is deliberately NOT a fraud signal. Drift raises an advisory alert
// (threat type "KYC Drift", modest fixed score) plus a KYC_REVIEW action
// that rides the existing webhook outbox into the bank's own review
// workflow. It never holds payments and never gates on the fraud bands —
// the drifted customer is usually legitimate; the point is that the bank's
// file about them no longer is.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
)

// driftSettings resolves tenant_settings.risk.kycDrift with defaults.
type driftSettings struct {
	enabled bool
	// recent inflow must exceed ratio × the baseline's per-window inflow
	ratio float64
	// recent window (days) compared against the baseline window before it
	windowDays, baselineDays int
	// baseline maturity: fewer inflows than this and the account is NEW,
	// not drifted — novelty is QUIET_ACCOUNT / NEW_INSTALL territory
	minBaselineTxns int
	// one drift alert per account per cooldown, whatever its state — a
	// drifted account stays drifted; re-alerting weekly is noise
	cooldownDays int
}

func (s *Server) resolveDrift(ctx context.Context, tenantID string) driftSettings {
	d := driftSettings{
		enabled: true, ratio: 2.5,
		windowDays: 30, baselineDays: 90,
		minBaselineTxns: 5, cooldownDays: 90,
	}
	var raw []byte
	if err := s.pool.QueryRow(ctx,
		`SELECT settings FROM tenant_settings WHERE tenant_id=$1`, tenantID).Scan(&raw); err != nil || len(raw) == 0 {
		return d
	}
	stored := map[string]any{}
	if json.Unmarshal(raw, &stored) != nil {
		return d
	}
	risk, _ := stored["risk"].(map[string]any)
	cfg, _ := risk["kycDrift"].(map[string]any)
	if cfg == nil {
		return d
	}
	if v, ok := cfg["enabled"].(bool); ok {
		d.enabled = v
	}
	if f, ok := toFloat(cfg["ratio"]); ok && f > 1 {
		d.ratio = f
	}
	if f, ok := toFloat(cfg["windowDays"]); ok && f >= 7 {
		d.windowDays = int(f)
	}
	if f, ok := toFloat(cfg["baselineDays"]); ok && f >= 30 {
		d.baselineDays = int(f)
	}
	if f, ok := toFloat(cfg["minBaselineTxns"]); ok && f > 0 {
		d.minBaselineTxns = int(f)
	}
	if f, ok := toFloat(cfg["cooldownDays"]); ok && f > 0 {
		d.cooldownDays = int(f)
	}
	return d
}

// checkKycDrift evaluates one account after a feed batch and raises the
// advisory alert + KYC_REVIEW action when sustained inflow departs the
// learned baseline. Best-effort by design: a drift failure must never
// break feed ingestion.
func (s *Server) checkKycDrift(ctx context.Context, tenantID, accountRef, userRef string) (string, bool) {
	cfg := s.resolveDrift(ctx, tenantID)
	if !cfg.enabled {
		return "", false
	}

	// Cooldown: any prior drift alert for this account inside the window —
	// open, resolved or dismissed — suppresses a new one.
	var recentAlerts int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM alerts
		 WHERE tenant_id=$1 AND account_ref=$2 AND threat_type='KYC Drift'
		   AND created_at > now() - ($3 || ' days')::interval`,
		tenantID, accountRef, fmt.Sprint(cfg.cooldownDays)).Scan(&recentAlerts); err != nil || recentAlerts > 0 {
		return "", false
	}

	// Inflow in the recent window vs. the baseline window before it,
	// normalized to the same length so the ratio compares like with like.
	var recentSum, baseSum float64
	var baseCount int
	if err := s.pool.QueryRow(ctx, `
		SELECT
		  coalesce(sum(amount) FILTER (WHERE ts >  now() - ($3 || ' days')::interval), 0),
		  coalesce(sum(amount) FILTER (WHERE ts <= now() - ($3 || ' days')::interval), 0),
		  count(*)             FILTER (WHERE ts <= now() - ($3 || ' days')::interval)
		FROM bank_txns
		WHERE tenant_id=$1 AND account_ref=$2 AND direction='IN'
		  AND ts > now() - (($3::int + $4::int) || ' days')::interval`,
		tenantID, accountRef, fmt.Sprint(cfg.windowDays), fmt.Sprint(cfg.baselineDays)).
		Scan(&recentSum, &baseSum, &baseCount); err != nil {
		return "", false
	}
	if baseCount < cfg.minBaselineTxns || baseSum <= 0 {
		return "", false // too new to have drifted
	}
	basePerWindow := baseSum * float64(cfg.windowDays) / float64(cfg.baselineDays)
	if basePerWindow <= 0 || recentSum < cfg.ratio*basePerWindow {
		return "", false
	}

	ratio := recentSum / basePerWindow
	evidence := fmt.Sprintf("inflow %s over %dd vs. %s/window learned from the prior %dd (×%.1f)",
		compactAmount(recentSum), cfg.windowDays, compactAmount(basePerWindow), cfg.baselineDays, ratio)

	alertID, err := s.raiseAlert(ctx, tenantID, AlertDraft{
		AccountRef: accountRef, UserRef: userRef,
		// Fixed advisory score: visible in the queue, sorted below fraud
		// under the risk sort, and never near the hold band.
		Score:      40,
		ThreatType: "KYC Drift",
		Signal:     "Observed behavior departed the declared profile",
		Signals: []Signal{{
			Code: "KYC_DRIFT", Label: "Sustained inflow above learned profile",
			Weight: 40, Evidence: evidence,
		}},
		Txn: map[string]any{
			"accountRef": accountRef,
			"recentIn":   recentSum, "baselinePerWindow": basePerWindow,
			"ratio": ratio, "windowDays": cfg.windowDays,
		},
	})
	if err != nil {
		return "", false
	}

	// The re-KYC trigger itself: a KYC_REVIEW action on the alert, delivered
	// to the bank's workflow over the same outbox (retries, backoff, audit)
	// as every containment action.
	if _, refusal, err := s.createAction(ctx, tenantID, alertID,
		"KYC_REVIEW", evidence, "system:kyc-drift"); err != nil || refusal != "" {
		// The alert still stands for analysts even if the webhook leg failed.
		log.Printf("kyc-drift action for %s: err=%v refusal=%q", alertID, err, refusal)
	}
	return alertID, true
}

// compactAmount renders 34200000 as "34.2M" — evidence strings are read by
// humans in a table cell, not parsed.
func compactAmount(v float64) string {
	switch {
	case v >= 1e9:
		return fmt.Sprintf("%.1fB", v/1e9)
	case v >= 1e6:
		return fmt.Sprintf("%.1fM", v/1e6)
	case v >= 1e3:
		return fmt.Sprintf("%.0fk", v/1e3)
	default:
		return fmt.Sprintf("%.0f", v)
	}
}
