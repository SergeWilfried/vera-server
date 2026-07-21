// Follow-the-money graph: a two-hop link-analysis view seeded from one
// subject, built entirely from data the platform already holds (bank feed,
// alerts, cases, sessions). Never the full ledger — top counterparties by
// value, expanded one hop when a suspicious counterparty is also an
// in-book account, plus device-sharing links from the sessions table.
package main

import (
	"context"
	"fmt"
	"time"
)

type graphNode struct {
	ID     string           `json:"id"`
	Parent string           `json:"parent,omitempty"`
	Label  string           `json:"label"`
	Sub    string           `json:"sub"`
	Kind   string           `json:"kind"` // safe | warn | mule | intel | device
	Dir    string           `json:"dir"`  // in | out
	Amount string           `json:"amount"`
	Weight int              `json:"weight"`
	Stats  []map[string]any `json:"stats,omitempty"`
	Flags  []string         `json:"flags,omitempty"`
}

func fmtAmt(total float64, cur string) string {
	if cur == "" {
		cur = "—"
	}
	if total >= 1000 {
		return fmt.Sprintf("%.0fk %s", total/1000, cur)
	}
	return fmt.Sprintf("%.0f %s", total, cur)
}

func amtWeight(total float64) int {
	switch {
	case total >= 100000:
		return 3
	case total >= 10000:
		return 2
	}
	return 1
}

// classifyCounterparty ranks a counterparty by what the ledger already
// knows: open-alert match ('intel') > mule flow pattern ('mule') >
// recurring relationship ('safe') > new/unusual ('warn').
func (s *Server) classifyCounterparty(ctx context.Context, tenantID, cp string,
	txnCount int, firstSeen time.Time) (kind string, flags []string, inBook bool) {

	var openAlerts int
	s.pool.QueryRow(ctx,
		`SELECT count(*)::int FROM alerts
		 WHERE tenant_id=$1 AND account_ref=$2 AND state='Open'`,
		tenantID, cp).Scan(&openAlerts)

	var fanIn int
	s.pool.QueryRow(ctx,
		`SELECT count(DISTINCT user_ref)::int FROM bank_txns
		 WHERE tenant_id=$1 AND counterparty_ref=$2 AND direction='OUT'
		   AND user_ref IS NOT NULL`, tenantID, cp).Scan(&fanIn)

	s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM bank_txns WHERE tenant_id=$1 AND account_ref=$2)`,
		tenantID, cp).Scan(&inBook)

	muleFlow := false
	if inBook {
		if f, err := s.getAccountFlow(ctx, tenantID, cp); err == nil {
			muleFlow = f.In72 > 0 && f.Out24 >= 0.8*f.In72
		}
	}

	switch {
	case openAlerts > 0:
		kind = "intel"
		flags = append(flags, fmt.Sprintf("Matches %d open alert(s) on this book", openAlerts))
	case muleFlow:
		kind = "mule"
		flags = append(flags, "Rapid in-out flow pattern on the counterparty account")
	case txnCount >= 3 && time.Since(firstSeen) > 30*24*time.Hour:
		kind = "safe"
	default:
		kind = "warn"
		if time.Since(firstSeen) < 30*24*time.Hour {
			flags = append(flags, "First seen less than 30 days ago")
		}
	}
	if fanIn >= 2 {
		if kind == "safe" || kind == "warn" {
			kind = "mule"
		}
		flags = append(flags, fmt.Sprintf("Fan-in from %d distinct customers", fanIn))
	}
	return kind, flags, inBook
}

func (s *Server) getGraph(ctx context.Context, tenantID, userRef string) (map[string]any, error) {
	// ---- subject ---------------------------------------------------------
	var out30, in30 float64
	var txn30 int
	var cur string
	if err := s.pool.QueryRow(ctx,
		`SELECT coalesce(sum(amount) FILTER (WHERE direction='OUT'), 0)::float8,
		        coalesce(sum(amount) FILTER (WHERE direction='IN'), 0)::float8,
		        count(*)::int, coalesce(max(currency), '')
		 FROM bank_txns
		 WHERE tenant_id=$1 AND user_ref=$2 AND ts > now() - interval '30 days'`,
		tenantID, userRef).Scan(&out30, &in30, &txn30, &cur); err != nil {
		return nil, err
	}
	stats := []map[string]any{
		{"k": "Outbound 30 days", "v": fmtAmt(out30, cur)},
		{"k": "Inbound 30 days", "v": fmtAmt(in30, cur)},
		{"k": "Ledger txns 30 days", "v": fmt.Sprintf("%d", txn30)},
	}
	var subjectFlags []string
	if alert, _ := queryMap(ctx, s.pool,
		`SELECT id, score, threat_type, state FROM alerts
		 WHERE tenant_id=$1 AND user_ref=$2 ORDER BY created_at DESC LIMIT 1`,
		tenantID, userRef); alert != nil {
		stats = append(stats, map[string]any{"k": "Latest alert",
			"v": fmt.Sprintf("%v · %v (%v)", alert["id"], alert["threat_type"], alert["score"])})
		if st, _ := alert["state"].(string); st == "Open" {
			subjectFlags = append(subjectFlags, fmt.Sprintf("Open alert %v on this subject", alert["id"]))
		}
	}
	if amlCase, _ := queryMap(ctx, s.pool,
		`SELECT id FROM cases WHERE tenant_id=$1 AND user_ref=$2 AND case_type='AML'
		 ORDER BY created_at DESC LIMIT 1`, tenantID, userRef); amlCase != nil {
		subjectFlags = append(subjectFlags,
			fmt.Sprintf("AML file %v — proceeds tracing in progress", amlCase["id"]))
	}

	// ---- hop 1: top counterparties by value ------------------------------
	cpRows, err := queryMaps(ctx, s.pool,
		`SELECT counterparty_ref, direction, sum(amount)::float8 AS total,
		        count(*)::int AS n, min(ts) AS first_ts,
		        coalesce(max(currency), '') AS currency
		 FROM bank_txns
		 WHERE tenant_id=$1 AND user_ref=$2 AND counterparty_ref IS NOT NULL
		 GROUP BY counterparty_ref, direction
		 ORDER BY total DESC LIMIT 12`, tenantID, userRef)
	if err != nil {
		return nil, err
	}
	nodes := []graphNode{}
	type hop2seed struct{ nodeID, cp string }
	var seeds []hop2seed
	for i, r := range cpRows {
		cp, _ := r["counterparty_ref"].(string)
		dir, _ := r["direction"].(string)
		total, _ := r["total"].(float64)
		n := asInt(r["n"])
		firstSeen, _ := r["first_ts"].(time.Time)
		currency, _ := r["currency"].(string)
		kind, flags, inBook := s.classifyCounterparty(ctx, tenantID, cp, n, firstSeen)
		node := graphNode{
			ID:     fmt.Sprintf("cp%d", i),
			Label:  cp,
			Sub:    fmt.Sprintf("%d txn(s) · first seen %s", n, firstSeen.Format("Jan 2")),
			Kind:   kind,
			Dir:    map[string]string{"IN": "in", "OUT": "out"}[dir],
			Amount: fmtAmt(total, currency),
			Weight: amtWeight(total),
			Flags:  flags,
			Stats: []map[string]any{
				{"k": "Total moved", "v": fmtAmt(total, currency)},
				{"k": "Transactions", "v": fmt.Sprintf("%d", n)},
				{"k": "First seen", "v": firstSeen.Format("2006-01-02")},
			},
		}
		nodes = append(nodes, node)
		if (kind == "mule" || kind == "intel") && inBook && len(seeds) < 3 {
			seeds = append(seeds, hop2seed{node.ID, cp})
		}
	}

	// ---- hop 2: where suspicious counterparties are in-book accounts -----
	for si, seed := range seeds {
		h2, err := queryMaps(ctx, s.pool,
			`SELECT counterparty_ref, direction, sum(amount)::float8 AS total,
			        count(*)::int AS n, coalesce(max(currency), '') AS currency
			 FROM bank_txns
			 WHERE tenant_id=$1 AND account_ref=$2 AND counterparty_ref IS NOT NULL
			 GROUP BY counterparty_ref, direction
			 ORDER BY total DESC LIMIT 4`, tenantID, seed.cp)
		if err != nil {
			return nil, err
		}
		for j, r := range h2 {
			cp, _ := r["counterparty_ref"].(string)
			dir, _ := r["direction"].(string)
			total, _ := r["total"].(float64)
			currency, _ := r["currency"].(string)
			kind := "warn"
			if dir == "OUT" {
				kind = "mule" // second-layer dispersal from a suspicious account
			}
			nodes = append(nodes, graphNode{
				ID:     fmt.Sprintf("h2_%d_%d", si, j),
				Parent: seed.nodeID,
				Label:  cp,
				Sub:    fmt.Sprintf("via %s", seed.cp),
				Kind:   kind,
				Dir:    map[string]string{"IN": "in", "OUT": "out"}[dir],
				Amount: fmtAmt(total, currency),
				Weight: amtWeight(total),
				Flags:  []string{fmt.Sprintf("Second-layer flow via %s (%d txns)", seed.cp, asInt(r["n"]))},
			})
		}
	}

	// ---- device-sharing links (sessions): the network-map edge type ------
	devRows, err := queryMaps(ctx, s.pool,
		`SELECT DISTINCT s2.user_ref FROM sessions s1
		 JOIN sessions s2 ON s2.tenant_id = s1.tenant_id
		                 AND s2.install_id = s1.install_id
		 WHERE s1.tenant_id=$1 AND s1.user_ref=$2 AND s1.install_id IS NOT NULL
		   AND s2.user_ref IS NOT NULL AND s2.user_ref <> $2
		 LIMIT 4`, tenantID, userRef)
	if err != nil {
		return nil, err
	}
	for i, r := range devRows {
		other, _ := r["user_ref"].(string)
		nodes = append(nodes, graphNode{
			ID:     fmt.Sprintf("dev%d", i),
			Label:  short(other, 10),
			Sub:    "shared install",
			Kind:   "device",
			Dir:    "in",
			Amount: "same device",
			Weight: 2,
			Flags:  []string{"Same device (install id) seen on both accounts — possible account farming or mule herding"},
		})
	}

	return map[string]any{
		"subject": map[string]any{
			"label": short(userRef, 10),
			"sub":   fmt.Sprintf("subject %s", short(userRef, 16)),
			"stats": stats,
			"flags": subjectFlags,
		},
		"nodes": nodes,
	}, nil
}
