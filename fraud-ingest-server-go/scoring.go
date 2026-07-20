// Scoring engine — pure logic, no I/O. Faithful port of the Node
// engine (../fraud-ingest-server/scoring.js): same signals, weights,
// thresholds and threat classification, so decisions are identical.
package main

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

type Signal struct {
	Code     string `json:"code"`
	Label    string `json:"label"`
	Weight   int    `json:"weight"`
	Evidence string `json:"evidence"`
}

type ScoreResult struct {
	Score      int
	Reasons    []string
	Signals    []Signal
	ThreatType string
	Summary    string
}

type EventRow struct {
	Type        string
	Ts          time.Time
	CallSignals json.RawMessage
	Payload     json.RawMessage
}

type Stroke struct {
	Dur      *float64 `json:"dur"`
	Gap      *float64 `json:"gap"`
	Len      *float64 `json:"len"`
	Straight *float64 `json:"straight"`
	Obscured bool     `json:"obscured"`
}

type remoteAccessPayload struct {
	ScreenShareLikely    bool     `json:"screenShareLikely"`
	AccessibilitySuspect bool     `json:"accessibilitySuspect"`
	ExtraDisplays        int      `json:"extraDisplays"`
	AccessibilityMatches []string `json:"accessibilityMatches"`
}

type KeyTiming struct {
	Dt    float64 `json:"dt"`
	Op    string  `json:"op"`
	Paste bool    `json:"paste"`
}

type ScoringCtx struct {
	UserRef              string
	SessionStart         *time.Time
	SimChanged           bool
	Events               []EventRow
	KnownDeviceFirstSeen *time.Time
	PrevSessionAt        *time.Time
	BaselineStrokes      []Stroke
	BaselineKeys         []KeyTiming
	HistoryGeohashes     []string
	AmountHistory        []float64
	HasBankFlow          bool
	FlowIn72             float64
	FlowLastInAt         *time.Time
	FlowFan              int
}

type ScoreTxn struct {
	TxnRef     string  `json:"txnRef"`
	Amount     float64 `json:"amount"`
	Currency   string  `json:"currency"`
	PayeeIsNew bool    `json:"payeeIsNew"`
	Channel    string  `json:"channel"`
}

// ---------- helpers ----------

func mean(xs []float64) float64 {
	s := 0.0
	for _, x := range xs {
		s += x
	}
	return s / float64(len(xs))
}

func median(xs []float64) float64 {
	c := append([]float64(nil), xs...)
	sort.Float64s(c)
	return c[len(c)/2]
}

func stddev(xs []float64, m float64) float64 {
	s := 0.0
	for _, x := range xs {
		s += (x - m) * (x - m)
	}
	return math.Sqrt(s / float64(len(xs)))
}

// Inter-key latencies usable for cadence: positive, below the
// hesitation cutoff (long pauses are a separate signal, not tempo).
func cadenceDts(keys []KeyTiming) []float64 {
	out := []float64{}
	for _, k := range keys {
		if k.Dt > 0 && k.Dt <= 4000 {
			out = append(out, k.Dt)
		}
	}
	return out
}

func strokeDim(s Stroke, dim string) *float64 {
	if dim == "dur" {
		return s.Dur
	}
	return s.Gap
}

// z-score of the session mean vs. the baseline distribution, per dim.
func touchDeviation(baseline, current []Stroke, dim string) *float64 {
	base, cur := []float64{}, []float64{}
	for _, s := range baseline {
		if v := strokeDim(s, dim); v != nil && *v >= 0 {
			base = append(base, *v)
		}
	}
	for _, s := range current {
		if v := strokeDim(s, dim); v != nil && *v >= 0 {
			cur = append(cur, *v)
		}
	}
	if len(base) < 20 || len(cur) < 5 {
		return nil
	}
	m := mean(base)
	sd := math.Max(math.Max(stddev(base, m), m*0.15), 1)
	z := (mean(cur) - m) / sd
	return &z
}

type callSignals struct {
	InGsmCall  bool `json:"inGsmCall"`
	InVoipCall bool `json:"inVoipCall"`
	SpeakerOn  bool `json:"speakerOn"`
}

type keystrokePayload struct {
	FieldID string      `json:"fieldId"`
	Keys    []KeyTiming `json:"keys"`
}

type integrityPayload struct {
	RootLikely            bool     `json:"rootLikely"`
	EmulatorLikely        bool     `json:"emulatorLikely"`
	HookingFramework      string   `json:"hookingFramework"`
	AccessibilityServices []string `json:"accessibilityServices"`
}

func parsePayload[T any](raw json.RawMessage) (T, bool) {
	var v T
	if len(raw) == 0 {
		return v, false
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return v, false
	}
	return v, true
}

// ---------- session scoring ----------

func scoreSession(ctx *ScoringCtx, txn ScoreTxn) ScoreResult {
	var signals []Signal
	add := func(code, label string, weight int, evidence string) {
		signals = append(signals, Signal{code, label, weight, evidence})
	}
	events := ctx.Events

	// --- coached-session: active call while transacting -----------------
	for _, e := range events {
		if len(e.Type) < 4 || e.Type[:4] != "BIZ_" {
			continue
		}
		cs, ok := parsePayload[callSignals](e.CallSignals)
		if !ok || (!cs.InGsmCall && !cs.InVoipCall) {
			continue
		}
		kind := "GSM"
		if cs.InVoipCall {
			kind = "VoIP"
		}
		ev := kind + " call"
		if cs.SpeakerOn {
			ev += ", speaker on"
		}
		add("ACTIVE_CALL", "Transaction session during active phone call", 35, ev)
		break
	}

	// --- payee & amount --------------------------------------------------
	if txn.PayeeIsNew {
		add("NEW_PAYEE", "First-time payee", 15, "asserted by tenant backend")
	}
	hist := []float64{}
	for _, a := range ctx.AmountHistory {
		if a > 0 {
			hist = append(hist, a)
		}
	}
	if len(hist) >= 3 {
		med := median(hist)
		if txn.Amount > 3*med {
			add("AMOUNT_ABOVE_PROFILE", "Amount far above learned profile", 25,
				fmt.Sprintf("%.0f vs. median %.0f over %d approved txns",
					txn.Amount, med, len(hist)))
		}
	} else if txn.Amount >= 500000 {
		add("HIGH_AMOUNT", "High amount, no spending history", 20,
			fmt.Sprintf("amount %.0f", txn.Amount))
	}

	// --- keystroke dynamics ----------------------------------------------
	hesitationDone, pasteDone := false, false
	for _, e := range events {
		if e.Type != "PASSIVE_KEYSTROKES" {
			continue
		}
		p, ok := parsePayload[keystrokePayload](e.Payload)
		if !ok {
			continue
		}
		deletes, longPause, hasPaste := 0, false, false
		for _, k := range p.Keys {
			if k.Op == "d" {
				deletes++
			}
			if k.Dt > 4000 {
				longPause = true
			}
			if k.Paste {
				hasPaste = true
			}
		}
		if (longPause || deletes >= 3) && !hesitationDone {
			hesitationDone = true
			ev := fmt.Sprintf("field %s: %d deletions", p.FieldID, deletes)
			if longPause {
				ev += ", pauses > 4s"
			}
			add("HESITATION", "Hesitation / corrections while typing", 10, ev)
		}
		if hasPaste && !pasteDone {
			pasteDone = true
			add("PASTE_INPUT", "Pasted input in monitored field", 10, "field "+p.FieldID)
		}
	}

	// --- device familiarity ----------------------------------------------
	if ctx.UserRef == "" {
		add("NO_USER_BOUND", "Session not bound to a known user", 20, "token has no userRef")
	} else if ctx.KnownDeviceFirstSeen != nil && ctx.SessionStart != nil {
		if !ctx.KnownDeviceFirstSeen.Before(ctx.SessionStart.Add(-60 * time.Second)) {
			add("NEW_DEVICE_FOR_USER", "First session on this device", 25,
				"install first seen this session")
		}
	}

	if ctx.SimChanged {
		add("SIM_CHANGED", "SIM changed since last session", 15, "SDK SIM-swap flag")
	}

	// --- integrity --------------------------------------------------------
	for _, e := range events {
		if e.Type != "PASSIVE_APP_INTEGRITY" {
			continue
		}
		integ, ok := parsePayload[integrityPayload](e.Payload)
		if !ok {
			break
		}
		if integ.RootLikely || integ.HookingFramework != "" {
			ev := "root indicators"
			if integ.HookingFramework != "" {
				ev = "hooking: " + integ.HookingFramework
			}
			add("DEVICE_INTEGRITY", "Rooted device or hooking framework", 30, ev)
		}
		if integ.EmulatorLikely {
			add("EMULATOR", "Emulator indicators", 20, "build fingerprint")
		}
		if len(integ.AccessibilityServices) > 0 {
			ev := ""
			for i, a := range integ.AccessibilityServices {
				if i > 0 {
					ev += ", "
				}
				ev += a
			}
			add("ACCESSIBILITY_SERVICES", "Accessibility services active", 15, ev)
		}
		break
	}

	// --- touch behavior vs. baseline -------------------------------------
	curStrokes := []Stroke{}
	for _, e := range events {
		if e.Type != "PASSIVE_TOUCH_STROKES" {
			continue
		}
		p, ok := parsePayload[struct {
			Strokes []Stroke `json:"strokes"`
		}](e.Payload)
		if ok {
			curStrokes = append(curStrokes, p.Strokes...)
		}
	}
	for _, dim := range []string{"dur", "gap"} {
		z := touchDeviation(ctx.BaselineStrokes, curStrokes, dim)
		if z != nil && math.Abs(*z) > 2.5 {
			add("TOUCH_ANOMALY", "Touch behavior deviates from learned profile", 25,
				fmt.Sprintf("%s z=%.1f vs. %d baseline strokes",
					dim, *z, len(ctx.BaselineStrokes)))
			break
		}
	}

	// --- remote access / screen sharing (on-device fraud) -----------------
	// Detect the effect, not the app: an active screen-share (virtual
	// display) or remote-control accessibility service, an overlay
	// (obscured touches), or robotic injected input.
	raEvidence := ""
	for _, e := range events {
		if e.Type != "PASSIVE_REMOTE_ACCESS" {
			continue
		}
		if ra, ok := parsePayload[remoteAccessPayload](e.Payload); ok {
			if ra.ScreenShareLikely {
				raEvidence = fmt.Sprintf("screen sharing active (%d extra display(s))", ra.ExtraDisplays)
				break
			}
			if ra.AccessibilitySuspect {
				m := "remote-control tool"
				if len(ra.AccessibilityMatches) > 0 {
					m = strings.Join(ra.AccessibilityMatches, ", ")
				}
				raEvidence = "remote-control accessibility service: " + m
				break
			}
		}
	}
	if raEvidence == "" {
		for _, s := range curStrokes {
			if s.Obscured {
				raEvidence = "overlay: obscured touch on a monitored view"
				break
			}
		}
	}
	if raEvidence == "" {
		robotic := 0
		for _, s := range curStrokes {
			if s.Len != nil && *s.Len > 30 && s.Straight != nil && *s.Straight >= 0.99 {
				robotic++
			}
		}
		if robotic >= 3 {
			raEvidence = fmt.Sprintf("%d robotic (injected) strokes", robotic)
		}
	}
	if raEvidence != "" {
		add("REMOTE_ACCESS", "Remote access / screen sharing likely", 35, raEvidence)
	}

	// --- keystroke cadence vs. baseline -----------------------------------
	curKeyEvents := []KeyTiming{}
	for _, e := range events {
		if e.Type != "PASSIVE_KEYSTROKES" {
			continue
		}
		if p, ok := parsePayload[keystrokePayload](e.Payload); ok {
			curKeyEvents = append(curKeyEvents, p.Keys...)
		}
	}
	curKeys := cadenceDts(curKeyEvents)
	baseKeys := cadenceDts(ctx.BaselineKeys)
	if len(baseKeys) >= 30 && len(curKeys) >= 10 {
		baseMed, curMed := median(baseKeys), median(curKeys)
		ratio := curMed / math.Max(baseMed, 1)
		if ratio > 1.6 || ratio < 0.6 {
			add("KEYSTROKE_ANOMALY", "Typing cadence deviates from learned profile", 20,
				fmt.Sprintf("median inter-key %.0fms vs. baseline %.0fms (%d baseline keys)",
					curMed, baseMed, len(baseKeys)))
		}
	}

	// --- location ---------------------------------------------------------
	curGeo := ""
	for _, e := range events {
		if e.Type != "PASSIVE_LOCATION_COARSE" {
			continue
		}
		if p, ok := parsePayload[struct {
			Geohash string `json:"geohash"`
		}](e.Payload); ok {
			curGeo = p.Geohash
		}
		break
	}
	if curGeo != "" && len(ctx.HistoryGeohashes) > 0 {
		prefix := curGeo
		if len(prefix) > 4 {
			prefix = prefix[:4]
		}
		known := false
		for _, g := range ctx.HistoryGeohashes {
			gp := g
			if len(gp) > 4 {
				gp = gp[:4]
			}
			if gp == prefix {
				known = true
				break
			}
		}
		if !known {
			add("GEO_UNUSUAL", "Location outside usual area", 10,
				fmt.Sprintf("geohash %s… never seen for this user", prefix))
		}
	}

	// --- bank-feed flow ---------------------------------------------------
	if ctx.HasBankFlow && ctx.FlowIn72 > 0 && ctx.FlowLastInAt != nil {
		sinceIn := time.Since(*ctx.FlowLastInAt)
		if sinceIn < 24*time.Hour && txn.Amount >= 0.6*ctx.FlowIn72 {
			add("RAPID_IN_OUT", "Outbound follows recent inbound transfer", 30,
				fmt.Sprintf("%.0f out vs. %.0f received %d min ago",
					txn.Amount, ctx.FlowIn72, int(sinceIn.Minutes())))
		}
	}
	if ctx.HasBankFlow && ctx.FlowFan >= 3 {
		add("FAN_OUT_24H", "Outbound split across many counterparties", 20,
			fmt.Sprintf("%d distinct counterparties in 24h", ctx.FlowFan))
	}

	// --- dormancy ---------------------------------------------------------
	if ctx.PrevSessionAt != nil && ctx.SessionStart != nil {
		gap := ctx.SessionStart.Sub(*ctx.PrevSessionAt)
		if gap > 90*24*time.Hour {
			add("DORMANT_REACTIVATED", "Dormant account reactivated", 25,
				fmt.Sprintf("%d days since previous session", int(gap.Hours()/24)))
		}
	}

	// --- velocity ---------------------------------------------------------
	if txn.PayeeIsNew && len(events) > 0 {
		for _, e := range events {
			if e.Type != "BIZ_TXN_INITIATED" {
				continue
			}
			dt := e.Ts.Sub(events[0].Ts)
			if dt >= 0 && dt < 20*time.Second {
				add("RAPID_TO_TXN", "Transaction seconds after session start", 10,
					fmt.Sprintf("%ds from first event to txn", int(dt.Seconds())))
			}
			break
		}
	}

	return finish(signals, ctx)
}

func finish(signals []Signal, ctx *ScoringCtx) ScoreResult {
	total := 0
	reasons := make([]string, 0, len(signals))
	summary := ""
	for i, s := range signals {
		total += s.Weight
		reasons = append(reasons, s.Code)
		if i > 0 {
			summary += " + "
		}
		summary += s.Label
	}
	if total > 100 {
		total = 100
	}
	if summary == "" {
		summary = "No risk signals"
	}
	has := func(code string) bool {
		for _, s := range signals {
			if s.Code == code {
				return true
			}
		}
		return false
	}
	threat := ""
	switch {
	case has("ACTIVE_CALL") &&
		(has("NEW_PAYEE") || has("AMOUNT_ABOVE_PROFILE") || has("HIGH_AMOUNT")):
		threat = "APP Scam"
	case ctx.UserRef != "" &&
		(has("REMOTE_ACCESS") || has("NEW_DEVICE_FOR_USER") || has("DEVICE_INTEGRITY") ||
			has("ACCESSIBILITY_SERVICES") || has("TOUCH_ANOMALY") ||
			has("KEYSTROKE_ANOMALY")):
		threat = "Account Takeover"
	case has("DORMANT_REACTIVATED") || has("RAPID_IN_OUT"):
		threat = "Money Mule"
	case has("NO_USER_BOUND") && (has("EMULATOR") || has("PASTE_INPUT")):
		threat = "New Account Fraud"
	}
	if signals == nil {
		signals = []Signal{}
	}
	return ScoreResult{Score: total, Reasons: reasons, Signals: signals,
		ThreatType: threat, Summary: summary}
}

// ---------- ledger detectors ----------

type AccountFlow struct {
	In72                  float64
	LastInAt              *time.Time
	Out24                 float64
	FanOut24              int
	PriorActivity90d      int
	FlaggedCounterparties int
}

func scoreAccountFlow(f AccountFlow) ScoreResult {
	var signals []Signal
	add := func(code, label string, weight int, evidence string) {
		signals = append(signals, Signal{code, label, weight, evidence})
	}
	if f.In72 >= 50000 && f.Out24 >= 0.8*f.In72 {
		add("RAPID_IN_OUT", "Inbound funds forwarded almost entirely within hours", 40,
			fmt.Sprintf("%.0f out in 24h vs. %.0f in over 72h", f.Out24, f.In72))
	}
	if f.FanOut24 >= 3 {
		add("FAN_OUT", "Outbound split across many counterparties", 20,
			fmt.Sprintf("%d distinct counterparties in 24h", f.FanOut24))
	}
	if f.PriorActivity90d == 0 && f.In72 > 0 {
		add("QUIET_ACCOUNT", "No account activity in the prior 90 days", 25,
			"account was dormant or newly opened before the inbound transfer")
	}
	if f.FlaggedCounterparties > 0 {
		add("FLAGGED_COUNTERPARTY", "Transacts with an account under an open alert", 25,
			fmt.Sprintf("%d recent txns against flagged accounts", f.FlaggedCounterparties))
	}
	r := finish(signals, &ScoringCtx{})
	if len(signals) == 0 {
		r.Summary = "No flow anomalies"
	}
	r.ThreatType = ""
	return r
}

type AgentStats struct {
	TopCpRef       string
	TopCpCount     int
	TopCpSum       float64
	Total24        int
	SmallCount     int
	TopAmountShare float64
}

func scoreAgentActivity(st AgentStats) ScoreResult {
	var signals []Signal
	add := func(code, label string, weight int, evidence string) {
		signals = append(signals, Signal{code, label, weight, evidence})
	}
	if st.TopCpCount >= 5 {
		add("SPLIT_TXNS", "Deposit split into many small txns to one counterparty", 45,
			fmt.Sprintf("%d small txns (sum %.0f) to %s in 24h",
				st.TopCpCount, st.TopCpSum, short(st.TopCpRef, 8)))
	}
	if st.SmallCount >= 10 {
		add("MICRO_BURST", "Burst of sub-threshold transactions", 25,
			fmt.Sprintf("%d small txns in 24h", st.SmallCount))
	}
	if st.Total24 >= 5 && st.TopAmountShare >= 0.6 {
		add("UNIFORM_AMOUNTS", "Near-identical amounts across the burst", 20,
			fmt.Sprintf("%d%% of txns share one amount", int(st.TopAmountShare*100)))
	}
	r := finish(signals, &ScoringCtx{})
	if len(signals) == 0 {
		r.Summary = "No commission anomalies"
	}
	r.ThreatType = ""
	return r
}
