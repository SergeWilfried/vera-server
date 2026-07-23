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
	ScreenRecording      bool     `json:"screenRecording"`
}

type webFingerprintPayload struct {
	Headless bool     `json:"headless"`
	BotFlags []string `json:"botFlags"`
	UA       string   `json:"userAgent"`
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
	BaselineMouse        []Stroke
	BaselineKeys         []KeyTiming
	HistoryGeohashes     []string
	LastFixGeohash       string     // most recent prior location fix …
	LastFixAt            *time.Time // … and when it was reported
	AmountHistory        []float64
	// Per-tenant, per-currency "high amount, no history" cutoff, resolved for
	// txn.Currency by the handler. <=0 means unset -> fall back to the global
	// default (see highAmountCutoff). The history-based AMOUNT_ABOVE_PROFILE
	// branch is already currency-safe (relative to the user's own median).
	HighAmountThreshold  float64
	HasBankFlow          bool
	FlowIn72             float64
	FlowLastInAt         *time.Time
	FlowFan              int
}

// defaultHighAmount cutoff, used when no override is configured — a low bar
// per currency (roughly a few hundred EUR) for "unusually large with no
// spending history to compare against".
const defaultHighAmountCutoff = 500000.0

func highAmountCutoff(t float64) float64 {
	if t > 0 {
		return t
	}
	return defaultHighAmountCutoff
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

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Geohash cell centroid — inverse of the SDK's encoder. Precision 5
// (~±2.4 km) is plenty for the country-scale distances IMPOSSIBLE_TRAVEL
// cares about. ok=false on malformed input.
func geohashCentroid(g string) (lat, lon float64, ok bool) {
	const b32 = "0123456789bcdefghjkmnpqrstuvwxyz"
	latR := [2]float64{-90, 90}
	lonR := [2]float64{-180, 180}
	even := true
	for _, c := range g {
		ci := strings.IndexRune(b32, c)
		if ci < 0 {
			return 0, 0, false
		}
		for bit := 4; bit >= 0; bit-- {
			hi := ci>>bit&1 == 1
			if even {
				if hi {
					lonR[0] = (lonR[0] + lonR[1]) / 2
				} else {
					lonR[1] = (lonR[0] + lonR[1]) / 2
				}
			} else {
				if hi {
					latR[0] = (latR[0] + latR[1]) / 2
				} else {
					latR[1] = (latR[0] + latR[1]) / 2
				}
			}
			even = !even
		}
	}
	return (latR[0] + latR[1]) / 2, (lonR[0] + lonR[1]) / 2, len(g) > 0
}

func haversineKm(lat1, lon1, lat2, lon2 float64) float64 {
	const r = 6371.0
	rad := math.Pi / 180
	dLat := (lat2 - lat1) * rad
	dLon := (lon2 - lon1) * rad
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1*rad)*math.Cos(lat2*rad)*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 2 * r * math.Asin(math.Sqrt(a))
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
	InGsmCall    bool `json:"inGsmCall"`
	InVoipCall   bool `json:"inVoipCall"`
	SpeakerOn    bool `json:"speakerOn"`
	BtAudio      bool `json:"btAudio"`
	WiredHeadset bool `json:"wiredHeadset"`
}

// audioRoute names the hands-free output the call audio is on, or "" when the
// phone is at the ear. Hands-free is the stronger coached tell: at the ear the
// victim cannot type a transfer; on speaker/headset they are free to follow
// the caller's instructions inside the app.
func (cs callSignals) audioRoute() string {
	switch {
	case cs.SpeakerOn:
		return "speaker"
	case cs.BtAudio:
		return "bluetooth audio"
	case cs.WiredHeadset:
		return "wired headset"
	}
	return ""
}

type callStatePayload struct {
	Active     bool   `json:"active"`
	Kind       string `json:"kind"`
	DurationMs int64  `json:"durationMs"`
}

type stepUpPayload struct {
	Outcome string `json:"outcome"`
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
	Debuggable            bool     `json:"debuggable"`
	DevOptionsEnabled     bool     `json:"devOptionsEnabled"`
	// Pointer: absence (older SDK builds without the field) must not read
	// as "" — an empty string is itself the sideload indicator.
	InstallerPackage *string `json:"installerPackage"`
}

// manualInstaller reports whether the installer package indicates a manual
// APK install (sideload) rather than any app store. Store packages vary by
// OEM, so only positive manual-install indicators are matched.
func manualInstaller(pkg string) bool {
	switch pkg {
	case "", "com.android.packageinstaller", "com.google.android.packageinstaller":
		return true
	}
	return false
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
	activeCall := false
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
		route := cs.audioRoute()
		if route != "" {
			ev += ", " + route
		}
		add("ACTIVE_CALL", "Transaction session during active phone call", 35, ev)
		if route != "" {
			add("CALL_HANDS_FREE", "Call audio on speaker/headset while using the app", 10,
				route+" during "+kind+" call")
		}
		activeCall = true
		break
	}

	// --- coached-session: call ended moments before the transfer --------
	// The SDK's call-state watch emits PASSIVE_CALL_STATE on every
	// idle<->in-call transition. A call that ends just before
	// TXN_INITIATED is the "hang up, then send it" coaching pattern the
	// per-event snapshot cannot see. Skipped when ACTIVE_CALL already
	// fired — the live call is the stronger form of the same fact.
	if !activeCall {
		var callEndAt, txnAt time.Time
		var endKind string
		var callDurMs int64
		for _, e := range events {
			switch e.Type {
			case "PASSIVE_CALL_STATE":
				p, ok := parsePayload[callStatePayload](e.Payload)
				if ok && !p.Active && e.Ts.After(callEndAt) {
					callEndAt = e.Ts
					endKind = p.Kind
					callDurMs = p.DurationMs
				}
			case "BIZ_TXN_INITIATED":
				if e.Ts.After(txnAt) {
					txnAt = e.Ts
				}
			}
		}
		if !callEndAt.IsZero() && txnAt.After(callEndAt) {
			gap := txnAt.Sub(callEndAt)
			if gap <= 5*time.Minute {
				when := fmt.Sprintf("%ds", int(gap.Seconds()))
				if gap >= time.Minute {
					when = fmt.Sprintf("%d min", int(gap.Minutes()))
				}
				ev := endKind + " call"
				if callDurMs >= 60000 {
					ev += fmt.Sprintf(" (%d min)", callDurMs/60000)
				}
				add("RECENT_CALL", "Call ended moments before the transfer", 25,
					ev+" ended "+when+" before transfer")
			}
		}
	}

	// --- step-up outcome (failed challenge escalates) --------------------
	// The bank performs the step-up (OTP/PIN/biometric/push) and reports the
	// result via BIZ_STEP_UP_RESULT. A failed challenge on an already-scored
	// session is a strong escalation — canonical for ATO, where an imposter
	// fails the owner's credential. Take the LAST result: a user who retries
	// and passes shouldn't be penalized for an earlier miss.
	var lastStepUp string
	var lastStepUpAt time.Time
	for _, e := range events {
		if e.Type != "BIZ_STEP_UP_RESULT" {
			continue
		}
		if p, ok := parsePayload[stepUpPayload](e.Payload); ok && !e.Ts.Before(lastStepUpAt) {
			lastStepUpAt = e.Ts
			lastStepUp = strings.ToUpper(p.Outcome)
		}
	}
	switch lastStepUp {
	case "FAIL", "FAILURE", "LOCKED":
		add("STEP_UP_FAILED", "Step-up challenge failed", 35, "outcome "+lastStepUp)
	case "ABANDONED":
		add("STEP_UP_ABANDONED", "Step-up challenge abandoned", 20, "user left the challenge")
	}

	// --- payee & amount --------------------------------------------------
	if txn.PayeeIsNew {
		add("NEW_PAYEE", "First-time payee", 15, "asserted by tenant backend")

		// APP-scam tell: the payee was created moments ago, in this very
		// session, and is being paid straight away — the "add payee, send
		// everything" pattern of a live coaching call. A legitimate new payee
		// is usually added, then paid days later.
		var payeeAddedAt, txnAt time.Time
		for _, e := range events {
			switch e.Type {
			case "BIZ_PAYEE_ADDED":
				if e.Ts.After(payeeAddedAt) {
					payeeAddedAt = e.Ts
				}
			case "BIZ_TXN_INITIATED":
				if e.Ts.After(txnAt) {
					txnAt = e.Ts
				}
			}
		}
		if txnAt.IsZero() {
			txnAt = time.Now()
		}
		if !payeeAddedAt.IsZero() && !txnAt.Before(payeeAddedAt) {
			gap := txnAt.Sub(payeeAddedAt)
			if gap <= 30*time.Minute {
				when := "seconds"
				if gap >= time.Minute {
					when = fmt.Sprintf("%d min", int(gap.Minutes()))
				}
				add("RUSHED_NEW_PAYEE", "New payee paid immediately after adding", 20,
					"payee added "+when+" before transfer")
			}
		}
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
	} else if cutoff := highAmountCutoff(ctx.HighAmountThreshold); txn.Amount >= cutoff {
		ccy := txn.Currency
		if ccy == "" {
			ccy = "amount"
		}
		add("HIGH_AMOUNT", "High amount, no spending history", 20,
			fmt.Sprintf("%.0f %s (>= %.0f)", txn.Amount, ccy, cutoff))
	}

	// --- transaction velocity (structuring / session drain) -------------
	// Many transfers in a short window — a drain split into small,
	// individually-benign amounts to stay under the per-transaction cutoff,
	// or an account-takeover cash-out. Escalates with the count so a runaway
	// drain crosses STEP_UP then HOLD on its own, even to a known payee.
	{
		velWindow := 10 * time.Minute
		var lastTxn time.Time
		var txnTimes []time.Time
		for _, e := range events {
			if e.Type == "BIZ_TXN_INITIATED" {
				txnTimes = append(txnTimes, e.Ts)
				if e.Ts.After(lastTxn) {
					lastTxn = e.Ts
				}
			}
		}
		count := 0
		if !lastTxn.IsZero() {
			for _, t := range txnTimes {
				if !t.Before(lastTxn.Add(-velWindow)) {
					count++
				}
			}
		}
		if count >= 4 {
			add("TXN_VELOCITY", "Rapid repeated transfers (velocity)", 20+15*(count-4),
				fmt.Sprintf("%d transfers within 10 min", count))
		}
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
		if integ.Debuggable {
			add("DEBUG_BUILD", "App build is debuggable", 20, "FLAG_DEBUGGABLE set")
		}
		if integ.DevOptionsEnabled {
			add("DEV_OPTIONS", "Developer options enabled", 10, "developer settings on")
		}
		if integ.InstallerPackage != nil && manualInstaller(*integ.InstallerPackage) {
			ev := "no installer package (manual install)"
			if *integ.InstallerPackage != "" {
				ev = "installer \"" + *integ.InstallerPackage + "\""
			}
			add("SIDELOADED_APP", "App installed outside an app store", 25, ev)
		}
		break
	}

	// --- screenshot during the session (coached exfiltration) ------------
	// Under coaching, victims are told to screenshot an OTP / balance /
	// transfer confirmation and send it to the "agent". Weak on its own —
	// low weight, corroborating — but meaningful stacked with a live call.
	for _, e := range events {
		if e.Type == "PASSIVE_SCREENSHOT" {
			add("SCREENSHOT", "Screenshot captured during the session", 10,
				"screen contents captured")
			break
		}
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
				switch {
				case ra.ExtraDisplays > 0:
					raEvidence = fmt.Sprintf("screen sharing active (%d extra display(s))", ra.ExtraDisplays)
				case ra.ScreenRecording:
					raEvidence = "screen recording active"
				default:
					raEvidence = "screen sharing likely"
				}
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

	// --- web: headless / bot browser --------------------------------------
	for _, e := range events {
		if e.Type != "PASSIVE_WEB_FINGERPRINT" {
			continue
		}
		if fp, ok := parsePayload[webFingerprintPayload](e.Payload); ok && fp.Headless {
			ev := "headless/automation indicators"
			if len(fp.BotFlags) > 0 {
				ev = strings.Join(fp.BotFlags, ", ")
			}
			add("HEADLESS_BROWSER", "Headless / automated browser", 30, ev)
		}
		break
	}

	// --- web: mouse dynamics vs. baseline ---------------------------------
	curMouse := []Stroke{}
	for _, e := range events {
		if e.Type != "PASSIVE_MOUSE_STROKES" {
			continue
		}
		if p, ok := parsePayload[struct {
			Strokes []Stroke `json:"strokes"`
		}](e.Payload); ok {
			curMouse = append(curMouse, p.Strokes...)
		}
	}
	for _, dim := range []string{"dur", "gap"} {
		z := touchDeviation(ctx.BaselineMouse, curMouse, dim)
		if z != nil && math.Abs(*z) > 2.5 {
			add("MOUSE_ANOMALY", "Mouse behavior deviates from learned profile", 25,
				fmt.Sprintf("%s z=%.1f vs. %d baseline mouse strokes",
					dim, *z, len(ctx.BaselineMouse)))
			break
		}
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
	// Integrity first: an untrusted fix must raise risk, never lower it.
	// A spoofer parking "at home" matches the geo history (silencing
	// GEO_UNUSUAL) — the mock flag turns that evasion into a detection.
	curGeo := ""
	curGeoMock := false
	var curGeoTs time.Time
	for _, e := range events {
		if e.Type != "PASSIVE_LOCATION_COARSE" {
			continue
		}
		if p, ok := parsePayload[struct {
			Geohash string `json:"geohash"`
			Mock    bool   `json:"mock"`
		}](e.Payload); ok {
			curGeo, curGeoMock, curGeoTs = p.Geohash, p.Mock, e.Ts
		}
		break
	}
	if curGeoMock {
		add("MOCK_LOCATION", "Location injected by a mock provider", 25,
			fmt.Sprintf("fake-GPS fix reported as %s…", trunc(curGeo, 4)))
	}
	// Cross-session velocity: last trusted-enough fix vs. this one. Both the
	// distance floor (geohash-5 cells are ~5 km) and the speed ceiling
	// (faster than commercial flight) must be broken.
	if curGeo != "" && ctx.LastFixGeohash != "" && ctx.LastFixAt != nil && !curGeoTs.IsZero() {
		lat1, lon1, ok1 := geohashCentroid(ctx.LastFixGeohash)
		lat2, lon2, ok2 := geohashCentroid(curGeo)
		dt := curGeoTs.Sub(*ctx.LastFixAt)
		if ok1 && ok2 && dt > 0 {
			km := haversineKm(lat1, lon1, lat2, lon2)
			kmh := km / dt.Hours()
			if km >= 100 && kmh > 950 {
				add("IMPOSSIBLE_TRAVEL", "Location physically unreachable since last fix", 30,
					fmt.Sprintf("%.0f km in %d min (%.0f km/h) since %s…",
						km, int(dt.Minutes()), kmh, trunc(ctx.LastFixGeohash, 4)))
			}
		}
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

// interventionFor recommends HOW the bank should act on a decision — VeraWall
// decides, the bank enforces. Crucially, an APP-scam step-up must NOT be an
// identity challenge: the victim is the real account holder and will pass any
// biometric/OTP while being coached. That case routes to SCAM_WARNING (show
// the anti-scam friction: coaching warning, cooling-off, out-of-band confirm)
// instead of IDENTITY (re-auth, the right tool for account takeover).
func interventionFor(decision, threat string) string {
	switch decision {
	case "STEP_UP":
		if threat == "APP Scam" {
			return "SCAM_WARNING"
		}
		return "IDENTITY"
	case "HOLD":
		return "ANALYST_REVIEW"
	}
	return ""
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
	case (has("ACTIVE_CALL") || has("RECENT_CALL") || has("RUSHED_NEW_PAYEE")) &&
		(has("NEW_PAYEE") || has("AMOUNT_ABOVE_PROFILE") || has("HIGH_AMOUNT")):
		threat = "APP Scam"
	case ctx.UserRef != "" &&
		(has("REMOTE_ACCESS") || has("NEW_DEVICE_FOR_USER") || has("DEVICE_INTEGRITY") ||
			has("SIDELOADED_APP") || has("DEBUG_BUILD") || has("STEP_UP_FAILED") ||
			has("TXN_VELOCITY") || has("ACCESSIBILITY_SERVICES") || has("TOUCH_ANOMALY") ||
			has("KEYSTROKE_ANOMALY") || has("MOUSE_ANOMALY") || has("HEADLESS_BROWSER") ||
			has("IMPOSSIBLE_TRAVEL") || has("MOCK_LOCATION")):
		threat = "Account Takeover"
	case has("DORMANT_REACTIVATED") || has("RAPID_IN_OUT"):
		threat = "Money Mule"
	case has("NO_USER_BOUND") && (has("EMULATOR") || has("PASTE_INPUT") ||
		has("HEADLESS_BROWSER") || has("MOCK_LOCATION")):
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
	OutCount24            int
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
	// Drain by many outbound transfers — catches a same-payee structuring
	// drain that FAN_OUT (distinct counterparties) would miss.
	if f.OutCount24 >= 10 {
		add("OUT_BURST", "Burst of outbound transactions (account drain)", 30,
			fmt.Sprintf("%d outbound transactions in 24h", f.OutCount24))
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
