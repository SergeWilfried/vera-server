// Demo Bank (Expo) — the mobile twin of fraud-sdk-web/demo. Sign in → dashboard
// → transfer → live ALLOW / STEP-UP / HOLD, scored by Verawall. The bank's tiny
// backend (../../fraud-sdk-web/demo/server.mjs, port 8099) makes the real
// server-to-server /v1/score call; the app only proves the session via the SDK.
//
// Screen-share detection: in Expo Go there's no native module, so the "Simulate
// screen-share" switch stands in for it via FraudSdk.reportRemoteAccess() — same
// as the web demo. In a dev build the bundled native module reports it for real.

import React, { useEffect, useMemo, useState } from 'react';
import {
  ActivityIndicator, Pressable, ScrollView, StyleSheet, Switch, Text, TextInput, View,
} from 'react-native';
import { StatusBar } from 'expo-status-bar';
import Constants from 'expo-constants';
import { FraudSdk, BusinessEvent, type LocalRisk } from '@veratools/fraud-sdk-expo';

// Dev default: reach the dev machine from the simulator/device via the Metro
// host IP. Deployed build: set EXPO_PUBLIC_COLLECTOR_URL (and optionally
// EXPO_PUBLIC_BANK_BACKEND) at build time — with a collector URL and no bank
// backend, the app calls /v1/score directly. That is a DEMO-ONLY shortcut so
// a standalone APK works without deploying server.mjs; a real integration
// keeps the score call server-to-server behind the bank's backend.
const HOST = (Constants.expoConfig?.hostUri ?? 'localhost:8081').split(':')[0];
const COLLECTOR = process.env.EXPO_PUBLIC_COLLECTOR_URL ?? `http://${HOST}:8080`;
const BACKEND = process.env.EXPO_PUBLIC_BANK_BACKEND ??
  (process.env.EXPO_PUBLIC_COLLECTOR_URL ? '' : `http://${HOST}:8099`);
const TENANT = 'wallet-acme';
const SITE_KEY = 'site_wallet-acme_pub';
const DEMO_EMAIL = 'olivia@demobank.cz';

type Preset = { id: string; title: string; sub: string; amount: number; newPayee: boolean; rushed?: boolean };
const PRESETS: Preset[] = [
  { id: 'rent', title: 'Pay landlord', sub: '8,000 CZK · known payee', amount: 8000, newPayee: false },
  { id: 'attack', title: 'New payee — large', sub: '150,000 CZK · first-time payee', amount: 150000, newPayee: true },
  { id: 'coached', title: 'Coached transfer', sub: '90,000 CZK · payee added just now', amount: 90000, newPayee: true, rushed: true },
];

type Decision = {
  decision?: 'ALLOW' | 'STEP_UP' | 'HOLD';
  riskScore?: number;
  threatType?: string;
  intervention?: 'SCAM_WARNING' | 'IDENTITY' | 'ANALYST_REVIEW';
  alertId?: string;
  signals?: { weight: number; label: string; evidence?: string }[];
};

const fmt = (n: number) => n.toLocaleString('en-US');

export default function App() {
  const [ready, setReady] = useState(false);
  const [screen, setScreen] = useState<'login' | 'dashboard' | 'transfer' | 'outcome'>('login');
  const [balance, setBalance] = useState(184320);
  const [pin, setPin] = useState('481920');
  const [pick, setPick] = useState<Preset>(PRESETS[0]);
  const [verdict, setVerdict] = useState<Decision | null>(null);
  const [riskReasons, setRiskReasons] = useState<string[]>([]);
  const [shareSim, setShareSim] = useState(false);
  const [callSim, setCallSim] = useState(false);
  const [preventShots, setPreventShots] = useState(false);
  const [shotSeen, setShotSeen] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    (async () => {
      await FraudSdk.init({ tenantId: TENANT, siteKey: SITE_KEY, collectorUrl: COLLECTOR, flushIntervalMs: 2000 });
      FraudSdk.onLocalRisk((r: LocalRisk) => setRiskReasons(r.reasons));
      FraudSdk.onScreenshot(() => setShotSeen(true));
      setReady(true);
    })();
  }, []);

  function togglePreventShots(v: boolean) {
    setPreventShots(v);
    void FraudSdk.preventScreenCapture(v);
  }

  const touch = useMemo(() => (ready ? FraudSdk.touch() : { panHandlers: {}, flush: () => {} }), [ready]);
  const pinTrack = useMemo(() => FraudSdk.trackInput('login.pin'), []);

  async function login() {
    FraudSdk.session().setUser(await FraudSdk.hash(DEMO_EMAIL));
    FraudSdk.session().event(BusinessEvent.loginResult('SUCCESS'));
    FraudSdk.session().screenView('dashboard');
    setScreen('dashboard');
  }

  async function pay(p: Preset) {
    setBusy(true);
    try {
      if (p.rushed) FraudSdk.session().event(BusinessEvent.payeeAdded('demo-payee-' + Date.now()));
      FraudSdk.session().event(BusinessEvent.txnInitiated({
        amountBucket: p.amount >= 50000 ? 'HIGH' : 'MID', currency: 'CZK', payeeIsNew: p.newPayee, channel: 'BANK_TRANSFER',
      }));
      await FraudSdk.flush();
      const token = await FraudSdk.session().getToken();
      const res = BACKEND
        ? await fetch(`${BACKEND}/demo/pay`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token, amount: p.amount, payeeNew: p.newPayee }),
          })
        : await fetch(`${COLLECTOR}/v1/score`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              sessionToken: token,
              transaction: {
                txnRef: 'DEMO-' + Date.now(), amount: p.amount, currency: 'CZK',
                payeeIsNew: p.newPayee, channel: 'BANK_TRANSFER',
              },
            }),
          });
      const d: Decision = await res.json();
      setVerdict(d);
      if (d.decision === 'ALLOW') setBalance((b) => b - p.amount);
      setScreen('outcome');
    } catch (e) {
      setVerdict({ decision: undefined, signals: [{ weight: 0, label: 'Network error', evidence: String(e) }] });
      setScreen('outcome');
    } finally {
      setBusy(false);
    }
  }

  function toggleShare(v: boolean) {
    setShareSim(v);
    FraudSdk.reportRemoteAccess(v);
  }

  function toggleCall(v: boolean) {
    setCallSim(v);
    FraudSdk.reportCallState(v, 'VoIP');
  }

  if (!ready) {
    return (
      <View style={[styles.app, styles.center]}>
        <ActivityIndicator color={C.brand} />
        <Text style={styles.muted}>Starting Verawall SDK…</Text>
      </View>
    );
  }

  return (
    <View style={styles.app} {...(touch.panHandlers as object)}>
      <StatusBar style="dark" />
      <ScrollView contentContainerStyle={styles.wrap}>
        <View style={styles.topbar}>
          <View style={styles.logo}><Text style={styles.logoTxt}>DB</Text></View>
          <Text style={styles.brand}>Demo Bank</Text>
          {screen !== 'login' && <Text style={styles.who}>{DEMO_EMAIL}</Text>}
        </View>

        {riskReasons.includes('SCREEN_SHARE') && (
          <View style={styles.scam}>
            <Text style={styles.scamIcon}>🛡️</Text>
            <View style={{ flex: 1 }}>
              <Text style={styles.scamHead}>Screen sharing detected on this device</Text>
              <Text style={styles.scamSub}>
                If someone phoned you and asked to install an app like AnyDesk or TeamViewer, or is watching your
                screen right now — hang up. Demo Bank will never ask you to share your screen or move money to a
                “safe account”.
              </Text>
            </View>
          </View>
        )}
        {riskReasons.includes('ACTIVE_CALL') && (
          <View style={styles.scam}>
            <Text style={styles.scamIcon}>📵</Text>
            <View style={{ flex: 1 }}>
              <Text style={styles.scamHead}>You’re on a call right now</Text>
              <Text style={styles.scamSub}>
                No one from Demo Bank is on this call. Bank staff never stay on the line while you send money —
                if the caller is guiding you through a transfer, hang up now.
              </Text>
            </View>
          </View>
        )}

        {screen === 'login' && (
          <Card>
            <Text style={styles.h2}>Sign in</Text>
            <Text style={styles.sub}>Demo customer — credentials are pre-filled.</Text>
            <Text style={styles.label}>Email</Text>
            <TextInput style={styles.input} value={DEMO_EMAIL} editable={false} />
            <Text style={styles.label}>PIN</Text>
            <TextInput
              style={styles.input}
              value={pin}
              onChangeText={(t) => { setPin(t); pinTrack.onChangeText(t); }}
              onKeyPress={pinTrack.onKeyPress}
              onBlur={pinTrack.onBlur}
              secureTextEntry
              keyboardType="number-pad"
            />
            <Btn label="Sign in" onPress={login} />
          </Card>
        )}

        {screen === 'dashboard' && (
          <>
            <Card>
              <Text style={styles.sub}>Current account · CZ89 •• 4412</Text>
              <Text style={styles.balance}>{fmt(balance)} <Text style={styles.balanceCcy}>CZK</Text></Text>
              <Btn label="New transfer" onPress={() => { FraudSdk.session().screenView('transfer'); setScreen('transfer'); }} />
            </Card>
            <Card>
              <Text style={styles.h3}>Recent activity</Text>
              {[['Employer s.r.o. — salary', '+62,000'], ['ČEZ — utilities', '−1,240'], ['Rohlík.cz — groceries', '−2,180']].map(([a, b]) => (
                <View key={a} style={styles.row}><Text style={styles.rowL}>{a}</Text><Text style={styles.rowR}>{b}</Text></View>
              ))}
            </Card>
          </>
        )}

        {screen === 'transfer' && (
          <Card>
            <Text style={styles.h2}>Send money</Text>
            <Text style={styles.sub}>Pick a scenario — Verawall scores the session in real time.</Text>
            {PRESETS.map((p) => (
              <Pressable key={p.id} onPress={() => setPick(p)} style={[styles.preset, pick.id === p.id && styles.presetSel]}>
                <Text style={styles.presetTitle}>{p.title}</Text>
                <Text style={styles.presetSub}>{p.sub}</Text>
              </Pressable>
            ))}
            <Btn label={busy ? 'Checking…' : `Send ${fmt(pick.amount)} CZK`} onPress={() => pay(pick)} disabled={busy} />
            <Btn label="Cancel" ghost onPress={() => setScreen('dashboard')} />
          </Card>
        )}

        {screen === 'outcome' && verdict && <Outcome d={verdict} onDone={() => setScreen('dashboard')} onBalance={(amt) => setBalance((b) => b - amt)} />}

        <VerawallPanel verdict={verdict} shareSim={shareSim} onToggleShare={toggleShare}
          callSim={callSim} onToggleCall={toggleCall}
          preventShots={preventShots} onTogglePreventShots={togglePreventShots}
          shotSeen={shotSeen} />
      </ScrollView>
    </View>
  );
}

function Outcome({ d, onDone, onBalance }: { d: Decision; onDone: () => void; onBalance: (n: number) => void }) {
  const [otp, setOtp] = useState('');
  const [done, setDone] = useState<null | string>(null);
  if (done) {
    return (
      <Card center>
        <Badge color={C.ok} icon="✓" />
        <Text style={styles.h2}>Payment sent</Text>
        <Text style={styles.sub}>{done}</Text>
        <Btn label="Back to account" ghost onPress={onDone} />
      </Card>
    );
  }
  if (d.decision === 'ALLOW') {
    return (
      <Card center>
        <Badge color={C.ok} icon="✓" />
        <Text style={styles.h2}>Payment sent</Text>
        <Text style={styles.sub}>On its way. No extra checks needed.</Text>
        <Btn label="Back to account" ghost onPress={onDone} />
      </Card>
    );
  }
  if (d.decision === 'STEP_UP') {
    // APP-scam step-up: an identity challenge is useless — the victim IS the
    // account holder and passes it. Show anti-scam friction instead: warn
    // about coaching and require an explicit acknowledgement.
    if (d.intervention === 'SCAM_WARNING') {
      return (
        <Card center>
          <Badge color={C.warn} icon="📵" />
          <Text style={styles.h2}>Is someone helping you with this?</Text>
          <Text style={styles.sub}>
            This transfer matches how scam payments happen — a caller guiding you to send money to a
            "safe account". No one from Demo Bank will ever ask you to do that. If you were told to make
            this payment, stop now.
          </Text>
          <Btn label="Cancel — this doesn't feel right" onPress={onDone} />
          <Btn label="No one told me to do this — continue" ghost
            onPress={() => setDone('Payment sent after scam-warning acknowledgement.')} />
        </Card>
      );
    }
    return (
      <Card center>
        <Badge color={C.warn} icon="↑" />
        <Text style={styles.h2}>Extra verification needed</Text>
        <Text style={styles.sub}>This transfer looks unusual — enter a one-time code.</Text>
        <TextInput style={[styles.input, styles.otp]} value={otp} onChangeText={setOtp} placeholder="••••••" keyboardType="number-pad" maxLength={6} />
        <Btn label="Verify & send" onPress={() => setDone('Verified — the payment is on its way.')} />
        <Btn label="Back to account" ghost onPress={onDone} />
      </Card>
    );
  }
  if (d.decision === 'HOLD') {
    return (
      <Card center>
        <Badge color={C.stop} icon="!" />
        <Text style={styles.h2}>Payment held for review</Text>
        <Text style={styles.sub}>Paused for a security review — no money has left your account.</Text>
        <Btn label="Back to account" ghost onPress={onDone} />
      </Card>
    );
  }
  return (
    <Card center>
      <Badge color={C.stop} icon="!" />
      <Text style={styles.h2}>Couldn’t reach the bank</Text>
      <Text style={styles.sub}>Check the backend is running and reachable.</Text>
      <Btn label="Back" ghost onPress={onDone} />
    </Card>
  );
}

function VerawallPanel({ verdict, shareSim, onToggleShare, callSim, onToggleCall,
  preventShots, onTogglePreventShots, shotSeen }: {
  verdict: Decision | null; shareSim: boolean; onToggleShare: (v: boolean) => void;
  callSim: boolean; onToggleCall: (v: boolean) => void;
  preventShots: boolean; onTogglePreventShots: (v: boolean) => void; shotSeen: boolean;
}) {
  const band = verdict?.decision;
  return (
    <View style={styles.vw}>
      <View style={styles.vwHead}>
        <View style={styles.vwDot}><Text style={styles.vwDotTxt}>V</Text></View>
        <View>
          <Text style={styles.vwTitle}>Verawall</Text>
          <Text style={styles.vwTag}>BEHAVIORAL INTELLIGENCE</Text>
        </View>
      </View>
      {!band && <Text style={styles.muted}>Session bound. Touch, keystroke and device signals are captured — timing only, never content.</Text>}
      {band && (
        <>
          <Text style={styles.muted}>The bank's backend called /v1/score with the session token. Verdict:</Text>
          <View style={styles.vwVerdict}>
            <View style={[styles.pill, { backgroundColor: bandBg[band], }]}>
              <Text style={[styles.pillTxt, { color: bandColor[band] }]}>{band.replace('_', ' ')}</Text>
            </View>
            <Text style={[styles.score, { color: bandColor[band] }]}>{verdict?.riskScore}</Text>
          </View>
          {verdict?.threatType ? (
            <Text style={styles.muted}>Classification: <Text style={styles.b}>{verdict.threatType}</Text>{verdict.alertId ? ` · alert ${verdict.alertId}` : ''}</Text>
          ) : null}
          {(verdict?.signals ?? []).map((s, i) => (
            <View key={i} style={styles.sig}>
              <Text style={styles.sigW}>+{s.weight}</Text>
              <View style={{ flex: 1 }}>
                <Text style={styles.sigLab}>{s.label}</Text>
                {!!s.evidence && <Text style={styles.sigEv}>{s.evidence}</Text>}
              </View>
            </View>
          ))}
        </>
      )}
      <View style={styles.demoCtl}>
        <View style={styles.ctlRow}>
          <Text style={styles.ctlLabel}>Simulate screen-share</Text>
          <Switch value={shareSim} onValueChange={onToggleShare} />
        </View>
        <View style={styles.ctlRow}>
          <Text style={styles.ctlLabel}>Simulate active call</Text>
          <Switch value={callSim} onValueChange={onToggleCall} />
        </View>
        <View style={styles.ctlRow}>
          <Text style={styles.ctlLabel}>Prevent screenshots</Text>
          <Switch value={preventShots} onValueChange={onTogglePreventShots} />
        </View>
        <Text style={styles.hint}>Screen-share / call stand in for the native modules (Expo Go can't run native
          code; the simulator can't place calls). "Prevent screenshots" blocks capture on this screen for real
          via expo-screen-capture — try screenshotting with it on vs. off.</Text>
        {shotSeen && (
          <Text style={[styles.hint, { color: C.stop, fontWeight: '700' }]}>
            Screenshot detected — PASSIVE_SCREENSHOT sent to Verawall. Under coaching, never share screenshots of
            your account or codes.
          </Text>
        )}
      </View>
    </View>
  );
}

// ---------- little building blocks ----------
const Card = ({ children, center }: { children: React.ReactNode; center?: boolean }) => (
  <View style={[styles.card, center && styles.center]}>{children}</View>
);
const Btn = ({ label, onPress, ghost, disabled }: { label: string; onPress: () => void; ghost?: boolean; disabled?: boolean }) => (
  <Pressable onPress={onPress} disabled={disabled} style={[styles.btn, ghost && styles.btnGhost, disabled && styles.btnDisabled]}>
    <Text style={[styles.btnTxt, ghost && styles.btnGhostTxt]}>{label}</Text>
  </Pressable>
);
const Badge = ({ color, icon }: { color: string; icon: string }) => (
  <View style={[styles.badge, { backgroundColor: color }]}><Text style={styles.badgeTxt}>{icon}</Text></View>
);

const C = { ink: '#14202b', muted: '#62727f', line: '#e6ebf0', bg: '#eef1f5', brand: '#0a5bd3', brandInk: '#08419a', ok: '#1e9e5a', warn: '#c67c00', stop: '#d71a28', card: '#fff' };
const bandColor: Record<string, string> = { ALLOW: C.ok, STEP_UP: C.warn, HOLD: C.stop };
const bandBg: Record<string, string> = { ALLOW: '#eaf7f0', STEP_UP: '#fbf1e2', HOLD: '#fbeaec' };

const styles = StyleSheet.create({
  app: { flex: 1, backgroundColor: C.bg },
  wrap: { padding: 16, paddingTop: 56, paddingBottom: 48, gap: 16 },
  center: { alignItems: 'center', justifyContent: 'center' },
  topbar: { flexDirection: 'row', alignItems: 'center', gap: 10 },
  logo: { width: 30, height: 30, borderRadius: 8, backgroundColor: C.brand, alignItems: 'center', justifyContent: 'center' },
  logoTxt: { color: '#fff', fontWeight: '800', fontSize: 12 },
  brand: { fontWeight: '800', fontSize: 17, color: C.ink },
  who: { marginLeft: 'auto', fontSize: 12, color: C.muted },

  scam: { flexDirection: 'row', gap: 12, backgroundColor: '#fff4e5', borderWidth: 1, borderColor: '#f0c37a', borderLeftWidth: 4, borderRadius: 10, padding: 14 },
  scamIcon: { fontSize: 20 },
  scamHead: { fontWeight: '800', fontSize: 14, color: '#8a5200', marginBottom: 3 },
  scamSub: { fontSize: 12.5, color: '#6b4c15', lineHeight: 18 },

  card: { backgroundColor: C.card, borderWidth: 1, borderColor: C.line, borderRadius: 12, padding: 20, gap: 4 },
  h2: { fontSize: 19, fontWeight: '800', color: C.ink },
  h3: { fontSize: 15, fontWeight: '800', color: C.ink, marginBottom: 4 },
  sub: { color: C.muted, fontSize: 13, marginBottom: 8, textAlign: 'center' },
  label: { fontSize: 12, fontWeight: '700', color: C.muted, marginTop: 12, marginBottom: 5 },
  input: { fontSize: 15, padding: 12, borderWidth: 1, borderColor: C.line, borderRadius: 8, backgroundColor: '#fbfcfd', color: C.ink },
  otp: { textAlign: 'center', letterSpacing: 6, marginTop: 12, alignSelf: 'stretch' },

  balance: { fontSize: 34, fontWeight: '800', color: C.ink, marginVertical: 4 },
  balanceCcy: { fontSize: 14, fontWeight: '600', color: C.muted },
  row: { flexDirection: 'row', justifyContent: 'space-between', paddingVertical: 11, borderTopWidth: 1, borderTopColor: C.line },
  rowL: { fontSize: 14, color: C.ink }, rowR: { fontSize: 14, color: C.ink, fontVariant: ['tabular-nums'] },

  preset: { borderWidth: 1, borderColor: C.line, borderRadius: 8, backgroundColor: '#fbfcfd', padding: 12, marginTop: 8 },
  presetSel: { borderColor: C.brand, backgroundColor: '#f2f7ff' },
  presetTitle: { fontWeight: '700', fontSize: 14, color: C.ink }, presetSub: { fontSize: 12.5, color: C.muted, marginTop: 2 },

  btn: { marginTop: 14, padding: 13, borderRadius: 8, backgroundColor: C.brand, alignItems: 'center', alignSelf: 'stretch' },
  btnGhost: { backgroundColor: '#fff', borderWidth: 1, borderColor: C.line },
  btnDisabled: { opacity: 0.55 },
  btnTxt: { color: '#fff', fontWeight: '700', fontSize: 15 }, btnGhostTxt: { color: C.brand },
  badge: { width: 56, height: 56, borderRadius: 28, alignItems: 'center', justifyContent: 'center', marginBottom: 10 },
  badgeTxt: { color: '#fff', fontSize: 26, fontWeight: '800' },

  vw: { backgroundColor: C.card, borderWidth: 1, borderColor: C.line, borderRadius: 12, padding: 18, gap: 8 },
  vwHead: { flexDirection: 'row', alignItems: 'center', gap: 8, marginBottom: 4 },
  vwDot: { width: 20, height: 20, borderRadius: 5, backgroundColor: C.stop, alignItems: 'center', justifyContent: 'center' },
  vwDotTxt: { color: '#fff', fontWeight: '800', fontSize: 12 },
  vwTitle: { fontWeight: '800', fontSize: 14, color: C.ink }, vwTag: { fontSize: 9.5, letterSpacing: 1, color: C.muted, fontWeight: '700' },
  vwVerdict: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', marginVertical: 6 },
  pill: { paddingHorizontal: 12, paddingVertical: 6, borderRadius: 999 }, pillTxt: { fontWeight: '800', fontSize: 13 },
  score: { fontWeight: '800', fontSize: 22 },
  sig: { flexDirection: 'row', gap: 8, paddingVertical: 8, borderTopWidth: 1, borderTopColor: C.line },
  sigW: { fontWeight: '800', color: C.stop, width: 32 }, sigLab: { color: C.ink, fontWeight: '600', fontSize: 13 }, sigEv: { color: C.muted, fontSize: 11.5, marginTop: 1 },

  demoCtl: { marginTop: 12, paddingTop: 12, borderTopWidth: 1, borderTopColor: C.line, borderStyle: 'dashed' },
  ctlRow: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' },
  ctlLabel: { fontSize: 13, fontWeight: '600', color: C.ink },
  hint: { fontSize: 10.5, color: C.muted, marginTop: 5 },

  muted: { color: C.muted, fontSize: 12.5, lineHeight: 18 },
  b: { fontWeight: '800', color: C.ink },
});
