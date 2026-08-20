// Demo Bank (Expo) — jumeau mobile de fraud-sdk-web/demo. Connexion → tableau de
// bord → virement → verdict ALLOW / STEP-UP / HOLD en direct, évalué par Verawall.
// Le backend de la banque appelle /v1/score de serveur à serveur ; l'app ne fait
// que prouver la session via le SDK.
//
// Partage d'écran / appel : Expo Go n'exécute pas de code natif, donc les
// interrupteurs « Simuler … » les remplacent via FraudSdk.reportRemoteAccess() /
// reportCallState(). En dev build, les modules natifs les détectent pour de vrai.

import React, { useEffect, useMemo, useState } from 'react';
import {
  ActivityIndicator, Pressable, ScrollView, StyleSheet, Switch, Text, TextInput, View,
} from 'react-native';
import { StatusBar } from 'expo-status-bar';
import Constants from 'expo-constants';
import { FraudSdk, BusinessEvent, InterventionSheet, type LocalRisk } from '@veratools/fraud-sdk-expo';

// Dev : joindre la machine de dev depuis le simulateur/appareil via l'IP hôte de
// Metro. Build déployé : EXPO_PUBLIC_COLLECTOR_URL (et éventuellement
// EXPO_PUBLIC_BANK_BACKEND) au build — avec une URL de collecteur et sans backend
// bancaire, l'app appelle /v1/score directement. Raccourci DÉMO uniquement pour
// qu'un APK autonome fonctionne sans déployer server.mjs ; une vraie intégration
// garde l'appel de score de serveur à serveur derrière le backend de la banque.
const HOST = (Constants.expoConfig?.hostUri ?? 'localhost:8081').split(':')[0];
const COLLECTOR = process.env.EXPO_PUBLIC_COLLECTOR_URL ?? `http://${HOST}:8080`;
const BACKEND = process.env.EXPO_PUBLIC_BANK_BACKEND ??
  (process.env.EXPO_PUBLIC_COLLECTOR_URL ? '' : `http://${HOST}:8099`);
const TENANT = 'wallet-acme';
const SITE_KEY = 'site_wallet-acme_pub';
// Identifiant natif du tenant (X-App-Key) — requis hors navigateur.
const APP_KEY = process.env.EXPO_PUBLIC_APP_KEY ?? 'app_wallet-acme_native';

// Identité HACHÉE, gardée stable : c'est le profil comportemental que le serveur
// de démo connaît (historique, médiane des montants). NE PAS changer, sinon les
// scénarios STEP-UP/HOLD sous-évaluent. Le persona AFFICHÉ, lui, est francophone.
const DEMO_REF = 'olivia@demobank.cz';
const PERSONA = { name: 'Awa Diallo', phone: '+225 07 88 •• 12' };

type Tone = 'ok' | 'warn' | 'stop';
type Preset = {
  id: string; title: string; sub: string; amount: number; newPayee: boolean; rushed?: boolean;
  threat: string; tone: Tone;
  /** Id stable -> bénéficiaire récurrent ; absent -> nouveau bénéficiaire à chaque envoi. */
  payee?: string;
  /** Demandes antérieures au même bénéficiaire, évaluées d'abord — l'escalade. */
  story?: number[];
  /** Rafale : N virements rapides d'affilée pour faire monter la vélocité. */
  burst?: number;
};
const PRESETS: Preset[] = [
  { id: 'rent', title: 'Payer le loyer', sub: '8 000 FCFA · bénéficiaire connu', amount: 8000, newPayee: false, payee: 'PAYEE-RENT', threat: 'Légitime', tone: 'ok' },
  { id: 'attack', title: 'Nouveau bénéficiaire — gros montant', sub: '150 000 FCFA · première fois', amount: 150000, newPayee: true, threat: 'Prise de contrôle', tone: 'stop' },
  { id: 'coached', title: 'Virement sous coaching', sub: '90 000 FCFA · bénéficiaire ajouté à l’instant', amount: 90000, newPayee: true, rushed: true, threat: 'Arnaque APP', tone: 'stop' },
  { id: 'invest', title: 'Arnaque à l’investissement — les demandes montent', sub: '3 000 → 5 400 → 9 800 déjà envoyés à un « conseiller » · puis le montant ci-dessous', amount: 30000, newPayee: false, story: [3000, 5400, 9800], threat: 'Arnaque investissement', tone: 'stop' },
  { id: 'drain', title: 'Rafale de virements — vidage de compte', sub: '8 virements rapides du montant ci-dessous · la vélocité passe de ALLOW à HOLD', amount: 12000, newPayee: false, payee: 'PAYEE-DRAIN', burst: 8, threat: 'Vidage de compte', tone: 'stop' },
];

type Intervention = 'SCAM_WARNING' | 'IDENTITY' | 'ANALYST_REVIEW';
type Decision = {
  decision?: 'ALLOW' | 'STEP_UP' | 'HOLD';
  riskScore?: number;
  threatType?: string;
  intervention?: Intervention;
  alertId?: string;
  signals?: { weight: number; label: string; evidence?: string }[];
};

const INTERVENTION_FR: Record<Intervention, string> = {
  SCAM_WARNING: 'Avertissement anti-arnaque (pas de défi d’identité)',
  IDENTITY: 'Défi d’identité (code à usage unique)',
  ANALYST_REVIEW: 'Revue analyste / blocage',
};

const fmt = (n: number) => n.toLocaleString('fr-FR');

export default function App() {
  const [ready, setReady] = useState(false);
  const [screen, setScreen] = useState<'login' | 'dashboard' | 'transfer' | 'outcome'>('login');
  const [balance, setBalance] = useState(184320);
  const [pin, setPin] = useState('481920');
  const [pick, setPick] = useState<Preset>(PRESETS[0]);
  const [amountStr, setAmountStr] = useState(String(PRESETS[0].amount));
  const [lastAmount, setLastAmount] = useState(0);
  const [verdict, setVerdict] = useState<Decision | null>(null);
  const [riskReasons, setRiskReasons] = useState<string[]>([]);
  const [shareSim, setShareSim] = useState(false);
  const [callSim, setCallSim] = useState(false);
  const [preventShots, setPreventShots] = useState(false);
  const [shotSeen, setShotSeen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState('');
  const [seeded, setSeeded] = useState(false);
  const [terminated, setTerminated] = useState(false);

  useEffect(() => {
    (async () => {
      // heartbeatMs court en démo : le coupe-circuit analyste doit se voir en
      // quelques secondes sur scène (défaut SDK : 30 s).
      await FraudSdk.init({ tenantId: TENANT, siteKey: SITE_KEY, appKey: APP_KEY,
        collectorUrl: COLLECTOR, flushIntervalMs: 2000, heartbeatMs: 5000 });
      FraudSdk.onLocalRisk((r: LocalRisk) => setRiskReasons(r.reasons));
      FraudSdk.onScreenshot(() => setShotSeen(true));
      // Coupe-circuit analyste : quand un analyste met fin à la session depuis
      // la console, le SDK a déjà délié l'utilisateur et fait tourner la
      // session — l'application doit forcer la déconnexion.
      FraudSdk.onSessionTerminated(() => setTerminated(true));
      setReady(true);
    })();
  }, []);

  function togglePreventShots(v: boolean) {
    setPreventShots(v);
    void FraudSdk.preventScreenCapture(v);
  }

  const touch = useMemo(() => (ready ? FraudSdk.touch() : { panHandlers: {}, flush: () => {} }), [ready]);
  const pinTrack = useMemo(() => FraudSdk.trackInput('login.pin'), []);

  function choose(p: Preset) {
    setPick(p);
    setAmountStr(String(p.amount));
  }

  // Profil de référence. Le moteur compare chaque montant à l'historique du
  // client : un appareil neuf n'en a aucun, donc tout paraît « normal » et les
  // scénarios STEP-UP restent hors d'atteinte. On rejoue donc trois petits
  // paiements approuvés à la connexion — la médiane (~5 000 FCFA) existe, et
  // un virement de 90 000 se lit alors comme très au-dessus du profil, comme
  // sur un vrai compte.
  const SEED_AMOUNTS = [4200, 5000, 5600];

  async function seedProfile(): Promise<void> {
    try {
      const token = await FraudSdk.session().getToken();
      if (!token) return;
      const run = Date.now();
      for (let i = 0; i < SEED_AMOUNTS.length; i++) {
        await scorePayment(token, SEED_AMOUNTS[i], false, 'PAYEE-SEED', `SEED-${run}-${i}`);
      }
      setSeeded(true);
    } catch {
      /* démo : sans profil, seuls les scénarios de montant sont atténués */
    }
  }

  async function login() {
    setProgress('Préparation du profil…');
    setBusy(true);
    try {
      // Await it: resolves once a token bound to this user exists, so the first
      // /v1/score after login sees the customer's profile (known device, history).
      await FraudSdk.session().setUser(await FraudSdk.hash(DEMO_REF));
      FraudSdk.session().event(BusinessEvent.loginResult('SUCCESS'));
      await seedProfile();
      FraudSdk.session().screenView('dashboard');
      setScreen('dashboard');
    } finally {
      setBusy(false);
      setProgress('');
    }
  }

  async function scorePayment(token: string, amount: number, payeeNew: boolean, payeeRef: string, txnRef?: string): Promise<Decision> {
    const res = BACKEND
      ? await fetch(`${BACKEND}/demo/pay`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token, amount, payeeNew, payeeRef }),
        })
      : await fetch(`${COLLECTOR}/v1/score`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            sessionToken: token,
            transaction: {
              txnRef: txnRef ?? 'DEMO-' + Date.now(), amount, currency: 'XOF',
              payeeIsNew: payeeNew, payeeRef, channel: 'BANK_TRANSFER',
            },
          }),
        });
    return res.json();
  }

  async function pay(p: Preset, amount: number) {
    setBusy(true);
    setLastAmount(amount);
    try {
      const payeeRef = p.payee ?? 'demo-payee-' + Date.now();

      // Vélocité (vidage de compte) : une rafale de virements rapides. Chacun
      // émet un BIZ_TXN_INITIATED, donc le compteur TXN_VELOCITY du serveur
      // grimpe et le verdict passe ALLOW → STEP-UP → HOLD. On s'arrête dès le
      // blocage — les premiers passent (le solde baisse), le drain est stoppé.
      if (p.burst) {
        let last: Decision = {};
        for (let i = 0; i < p.burst; i++) {
          setProgress(`Virement ${i + 1}/${p.burst}…`);
          FraudSdk.session().event(BusinessEvent.txnInitiated({
            amountBucket: amount >= 50000 ? 'HIGH' : 'MID', currency: 'XOF', payeeIsNew: false, channel: 'BANK_TRANSFER',
          }));
          await FraudSdk.flush();
          const token = await FraudSdk.session().getToken();
          last = await scorePayment(token, amount, false, payeeRef);
          if (last.decision === 'ALLOW') setBalance((b) => b - amount);
          if (last.decision === 'HOLD') break;
        }
        setVerdict(last);
        setScreen('outcome');
        return;
      }

      if (p.rushed) FraudSdk.session().event(BusinessEvent.payeeAdded(payeeRef));
      FraudSdk.session().event(BusinessEvent.txnInitiated({
        amountBucket: amount >= 50000 ? 'HIGH' : 'MID', currency: 'XOF', payeeIsNew: p.newPayee, channel: 'BANK_TRANSFER',
      }));
      await FraudSdk.flush();
      const token = await FraudSdk.session().getToken();
      // Escalade : les demandes antérieures, plus petites, au même bénéficiaire —
      // évaluées d'abord pour que l'historique par bénéficiaire porte le motif
      // ascendant que la demande finale vient compléter.
      for (const prior of p.story ?? []) {
        const past = await scorePayment(token, prior, false, payeeRef);
        if (past.decision === 'ALLOW') setBalance((b) => b - prior);
      }
      const d = await scorePayment(token, amount, p.newPayee, payeeRef);
      setVerdict(d);
      if (d.decision === 'ALLOW') setBalance((b) => b - amount);
      setScreen('outcome');
    } catch (e) {
      setVerdict({ decision: undefined, signals: [{ weight: 0, label: 'Erreur réseau', evidence: String(e) }] });
      setScreen('outcome');
    } finally {
      setBusy(false);
      setProgress('');
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
        <Text style={styles.muted}>Démarrage du SDK Verawall…</Text>
      </View>
    );
  }

  // Coupe-circuit : un analyste a terminé la session depuis la console.
  if (terminated) {
    return (
      <View style={[styles.app, styles.center, { padding: 24 }]}>
        <Badge color={C.stop} icon="!" />
        <Text style={styles.h2}>Session terminée</Text>
        <Text style={styles.sub}>
          Un analyste antifraude a mis fin à cette session depuis la console Verawall — le SDK a
          délié le compte et fait tourner l’identifiant de session sur l’appareil. Reconnectez-vous
          pour continuer.
        </Text>
        <Btn
          label="Se reconnecter"
          onPress={() => {
            setTerminated(false);
            setVerdict(null);
            setSeeded(false);
            setScreen('login');
          }}
        />
      </View>
    );
  }

  const amount = Number(amountStr) || pick.amount;

  return (
    <View style={styles.app} {...(touch.panHandlers as object)}>
      <StatusBar style="dark" />
      <ScrollView contentContainerStyle={styles.wrap}>
        <View style={styles.topbar}>
          <View style={styles.logo}><Text style={styles.logoTxt}>DB</Text></View>
          <Text style={styles.brand}>Demo Bank</Text>
          {screen !== 'login' && <Text style={styles.who}>{PERSONA.name}</Text>}
        </View>

        {riskReasons.includes('SCREEN_SHARE') && (
          <View style={styles.scam}>
            <Text style={styles.scamIcon}>🛡️</Text>
            <View style={{ flex: 1 }}>
              <Text style={styles.scamHead}>Partage d’écran détecté sur cet appareil</Text>
              <Text style={styles.scamSub}>
                Si quelqu’un vous a appelé pour installer une application comme AnyDesk ou TeamViewer, ou regarde
                votre écran en ce moment — raccrochez. Demo Bank ne vous demandera jamais de partager votre écran
                ni de transférer de l’argent vers un « compte sécurisé ».
              </Text>
            </View>
          </View>
        )}
        {riskReasons.includes('ACTIVE_CALL') && (
          <View style={styles.scam}>
            <Text style={styles.scamIcon}>📵</Text>
            <View style={{ flex: 1 }}>
              <Text style={styles.scamHead}>Vous êtes en communication</Text>
              <Text style={styles.scamSub}>
                Personne de Demo Bank n’est en ligne avec vous. Nos agents ne restent jamais au téléphone pendant
                un envoi d’argent — si l’appelant vous guide pour effectuer un virement, raccrochez maintenant.
              </Text>
            </View>
          </View>
        )}

        {screen === 'login' && (
          <Card>
            <Text style={styles.h2}>Se connecter</Text>
            <Text style={styles.sub}>Client de démonstration — identifiants pré-remplis.</Text>
            <Text style={styles.label}>Téléphone</Text>
            <TextInput style={styles.input} value={PERSONA.phone} editable={false} />
            <Text style={styles.label}>Code PIN</Text>
            <TextInput
              style={styles.input}
              value={pin}
              onChangeText={(t) => { setPin(t); pinTrack.onChangeText(t); }}
              onKeyPress={pinTrack.onKeyPress}
              onBlur={pinTrack.onBlur}
              secureTextEntry
              keyboardType="number-pad"
            />
            <Btn label={busy ? (progress || 'Connexion…') : 'Se connecter'} onPress={login} disabled={busy} />
          </Card>
        )}

        {screen === 'dashboard' && (
          <>
            <Card>
              <Text style={styles.sub}>Compte Mobile Money · {PERSONA.phone}</Text>
              <Text style={styles.balance}>{fmt(balance)} <Text style={styles.balanceCcy}>FCFA</Text></Text>
              <Btn label="Nouveau virement" onPress={() => { FraudSdk.session().screenView('transfer'); setScreen('transfer'); }} />
            </Card>
            <Card>
              <Text style={styles.h3}>Activité récente</Text>
              {[['Salaire — SITAB SA', '+120 000'], ['CIE — facture électricité', '−8 400'], ['Recharge Orange', '−2 000']].map(([a, b]) => (
                <View key={a} style={styles.row}><Text style={styles.rowL}>{a}</Text><Text style={styles.rowR}>{b}</Text></View>
              ))}
            </Card>
          </>
        )}

        {screen === 'transfer' && (
          <Card>
            <Text style={styles.h2}>Envoyer de l’argent</Text>
            <Text style={styles.sub}>Choisissez un scénario — Verawall évalue la session en temps réel.</Text>
            {PRESETS.map((p) => (
              <Pressable key={p.id} onPress={() => choose(p)} style={[styles.preset, pick.id === p.id && styles.presetSel]}>
                <View style={styles.presetHead}>
                  <Text style={styles.presetTitle}>{p.title}</Text>
                  <View style={[styles.threat, { backgroundColor: toneBg[p.tone] }]}>
                    <Text style={[styles.threatTxt, { color: toneColor[p.tone] }]}>{p.threat}</Text>
                  </View>
                </View>
                <Text style={styles.presetSub}>{p.sub}</Text>
              </Pressable>
            ))}
            <Text style={styles.label}>Montant (FCFA)</Text>
            <TextInput style={styles.input} value={amountStr} onChangeText={setAmountStr}
              keyboardType="number-pad" placeholder="0" />
            {amount > balance && (
              <Text style={[styles.sub, { color: C.stop, fontWeight: '700', marginTop: 8 }]}>
                Solde insuffisant — vous avez {fmt(balance)} FCFA.
              </Text>
            )}
            <Btn label={busy ? (progress || 'Vérification…') : `Envoyer ${fmt(amount)} FCFA`}
              onPress={() => pay(pick, amount)} disabled={busy || amount > balance || amount <= 0} />
            <Btn label="Annuler" ghost onPress={() => setScreen('dashboard')} />
          </Card>
        )}

        {screen === 'outcome' && verdict && <Outcome d={verdict} amount={lastAmount} onDone={() => setScreen('dashboard')} onBalance={(amt) => setBalance((b) => b - amt)} />}

        <VerawallPanel verdict={verdict} shareSim={shareSim} onToggleShare={toggleShare}
          callSim={callSim} onToggleCall={toggleCall}
          preventShots={preventShots} onTogglePreventShots={togglePreventShots}
          shotSeen={shotSeen} seeded={seeded} />
      </ScrollView>
    </View>
  );
}

function Outcome({ d, amount, onDone, onBalance }: { d: Decision; amount: number; onDone: () => void; onBalance: (n: number) => void }) {
  const [done, setDone] = useState<null | string>(null);
  if (done) {
    return (
      <Card center>
        <Badge color={C.ok} icon="✓" />
        <Text style={styles.h2}>Paiement envoyé</Text>
        <Text style={styles.sub}>{done}</Text>
        <Btn label="Retour au compte" ghost onPress={onDone} />
      </Card>
    );
  }
  if (d.decision === 'ALLOW') {
    return (
      <Card center>
        <Badge color={C.ok} icon="✓" />
        <Text style={styles.h2}>Paiement envoyé</Text>
        <Text style={styles.sub}>En cours d’envoi. Aucune vérification supplémentaire.</Text>
        <Btn label="Retour au compte" ghost onPress={onDone} />
      </Card>
    );
  }
  if (d.decision === 'STEP_UP' || d.decision === 'HOLD') {
    // Le kit d'intervention du SDK affiche l'écran adapté (avertissement
    // anti-arnaque, code à usage unique, ou paiement suspendu) et rapporte
    // l'issue à la plateforme (BIZ_STEP_UP_RESULT / BIZ_INTERVENTION_RESULT).
    return (
      <Card center>
        <Badge color={d.decision === 'HOLD' ? C.stop : C.warn} icon="…" />
        <Text style={styles.h2}>Vérification Verawall</Text>
        <InterventionSheet
          decision={d}
          bankName="Demo Bank"
          locale="fr"
          accentColor="#0A5BD3"
          onVerify={async (code) => code.length === 6 /* démo : la banque vérifierait côté serveur */}
          onResult={(r) => {
            if (r.action === 'VERIFIED') { onBalance(amount); setDone('Vérifié — le paiement est en cours d’envoi.'); }
            else if (r.action === 'ACKNOWLEDGED') { onBalance(amount); setDone('Paiement envoyé après acquittement de l’avertissement.'); }
            else onDone(); // CANCELLED / CLOSED — rien n'a quitté le compte
          }}
        />
      </Card>
    );
  }
  return (
    <Card center>
      <Badge color={C.stop} icon="!" />
      <Text style={styles.h2}>Impossible de joindre la banque</Text>
      <Text style={styles.sub}>Vérifiez que le serveur est démarré et accessible.</Text>
      <Btn label="Retour" ghost onPress={onDone} />
    </Card>
  );
}

function VerawallPanel({ verdict, shareSim, onToggleShare, callSim, onToggleCall,
  preventShots, onTogglePreventShots, shotSeen, seeded }: {
  verdict: Decision | null; shareSim: boolean; onToggleShare: (v: boolean) => void;
  callSim: boolean; onToggleCall: (v: boolean) => void;
  preventShots: boolean; onTogglePreventShots: (v: boolean) => void; shotSeen: boolean;
  seeded: boolean;
}) {
  const band = verdict?.decision;
  return (
    <View style={styles.vw}>
      <View style={styles.vwHead}>
        <View style={styles.vwDot}><Text style={styles.vwDotTxt}>V</Text></View>
        <View>
          <Text style={styles.vwTitle}>Verawall</Text>
          <Text style={styles.vwTag}>INTELLIGENCE COMPORTEMENTALE</Text>
        </View>
      </View>
      {!band && <Text style={styles.muted}>Session liée. Signaux tactiles, de frappe et appareil capturés — horodatage uniquement, jamais le contenu.</Text>}
      {seeded && !band && (
        <Text style={styles.muted}>
          Profil comportemental : 3 paiements de référence (médiane 5 000 FCFA) — les montants sont
          désormais évalués par rapport à cet historique.
        </Text>
      )}
      {band && (
        <>
          <Text style={styles.muted}>Le backend de la banque a appelé /v1/score avec le jeton de session. Verdict :</Text>
          <View style={styles.vwVerdict}>
            <View style={[styles.pill, { backgroundColor: bandBg[band] }]}>
              <Text style={[styles.pillTxt, { color: bandColor[band] }]}>{band.replace('_', ' ')}</Text>
            </View>
            <Text style={[styles.score, { color: bandColor[band] }]}>{verdict?.riskScore}</Text>
          </View>
          {verdict?.threatType ? (
            <Text style={styles.muted}>Classification : <Text style={styles.b}>{verdict.threatType}</Text>{verdict.alertId ? ` · alerte ${verdict.alertId}` : ''}</Text>
          ) : null}
          {verdict?.intervention ? (
            <View style={styles.reco}>
              <Text style={styles.recoLabel}>ACTION RECOMMANDÉE</Text>
              <Text style={styles.recoTxt}>{INTERVENTION_FR[verdict.intervention]}</Text>
            </View>
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
        <Text style={styles.ctlHead}>SIGNAUX APPAREIL (DÉMO)</Text>
        <View style={styles.ctlRow}>
          <Text style={styles.ctlLabel}>Simuler le partage d’écran</Text>
          <Switch value={shareSim} onValueChange={onToggleShare} />
        </View>
        <View style={styles.ctlRow}>
          <Text style={styles.ctlLabel}>Simuler un appel en cours</Text>
          <Switch value={callSim} onValueChange={onToggleCall} />
        </View>
        <View style={styles.ctlRow}>
          <Text style={styles.ctlLabel}>Bloquer les captures d’écran</Text>
          <Switch value={preventShots} onValueChange={onTogglePreventShots} />
        </View>
        <Text style={styles.hint}>Le partage d’écran et l’appel remplacent les modules natifs (Expo Go n’exécute
          pas de code natif ; le simulateur ne passe pas d’appels). « Bloquer les captures d’écran » empêche
          réellement la capture sur cet écran via expo-screen-capture — essayez une capture activé/désactivé.</Text>
        {shotSeen && (
          <Text style={[styles.hint, { color: C.stop, fontWeight: '700' }]}>
            Capture d’écran détectée — PASSIVE_SCREENSHOT envoyé à Verawall. Sous coaching, ne partagez jamais
            de captures de votre compte ni de vos codes.
          </Text>
        )}
      </View>
    </View>
  );
}

// ---------- briques d'UI ----------
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
const toneColor: Record<Tone, string> = { ok: C.ok, warn: C.warn, stop: C.stop };
const toneBg: Record<Tone, string> = { ok: '#eaf7f0', warn: '#fbf1e2', stop: '#fbeaec' };

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
  presetHead: { flexDirection: 'row', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8 },
  presetTitle: { fontWeight: '700', fontSize: 14, color: C.ink, flex: 1 },
  presetSub: { fontSize: 12.5, color: C.muted, marginTop: 2 },
  threat: { paddingHorizontal: 8, paddingVertical: 2, borderRadius: 999 },
  threatTxt: { fontSize: 10.5, fontWeight: '800' },

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
  reco: { marginTop: 6, backgroundColor: '#f2f7ff', borderRadius: 8, padding: 10 },
  recoLabel: { fontSize: 9.5, letterSpacing: 1, fontWeight: '800', color: C.brandInk },
  recoTxt: { fontSize: 13, fontWeight: '600', color: C.ink, marginTop: 2 },
  sig: { flexDirection: 'row', gap: 8, paddingVertical: 8, borderTopWidth: 1, borderTopColor: C.line },
  sigW: { fontWeight: '800', color: C.stop, width: 32 }, sigLab: { color: C.ink, fontWeight: '600', fontSize: 13 }, sigEv: { color: C.muted, fontSize: 11.5, marginTop: 1 },

  demoCtl: { marginTop: 12, paddingTop: 12, borderTopWidth: 1, borderTopColor: C.line, borderStyle: 'dashed' },
  ctlHead: { fontSize: 9.5, letterSpacing: 1, fontWeight: '800', color: C.muted, marginBottom: 6 },
  ctlRow: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', paddingVertical: 2 },
  ctlLabel: { fontSize: 13, fontWeight: '600', color: C.ink },
  hint: { fontSize: 10.5, color: C.muted, marginTop: 5 },

  muted: { color: C.muted, fontSize: 12.5, lineHeight: 18 },
  b: { fontWeight: '800', color: C.ink },
});
