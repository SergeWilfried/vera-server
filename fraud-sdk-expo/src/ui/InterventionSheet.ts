// Drop-in intervention UI — the screen a bank shows when /v1/score says
// STEP_UP or HOLD. Localized (EN/FR), self-contained (no dependencies
// beyond react-native), and wired to the SDK: outcomes are reported back
// automatically (BIZ_STEP_UP_RESULT for scoring, BIZ_INTERVENTION_RESULT
// for the audit trail), so the "step-up outcome" scoring signals work
// without any extra integration.
//
//   const [verdict, setVerdict] = useState<Decision | null>(null);
//   ...
//   <InterventionSheet
//     decision={verdict}
//     bankName="Demo Bank"
//     locale="fr"
//     onVerify={(code) => bank.verifyOtp(code)}   // IDENTITY only
//     onResult={(r) => {
//       if (r.action === 'ACKNOWLEDGED' || r.action === 'VERIFIED') releasePayment();
//       else returnToAccount();
//     }}
//   />
//
// Three variants, chosen from the decision's `intervention`:
//   SCAM_WARNING   coached-fraud warning — Cancel (primary) / Continue.
//                  The victim IS the account owner, so this is friction
//                  they must read, not a challenge they would pass.
//   IDENTITY       one-time-code challenge; the bank verifies via onVerify.
//   ANALYST_REVIEW / HOLD   informational: payment held, nothing left the
//                  account.
// ALLOW (or no intervention) renders nothing.

import { createElement as h, useState, type ReactNode } from 'react';
import { Modal, Pressable, StyleSheet, Text, TextInput, View } from 'react-native';
import { BusinessEvent } from '../events';

export interface InterventionDecision {
  decision?: string; // ALLOW | STEP_UP | HOLD
  intervention?: string; // SCAM_WARNING | IDENTITY | ANALYST_REVIEW
  threatType?: string;
}

export type InterventionAction = 'CANCELLED' | 'ACKNOWLEDGED' | 'VERIFIED' | 'CLOSED';
export interface InterventionResult {
  action: InterventionAction;
}

export interface InterventionSheetProps {
  /** The /v1/score response (or null — renders nothing). */
  decision: InterventionDecision | null;
  /** Shown inside the warning copy ("… {bankName} will never ask …"). */
  bankName?: string;
  locale?: 'en' | 'fr';
  /** Primary-action color; defaults to a neutral banking blue. */
  accentColor?: string;
  /** IDENTITY only: verify the one-time code against YOUR backend.
   *  Return true to accept. Without it, any submitted code is accepted
   *  (demo mode) — always provide it in production. */
  onVerify?: (code: string) => Promise<boolean> | boolean;
  /** Called exactly once with how the customer resolved the sheet. */
  onResult: (result: InterventionResult) => void;
}

const STRINGS = {
  en: {
    scamTitle: 'Is someone helping you with this payment?',
    scamBody: (bank: string) =>
      `This transfer matches the pattern of coached fraud — a caller or chat guiding you to move money to a "safe account". ${bank} will never ask you to do this. If someone asked you to make this payment, stop now.`,
    scamCancel: "Cancel — this doesn't feel right",
    scamContinue: 'No one asked me — continue',
    otpTitle: 'Extra verification required',
    otpBody: 'This payment looks unusual for your account. Enter the one-time code to continue.',
    otpPlaceholder: '••••••',
    otpVerify: 'Verify and send',
    otpWrong: "That code didn't match — try again.",
    otpCancel: 'Cancel payment',
    holdTitle: 'Payment held for review',
    holdBody: 'This payment was paused for a security check — no money has left your account. Our fraud team is reviewing it now.',
    holdClose: 'Back to account',
  },
  fr: {
    scamTitle: 'Quelqu’un vous aide-t-il pour ce paiement ?',
    scamBody: (bank: string) =>
      `Ce virement correspond au schéma des paiements sous influence — un appelant ou un chat qui vous guide vers un « compte sécurisé ». ${bank} ne vous demandera jamais cela. Si on vous a demandé de faire ce paiement, arrêtez maintenant.`,
    scamCancel: 'Annuler — ça ne me semble pas normal',
    scamContinue: 'Personne ne me l’a demandé — continuer',
    otpTitle: 'Vérification supplémentaire requise',
    otpBody: 'Ce paiement semble inhabituel pour votre compte. Saisissez le code à usage unique pour continuer.',
    otpPlaceholder: '••••••',
    otpVerify: 'Vérifier et envoyer',
    otpWrong: 'Ce code ne correspond pas — réessayez.',
    otpCancel: 'Annuler le paiement',
    holdTitle: 'Paiement mis en attente',
    holdBody: 'Ce paiement est suspendu pour un contrôle de sécurité — aucun montant n’a quitté votre compte. Notre équipe antifraude l’examine.',
    holdClose: 'Retour au compte',
  },
} as const;

// Reporting hooks are injected by the SDK entry (avoids a circular import).
type Reporter = { event: (e: BusinessEvent) => void; flush: () => Promise<void> };
let reporter: Reporter | null = null;
/** @internal wired by FraudSdk.init */
export function _setReporter(r: Reporter): void {
  reporter = r;
}

function report(e: BusinessEvent): void {
  try {
    reporter?.event(e);
    void reporter?.flush();
  } catch {
    /* reporting must never break the sheet */
  }
}

const st = StyleSheet.create({
  backdrop: { flex: 1, backgroundColor: 'rgba(15,20,24,0.55)', justifyContent: 'flex-end' },
  sheet: { backgroundColor: '#fff', borderTopLeftRadius: 16, borderTopRightRadius: 16, padding: 24, paddingBottom: 34 },
  badge: { width: 52, height: 52, borderRadius: 26, alignSelf: 'center', alignItems: 'center', justifyContent: 'center', marginBottom: 14 },
  badgeTxt: { color: '#fff', fontSize: 24, fontWeight: '800' },
  title: { fontSize: 19, fontWeight: '800', color: '#14202B', textAlign: 'center' },
  body: { fontSize: 14, color: '#5A6976', lineHeight: 21, textAlign: 'center', marginTop: 10 },
  btn: { marginTop: 12, padding: 14, borderRadius: 8, alignItems: 'center' },
  btnTxt: { color: '#fff', fontWeight: '700', fontSize: 15 },
  btnGhost: { backgroundColor: '#fff', borderWidth: 1, borderColor: '#E3E7EB' },
  btnGhostTxt: { fontWeight: '700', fontSize: 15, color: '#5A6976' },
  otp: { marginTop: 16, borderWidth: 1, borderColor: '#E3E7EB', borderRadius: 8, padding: 12, fontSize: 18, textAlign: 'center', letterSpacing: 6, color: '#14202B', backgroundColor: '#FBFCFD' },
  err: { color: '#D71A28', fontSize: 12.5, textAlign: 'center', marginTop: 8, fontWeight: '600' },
});

export function InterventionSheet(props: InterventionSheetProps): ReactNode {
  const { decision, onResult, onVerify } = props;
  const bank = props.bankName ?? 'Your bank';
  const accent = props.accentColor ?? '#0A5BD3';
  const t = STRINGS[props.locale ?? 'en'];

  const [code, setCode] = useState('');
  const [error, setError] = useState(false);
  const [busy, setBusy] = useState(false);

  const kind =
    decision == null || decision.decision === 'ALLOW' || !decision.decision
      ? null
      : decision.intervention === 'SCAM_WARNING'
        ? 'SCAM_WARNING'
        : decision.intervention === 'IDENTITY'
          ? 'IDENTITY'
          : 'HOLD'; // ANALYST_REVIEW, plain HOLD, unknown interventions
  if (kind == null) return null;

  const finish = (action: InterventionAction): void => {
    report(BusinessEvent.interventionResult(decision?.intervention ?? kind, action));
    onResult({ action });
  };

  const verify = async (): Promise<void> => {
    if (busy) return;
    setBusy(true);
    try {
      const ok = onVerify ? await onVerify(code) : true;
      if (ok) {
        report(BusinessEvent.stepUpResult('PASS'));
        finish('VERIFIED');
      } else {
        // A failed challenge is a strong ATO escalation — score it.
        report(BusinessEvent.stepUpResult('FAIL'));
        setError(true);
        setCode('');
      }
    } finally {
      setBusy(false);
    }
  };

  let badge: ReactNode;
  let content: ReactNode[];
  if (kind === 'SCAM_WARNING') {
    badge = h(View, { style: [st.badge, { backgroundColor: '#C67C00' }] }, h(Text, { style: st.badgeTxt }, '!'));
    content = [
      h(Text, { key: 't', style: st.title }, t.scamTitle),
      h(Text, { key: 'b', style: st.body }, t.scamBody(bank)),
      h(
        Pressable,
        {
          key: 'cancel',
          style: [st.btn, { backgroundColor: accent }],
          onPress: () => {
            // Cancelling after the warning: report an abandoned step-up so a
            // retry of the same payment in this session scores higher.
            report(BusinessEvent.stepUpResult('ABANDONED'));
            finish('CANCELLED');
          },
        },
        h(Text, { style: st.btnTxt }, t.scamCancel),
      ),
      h(
        Pressable,
        { key: 'go', style: [st.btn, st.btnGhost], onPress: () => finish('ACKNOWLEDGED') },
        h(Text, { style: st.btnGhostTxt }, t.scamContinue),
      ),
    ];
  } else if (kind === 'IDENTITY') {
    badge = h(View, { style: [st.badge, { backgroundColor: accent }] }, h(Text, { style: st.badgeTxt }, '↑'));
    content = [
      h(Text, { key: 't', style: st.title }, t.otpTitle),
      h(Text, { key: 'b', style: st.body }, t.otpBody),
      h(TextInput, {
        key: 'otp',
        style: st.otp,
        value: code,
        onChangeText: (v: string) => {
          setCode(v);
          setError(false);
        },
        placeholder: t.otpPlaceholder,
        keyboardType: 'number-pad',
        maxLength: 6,
        editable: !busy,
      }),
      error ? h(Text, { key: 'err', style: st.err }, t.otpWrong) : null,
      h(
        Pressable,
        {
          key: 'verify',
          style: [st.btn, { backgroundColor: accent, opacity: code.length >= 4 && !busy ? 1 : 0.5 }],
          disabled: code.length < 4 || busy,
          onPress: () => void verify(),
        },
        h(Text, { style: st.btnTxt }, t.otpVerify),
      ),
      h(
        Pressable,
        {
          key: 'cancel',
          style: [st.btn, st.btnGhost],
          onPress: () => {
            report(BusinessEvent.stepUpResult('ABANDONED'));
            finish('CANCELLED');
          },
        },
        h(Text, { style: st.btnGhostTxt }, t.otpCancel),
      ),
    ];
  } else {
    badge = h(View, { style: [st.badge, { backgroundColor: '#D71A28' }] }, h(Text, { style: st.badgeTxt }, '!'));
    content = [
      h(Text, { key: 't', style: st.title }, t.holdTitle),
      h(Text, { key: 'b', style: st.body }, t.holdBody),
      h(
        Pressable,
        { key: 'close', style: [st.btn, { backgroundColor: accent }], onPress: () => finish('CLOSED') },
        h(Text, { style: st.btnTxt }, t.holdClose),
      ),
    ];
  }

  return h(
    Modal,
    { transparent: true, animationType: 'slide', visible: true, onRequestClose: () => finish(kind === 'SCAM_WARNING' ? 'CANCELLED' : 'CLOSED') },
    h(View, { style: st.backdrop }, h(View, { style: st.sheet }, badge, ...content)),
  );
}
