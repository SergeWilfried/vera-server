// Drop-in intervention UI — the sheet a bank shows when /v1/score says
// STEP_UP or HOLD. Framework-free (plain DOM), localized (EN/FR), and wired
// to the SDK: outcomes are reported back automatically (BIZ_STEP_UP_RESULT
// for scoring, BIZ_INTERVENTION_RESULT for the audit trail).
//
//   const decision = await bank.pay(...);              // your /score call
//   const r = await FraudSdk.showIntervention(decision, {
//     bankName: 'Demo Bank',
//     onVerify: (code) => bank.verifyOtp(code),        // IDENTITY only
//   });
//   if (r.action === 'ACKNOWLEDGED' || r.action === 'VERIFIED') releasePayment();
//
// Variants (chosen from decision.intervention): SCAM_WARNING (coached-fraud
// warning — Cancel primary / Continue), IDENTITY (one-time code, verified by
// YOUR backend via onVerify), and HOLD / ANALYST_REVIEW (informational).
// ALLOW resolves immediately with {action: 'NONE'}.

import type { BusinessEvent } from './events.js';

export interface InterventionDecision {
  decision?: string;
  intervention?: string;
  threatType?: string;
}

export type InterventionAction = 'NONE' | 'CANCELLED' | 'ACKNOWLEDGED' | 'VERIFIED' | 'CLOSED';
export interface InterventionResult {
  action: InterventionAction;
}

export interface InterventionOptions {
  bankName?: string;
  locale?: 'en' | 'fr';
  /** Primary-action color; defaults to a neutral banking blue. */
  accentColor?: string;
  /** IDENTITY only: verify the code against YOUR backend; return true to
   *  accept. Without it any submitted code is accepted (demo mode). */
  onVerify?: (code: string) => Promise<boolean> | boolean;
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
    otpVerify: 'Vérifier et envoyer',
    otpWrong: 'Ce code ne correspond pas — réessayez.',
    otpCancel: 'Annuler le paiement',
    holdTitle: 'Paiement mis en attente',
    holdBody: 'Ce paiement est suspendu pour un contrôle de sécurité — aucun montant n’a quitté votre compte. Notre équipe antifraude l’examine.',
    holdClose: 'Retour au compte',
  },
} as const;

type Reporter = { event: (e: BusinessEvent) => void; flush: () => Promise<void> };

const css = (el: HTMLElement, styles: Partial<CSSStyleDeclaration>) => Object.assign(el.style, styles);

function button(label: string, primary: boolean, accent: string): HTMLButtonElement {
  const b = document.createElement('button');
  b.type = 'button';
  b.textContent = label;
  css(b, {
    display: 'block', width: '100%', marginTop: '12px', padding: '14px', borderRadius: '8px',
    fontSize: '15px', fontWeight: '700', cursor: 'pointer', fontFamily: 'inherit',
    background: primary ? accent : '#fff', color: primary ? '#fff' : '#5A6976',
    border: primary ? 'none' : '1px solid #E3E7EB',
  });
  return b;
}

/** Render the intervention for a /v1/score decision; resolves with how the
 *  customer dismissed it. `report` is injected by the SDK entry point. */
export function showIntervention(
  decision: InterventionDecision | null,
  opts: InterventionOptions,
  reporter: Reporter,
  events: {
    stepUpResult: (outcome: 'PASS' | 'FAIL' | 'ABANDONED') => BusinessEvent;
    interventionResult: (intervention: string, action: string) => BusinessEvent;
  },
): Promise<InterventionResult> {
  const kind =
    decision == null || !decision.decision || decision.decision === 'ALLOW'
      ? null
      : decision.intervention === 'SCAM_WARNING'
        ? 'SCAM_WARNING'
        : decision.intervention === 'IDENTITY'
          ? 'IDENTITY'
          : 'HOLD';
  if (kind == null) return Promise.resolve({ action: 'NONE' });

  const t = STRINGS[opts.locale ?? 'en'];
  const bank = opts.bankName ?? 'Your bank';
  const accent = opts.accentColor ?? '#0A5BD3';

  const report = (e: BusinessEvent) => {
    try {
      reporter.event(e);
      void reporter.flush();
    } catch {
      /* reporting must never break the sheet */
    }
  };

  return new Promise((resolve) => {
    const overlay = document.createElement('div');
    overlay.setAttribute('data-vw-intervention', kind);
    css(overlay, {
      position: 'fixed', inset: '0', background: 'rgba(15,20,24,0.55)', zIndex: '2147483000',
      display: 'flex', alignItems: 'flex-end', justifyContent: 'center',
    });
    const sheet = document.createElement('div');
    sheet.setAttribute('role', 'alertdialog');
    sheet.setAttribute('aria-modal', 'true');
    css(sheet, {
      background: '#fff', borderRadius: '16px 16px 0 0', padding: '24px 24px 34px',
      width: '100%', maxWidth: '440px', boxSizing: 'border-box',
      fontFamily: 'inherit', textAlign: 'center',
    });
    overlay.appendChild(sheet);

    const badge = document.createElement('div');
    css(badge, {
      width: '52px', height: '52px', borderRadius: '26px', margin: '0 auto 14px',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      color: '#fff', fontSize: '24px', fontWeight: '800',
      background: kind === 'SCAM_WARNING' ? '#C67C00' : kind === 'IDENTITY' ? accent : '#D71A28',
    });
    badge.textContent = kind === 'IDENTITY' ? '↑' : '!';
    const title = document.createElement('div');
    css(title, { fontSize: '19px', fontWeight: '800', color: '#14202B' });
    const body = document.createElement('div');
    css(body, { fontSize: '14px', color: '#5A6976', lineHeight: '1.5', marginTop: '10px' });
    sheet.append(badge, title, body);

    const finish = (action: InterventionAction) => {
      report(events.interventionResult(decision?.intervention ?? kind, action));
      overlay.remove();
      resolve({ action });
    };

    if (kind === 'SCAM_WARNING') {
      title.textContent = t.scamTitle;
      body.textContent = t.scamBody(bank);
      const cancel = button(t.scamCancel, true, accent);
      cancel.onclick = () => {
        // Cancelling after the warning: report an abandoned step-up so a
        // retry of the same payment in this session scores higher.
        report(events.stepUpResult('ABANDONED'));
        finish('CANCELLED');
      };
      const go = button(t.scamContinue, false, accent);
      go.onclick = () => finish('ACKNOWLEDGED');
      sheet.append(cancel, go);
    } else if (kind === 'IDENTITY') {
      title.textContent = t.otpTitle;
      body.textContent = t.otpBody;
      const input = document.createElement('input');
      input.inputMode = 'numeric';
      input.maxLength = 6;
      input.placeholder = '••••••';
      css(input, {
        display: 'block', width: '100%', boxSizing: 'border-box', marginTop: '16px',
        border: '1px solid #E3E7EB', borderRadius: '8px', padding: '12px', fontSize: '18px',
        textAlign: 'center', letterSpacing: '6px', background: '#FBFCFD', color: '#14202B',
      });
      const err = document.createElement('div');
      css(err, { color: '#D71A28', fontSize: '12.5px', marginTop: '8px', fontWeight: '600', display: 'none' });
      err.textContent = t.otpWrong;
      const verify = button(t.otpVerify, true, accent);
      verify.onclick = async () => {
        verify.disabled = true;
        const ok = opts.onVerify ? await opts.onVerify(input.value) : true;
        if (ok) {
          report(events.stepUpResult('PASS'));
          finish('VERIFIED');
        } else {
          // A failed challenge is a strong ATO escalation — score it.
          report(events.stepUpResult('FAIL'));
          err.style.display = 'block';
          input.value = '';
          verify.disabled = false;
        }
      };
      const cancel = button(t.otpCancel, false, accent);
      cancel.onclick = () => {
        report(events.stepUpResult('ABANDONED'));
        finish('CANCELLED');
      };
      sheet.append(input, err, verify, cancel);
      setTimeout(() => input.focus(), 50);
    } else {
      title.textContent = t.holdTitle;
      body.textContent = t.holdBody;
      const close = button(t.holdClose, true, accent);
      close.onclick = () => finish('CLOSED');
      sheet.append(close);
    }

    document.body.appendChild(overlay);
  });
}
