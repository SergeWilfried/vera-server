// fraud-sdk-web — browser behavioral-fraud SDK.
//
//   FraudSdk.init({ tenantId: 'wallet-acme', siteKey: 'site_wallet-acme_pub' });
//   FraudSdk.session().setUser(await FraudSdk.hash(email));
//   FraudSdk.session().event(BusinessEvent.txnInitiated({ amountBucket: 'HIGH', payeeIsNew: true }));
//   const token = await FraudSdk.session().getToken();  // -> X-Fraud-Session
//   FraudSdk.captureKeystrokes(pinInput, 'login.pin');
//
// Public site-key auth (no secret in the browser); the server mints the
// session token. Privacy: timing/geometry only, never keystroke content;
// identifiers should be hashed via FraudSdk.hash() before setUser.

import type { SdkConfig, SdkEvent } from './types.js';
import { getInstallId, randomId } from './session.js';
import { Transport } from './transport.js';
import { fingerprint } from './collectors/fingerprint.js';
import { attachMouse } from './collectors/mouse.js';
import { attachKeystrokes } from './collectors/keystroke.js';
import { attachNav } from './collectors/nav.js';
import { BusinessEvent } from './events.js';

interface State {
  cfg: Required<SdkConfig>;
  installId: string;
  sessionId: string;
  userRef?: string;
  token?: string;
  transport: Transport;
  detach: Array<() => void>;
}

let state: State | null = null;

function resolveBase(url?: string): string {
  if (url) return url;
  return typeof location !== 'undefined' ? location.origin : 'http://localhost:8080';
}

const sessionApi = {
  setUser(userRef: string): void {
    if (!state) return;
    state.userRef = userRef;
    void refreshToken();
  },
  clearUser(): void {
    if (!state) return;
    state.userRef = undefined;
    state.sessionId = randomId();
    void refreshToken();
  },
  event(e: BusinessEvent): void {
    if (!state) return;
    enqueue(e.type, e.payload);
  },
  screenView(screenId: string): void {
    if (!state) return;
    enqueue('SCREEN_VIEWED', { screenId });
  },
  async getToken(): Promise<string> {
    if (!state) return '';
    if (!state.token) await refreshToken();
    return state.token || '';
  },
};

function enqueue(type: string, payload: unknown): void {
  if (!state) return;
  const ev: SdkEvent = {
    type, sessionId: state.sessionId, installId: state.installId,
    userRef: state.userRef, ts: Date.now(), payload,
  };
  state.transport.enqueue(ev);
}

async function refreshToken(): Promise<void> {
  if (!state) return;
  try {
    const res = await fetch(resolveBase(state.cfg.collectorUrl) + '/v1/collect/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json',
                 'X-Tenant-Id': state.cfg.tenantId, 'X-Site-Key': state.cfg.siteKey },
      body: JSON.stringify({ sessionId: state.sessionId, installId: state.installId, userRef: state.userRef }),
    });
    if (res.ok) state.token = (await res.json()).token;
  } catch {
    /* token is best-effort; the bank backend can retry */
  }
}

export const FraudSdk = {
  /** Call once on app start. Idempotent. */
  init(config: SdkConfig): void {
    if (state) return;
    const cfg: Required<SdkConfig> = {
      tenantId: config.tenantId,
      siteKey: config.siteKey,
      collectorUrl: resolveBase(config.collectorUrl),
      sdk: config.sdk ?? 'web/0.1.0',
      flushIntervalMs: config.flushIntervalMs ?? 5000,
    };
    const installId = getInstallId();
    const sessionId = randomId();
    const transport = new Transport(cfg, installId);
    state = { cfg, installId, sessionId, transport, detach: [] };
    transport.start();

    // Passive capture.
    enqueue('PASSIVE_WEB_FINGERPRINT', fingerprint());
    const getUser = () => state?.userRef;
    state.detach.push(attachMouse(installId, sessionId, getUser, (e) => transport.enqueue(e)));
    state.detach.push(attachNav(installId, sessionId, getUser, (e) => transport.enqueue(e)));

    void refreshToken();
  },

  session(): typeof sessionApi {
    return sessionApi;
  },

  /** Opt-in per-field keystroke dynamics (timing only). */
  captureKeystrokes(el: HTMLInputElement | HTMLTextAreaElement, fieldId: string): void {
    if (!state) return;
    state.detach.push(
      attachKeystrokes(el, fieldId, state.installId, state.sessionId, () => state?.userRef,
        (e) => state?.transport.enqueue(e)),
    );
  },

  /** Force-upload queued events (e.g. right before a critical API call). */
  flush(): Promise<void> {
    return state ? state.transport.flush() : Promise.resolve();
  },

  /** SHA-256 hex of an identifier — hash PII before setUser. */
  async hash(value: string): Promise<string> {
    if (typeof crypto !== 'undefined' && crypto.subtle) {
      const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
      return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
    }
    return value;
  },

  /** Test/teardown hook. */
  _reset(): void {
    if (!state) return;
    state.transport.stop();
    state.detach.forEach((d) => d());
    state = null;
  },
};

export { BusinessEvent };
export type { SdkConfig, SdkEvent };
