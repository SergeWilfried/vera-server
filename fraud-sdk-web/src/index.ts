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

/** Locally-known risk the host app can react to immediately, with no server
 *  round-trip — e.g. to show an anti-scam banner while a transfer is in flight. */
export interface LocalRisk {
  level: 'none' | 'warn';
  reasons: string[]; // e.g. 'AUTOMATION', 'SCREEN_SHARE'
}

interface State {
  cfg: Required<SdkConfig>;
  installId: string;
  sessionId: string;
  userRef?: string;
  token?: string;
  transport: Transport;
  detach: Array<() => void>;
  headless: boolean;
  remoteActive: boolean;
  riskCb?: (r: LocalRisk) => void;
}

let state: State | null = null;

function localRisk(): LocalRisk {
  const reasons: string[] = [];
  if (state?.headless) reasons.push('AUTOMATION');
  if (state?.remoteActive) reasons.push('SCREEN_SHARE');
  return { level: reasons.length ? 'warn' : 'none', reasons };
}

function emitLocalRisk(): void {
  state?.riskCb?.(localRisk());
}

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
    const fp = fingerprint();
    state = { cfg, installId, sessionId, transport, detach: [],
              headless: fp.headless, remoteActive: false };
    transport.start();

    // Passive capture.
    enqueue('PASSIVE_WEB_FINGERPRINT', fp);
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

  /** Subscribe to locally-known risk (automation, reported screen-share). Fires
   *  immediately with the current state, then on every change — so the host app
   *  can raise an anti-scam banner the instant a tell appears, no server needed. */
  onLocalRisk(cb: (r: LocalRisk) => void): void {
    if (!state) return;
    state.riskCb = cb;
    emitLocalRisk();
  },

  /** Report an environment signal the SDK can't see from the page itself.
   *  A native/webview shell that detects screen-sharing or a remote-control
   *  tool (e.g. an Android VirtualDisplay from AnyDesk/TeamViewer) calls this;
   *  it raises local risk for onLocalRisk subscribers AND emits a
   *  PASSIVE_REMOTE_ACCESS event so the server scores REMOTE_ACCESS. In a
   *  pure-web demo with no native shell, a control drives it to show the UX. */
  reportRemoteAccess(active: boolean): void {
    if (!state) return;
    state.remoteActive = !!active;
    if (active) {
      enqueue('PASSIVE_REMOTE_ACCESS', {
        screenShareLikely: true, extraDisplays: 1,
        accessibilitySuspect: false, accessibilityMatches: [],
      });
    }
    emitLocalRisk();
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
