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
import { getInstall, randomId } from './session.js';
import { Transport, type ServerCommand } from './transport.js';
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
  /** userRef the current token was minted for (undefined = anonymous). */
  tokenUserRef?: string;
  /** Epoch ms the current token was minted; 0 = none. */
  tokenMintedAt: number;
  /** Coalesces concurrent mints into one request. */
  tokenInflight?: Promise<void>;
  transport: Transport;
  detach: Array<() => void>;
  headless: boolean;
  remoteActive: boolean;
  riskCb?: (r: LocalRisk) => void;
  terminatedCb?: (sessionId: string) => void;
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
  /** Bind a (hashed) identity. Resolves once a token for this user has been
   *  minted (or the mint failed) — await it before getToken() when you need
   *  the very next score to see the user's profile; a token requested in the
   *  meantime is re-minted for the new identity anyway. */
  setUser(userRef: string): Promise<void> {
    if (!state) return Promise.resolve();
    state.userRef = userRef;
    return ensureToken().then(() => undefined);
  },
  /** Unbind on logout; rotates the session id. */
  clearUser(): Promise<void> {
    if (!state) return Promise.resolve();
    state.userRef = undefined;
    state.sessionId = randomId();
    return ensureToken().then(() => undefined);
  },
  event(e: BusinessEvent): void {
    if (!state) return;
    enqueue(e.type, e.payload);
  },
  screenView(screenId: string): void {
    if (!state) return;
    enqueue('SCREEN_VIEWED', { screenId });
  },
  /** A session token for the current identity — fresh (re-minted before the
   *  server's 1h expiry) and bound to the current userRef. '' if the SDK is
   *  not initialised or the collector couldn't mint. */
  getToken(): Promise<string> {
    return ensureToken();
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

// The server accepts a token for 1h from mint. Re-mint well before that so a
// token handed to the bank backend never expires while its /score call is in
// flight — a tab left open past an hour would otherwise 401.
const TOKEN_TTL_MS = 45 * 60 * 1000;

/** True when the cached token is fresh AND was minted for the current user. */
function tokenUsable(): boolean {
  if (!state?.token) return false;
  if (state.tokenUserRef !== state.userRef) return false;
  return Date.now() - state.tokenMintedAt < TOKEN_TTL_MS;
}

// Mint a token for the current identity. Concurrent callers share one request;
// the result is only cached when a mint succeeds, so a failure never clobbers
// a still-valid token for the same user.
function refreshToken(): Promise<void> {
  if (!state) return Promise.resolve();
  if (state.tokenInflight) return state.tokenInflight;
  const s = state;
  const userRef = s.userRef;
  const sessionId = s.sessionId;
  let done = false;
  const p = (async () => {
    try {
      const res = await fetch(resolveBase(s.cfg.collectorUrl) + '/v1/collect/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json',
                   'X-Tenant-Id': s.cfg.tenantId, 'X-Site-Key': s.cfg.siteKey },
        body: JSON.stringify({ sessionId, installId: s.installId, userRef }),
      });
      if (res.ok) {
        const token = (await res.json())?.token;
        if (typeof token === 'string' && token) {
          // Only cache if the session hasn't rotated while we were minting
          // (logout or a server kill switch invalidates the old session).
          if (s.sessionId !== sessionId) return;
          s.token = token;
          s.tokenUserRef = userRef;
          s.tokenMintedAt = Date.now();
          return;
        }
      }
      if (s.cfg.debug) console.warn(`[VeraFraudSdk] session token mint failed: HTTP ${res.status} (check tenantId / siteKey / collectorUrl / allowed origins)`);
    } catch (e) {
      if (s.cfg.debug) console.warn('[VeraFraudSdk] session token mint failed:', e);
    } finally {
      done = true;
      s.tokenInflight = undefined;
    }
  })();
  if (!done) s.tokenInflight = p;
  return p;
}

// Resolve to a usable token for the CURRENT identity, minting (at most twice —
// the first attempt may be an in-flight mint for a previous userRef) when the
// cache is empty, stale, or belongs to another user. '' if the collector
// couldn't mint.
async function ensureToken(): Promise<string> {
  for (let i = 0; i < 2 && state && !tokenUsable(); i++) await refreshToken();
  return state && tokenUsable() ? state.token! : '';
}

// Server-issued commands (the action channel's device leg). TERMINATE_SESSION
// is the analyst kill switch: ack inside the dying session, unbind the user,
// rotate the session id (invalidating future tokens for the killed session),
// then notify the host app so it can force logout — the same semantics as the
// Android SDK. Commands for a session other than the current one are stale.
function handleServerCommands(commands: ServerCommand[]): void {
  if (!state) return;
  for (const cmd of commands) {
    if (cmd.kind !== 'TERMINATE_SESSION') continue;
    const current = state.sessionId;
    if (cmd.sessionId && cmd.sessionId !== current) continue; // stale
    enqueue('PASSIVE_COMMAND_ACK', { commandId: cmd.id, kind: 'TERMINATE_SESSION' });
    state.userRef = undefined;
    state.sessionId = randomId();
    state.token = undefined;
    state.tokenUserRef = undefined;
    state.tokenMintedAt = 0;
    void refreshToken();
    try {
      state.terminatedCb?.(current);
    } catch {
      /* host callback must never break the SDK */
    }
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
      debug: config.debug ?? false,
    };
    const install = getInstall();
    const installId = install.id;
    const sessionId = randomId();
    const transport = new Transport(cfg, installId);
    const fp = fingerprint();
    state = { cfg, installId, sessionId, tokenMintedAt: 0, transport, detach: [],
              headless: fp.headless, remoteActive: false };
    transport.onCommands = handleServerCommands;
    transport.start();

    // Passive capture.
    enqueue('PASSIVE_WEB_FINGERPRINT', {
      ...fp,
      firstSeen: install.firstSeen,
      installAgeMs: install.firstSeen != null ? Date.now() - install.firstSeen : null,
    });
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

  /** Notified when a fraud analyst terminates this session from the console
   *  (kill switch). The SDK has already unbound the user and rotated its
   *  session; the host app should force logout and invalidate its own auth
   *  tokens. Arrives within one flush interval. Defense in depth — never the
   *  only logout path. */
  onSessionTerminated(cb: (sessionId: string) => void): void {
    if (state) state.terminatedCb = cb;
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
