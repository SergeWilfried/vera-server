// fraud-sdk-expo — React Native / Expo behavioral-fraud SDK.
//
//   await FraudSdk.init({ tenantId, siteKey, collectorUrl });
//   FraudSdk.session().setUser(await FraudSdk.hash(email));
//   <TextInput {...FraudSdk.trackInput('login.pin')} />       // keystroke timing
//   <View {...FraudSdk.touch().panHandlers}>…</View>          // touch dynamics
//   FraudSdk.session().event(BusinessEvent.txnInitiated({ amountBucket: 'HIGH' }));
//   const token = await FraudSdk.session().getToken();         // -> bank backend
//   FraudSdk.onLocalRisk(r => setBanner(r.reasons.includes('SCREEN_SHARE')
//     || r.reasons.includes('ACTIVE_CALL')));   // anti-scam banner, no server hop
//
// Emits the same mobile wire as the Android SDK, so the collector and scoring
// treat an RN session identically. Public site-key auth (no secret in the app);
// the session token is minted server-side. Privacy: timing/geometry only, never
// keystroke content; hash identifiers via FraudSdk.hash() before setUser.

import { AppState, type AppStateStatus } from 'react-native';
import type { SdkConfig, SdkEvent, LocalRisk, CallSignals } from './types';
import { Transport, type ServerCommand } from './wire/transport';
import { RiskTracker } from './core/risk';
import { newId, hash as sha256 } from './platform/crypto';
import { getInstall } from './platform/storage';
import { fingerprint } from './platform/device';
import { keystrokeProps, type KeystrokeProps } from './collectors/keystroke';
import { createTouchCapture, type TouchCapture } from './collectors/touch';
import {
  createRemoteAccessWatch,
  type RemoteAccessStatus,
  type RemoteAccessWatch,
} from './collectors/remoteAccess';
import {
  createCallSignalsWatch,
  type CallKind,
  type CallSignalsWatch,
} from './collectors/callSignals';
import {
  createScreenshotWatch,
  preventScreenCapture,
  type ScreenshotWatch,
} from './collectors/screenCapture';
import { BusinessEvent } from './events';
import { _setReporter } from './ui/InterventionSheet';

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
  risk: RiskTracker;
  touch: TouchCapture;
  watch: RemoteAccessWatch;
  callWatch: CallSignalsWatch;
  shotWatch: ScreenshotWatch;
  screenshotCb?: () => void;
  terminatedCb?: (sessionId: string) => void;
  appSub: { remove(): void };
}

let state: State | null = null;

function enqueue(type: string, payload: unknown): void {
  if (!state) return;
  const ev: SdkEvent = {
    type, sessionId: state.sessionId, installId: state.installId,
    userRef: state.userRef, ts: Date.now(), payload,
  };
  // in-call context at the moment of the event (coached-scam signal) — the
  // same top-level wire field the Android SDK stamps on business events
  if (type.startsWith('BIZ_')) {
    const cs = state.callWatch.snapshot();
    if (cs) ev.callSignals = cs;
  }
  state.transport.enqueue(ev);
}

// The server accepts a token for 1h from mint. Re-mint well before that so a
// token handed to the bank backend never expires while its /score call is in
// flight — a session left open past an hour would otherwise 401.
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
      const res = await fetch(s.cfg.collectorUrl.replace(/\/$/, '') + '/v1/collect/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Tenant-Id': s.cfg.tenantId,
          'X-Site-Key': s.cfg.siteKey,
        },
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
      if (__DEV__) console.warn(`[VeraFraudSdk] session token mint failed: HTTP ${res.status} (check tenantId / siteKey / collectorUrl)`);
    } catch (e) {
      if (__DEV__) console.warn('[VeraFraudSdk] session token mint failed:', e);
    } finally {
      done = true;
      s.tokenInflight = undefined;
    }
  })();
  // A synchronous throw path aside, the async body can't finish before this
  // line — but guard anyway so a completed mint never leaves a stale handle.
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

function applyRemoteAccess(active: boolean, status: RemoteAccessStatus): void {
  if (!state) return;
  state.risk.setRemoteAccess(active);
  if (active) enqueue('PASSIVE_REMOTE_ACCESS', status);
}

function applyCallTransition(active: boolean, kind: CallKind, durationMs: number): void {
  if (!state) return;
  state.risk.setActiveCall(active);
  enqueue('PASSIVE_CALL_STATE', active ? { active, kind } : { active, kind, durationMs });
}

// A screenshot is a one-shot event, not a persistent state — emit it for
// scoring but don't put it in the local-risk state machine (which drives the
// persistent banner). The host app can react via onScreenshot below.
function onScreenshot(): void {
  if (!state) return;
  enqueue('PASSIVE_SCREENSHOT', { at: Date.now() });
  state.screenshotCb?.();
}

// Server-issued commands (the action channel's device leg). TERMINATE_SESSION
// is the analyst kill switch: ack inside the dying session, unbind the user,
// rotate the session id (invalidating future tokens for the killed session),
// then notify the host app so it can force logout — the same semantics as the
// Android SDK. Commands for a session other than the current one are stale
// (the session already rotated) and are ignored.
function handleServerCommands(commands: ServerCommand[]): void {
  if (!state) return;
  for (const cmd of commands) {
    if (cmd.kind !== 'TERMINATE_SESSION') continue;
    const current = state.sessionId;
    if (cmd.sessionId && cmd.sessionId !== current) continue; // stale
    enqueue('PASSIVE_COMMAND_ACK', { commandId: cmd.id, kind: 'TERMINATE_SESSION' });
    state.userRef = undefined;
    state.sessionId = newId();
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
    state.sessionId = newId();
    return ensureToken().then(() => undefined);
  },
  event(e: BusinessEvent): void {
    enqueue(e.type, e.payload);
  },
  screenView(screenId: string): void {
    enqueue('SCREEN_VIEWED', { screenId });
  },
  /** A session token for the current identity — fresh (re-minted before the
   *  server's 1h expiry) and bound to the current userRef. '' if the SDK is
   *  not initialised or the collector couldn't mint. */
  getToken(): Promise<string> {
    return ensureToken();
  },
};

export const FraudSdk = {
  /** Call once on app start (await it — install identity is loaded from the
   *  keystore). Idempotent. */
  async init(config: SdkConfig): Promise<void> {
    if (state) return;
    const cfg: Required<SdkConfig> = {
      tenantId: config.tenantId,
      siteKey: config.siteKey,
      collectorUrl: config.collectorUrl,
      sdk: config.sdk ?? 'expo/0.1.0',
      flushIntervalMs: config.flushIntervalMs ?? 5000,
      remoteAccessPollMs: config.remoteAccessPollMs ?? 4000,
      callPollMs: config.callPollMs ?? 4000,
    };
    const install = await getInstall();
    const installId = install.id;
    const transport = new Transport(cfg, installId, newId);
    transport.onCommands = handleServerCommands;
    const risk = new RiskTracker();
    const touch = createTouchCapture(enqueue);
    const watch = createRemoteAccessWatch(cfg.remoteAccessPollMs, applyRemoteAccess);
    const callWatch = createCallSignalsWatch(cfg.callPollMs, applyCallTransition);
    const shotWatch = createScreenshotWatch(onScreenshot);
    const appSub = AppState.addEventListener('change', (s: AppStateStatus) => {
      if (s === 'background' || s === 'inactive') void transport.flush();
    });
    state = { cfg, installId, sessionId: newId(), tokenMintedAt: 0, transport, risk, touch, watch, callWatch, shotWatch, appSub };
    // The intervention sheet reports outcomes through the live session.
    _setReporter({ event: (e) => sessionApi.event(e), flush: () => FraudSdk.flush() });
    transport.start();

    enqueue('PASSIVE_DEVICE_FINGERPRINT', {
      ...fingerprint(),
      firstSeen: install.firstSeen,
      installAgeMs: install.firstSeen != null ? Date.now() - install.firstSeen : null,
    });
    const remoteNative = watch.start();     // false => no native module
    const callNative = callWatch.start();   // false => no native module
    const shotNative = shotWatch.start();   // false => expo-screen-capture absent
    if (__DEV__) {
      console.log(
        `[VeraFraudSdk] native watches — remoteAccess: ${remoteNative}, ` +
        `callSignals: ${callNative}, screenshot: ${shotNative}` +
        (remoteNative && callNative ? '' : ' (manual report* fallbacks active)'),
      );
    }
    void refreshToken();
  },

  session(): typeof sessionApi {
    return sessionApi;
  },

  /** Props to spread onto a <TextInput> for opt-in keystroke dynamics. */
  trackInput(fieldId: string): KeystrokeProps {
    return keystrokeProps(fieldId, enqueue);
  },

  /** The shared touch capture — spread `.panHandlers` onto a wrapping <View>. */
  touch(): TouchCapture {
    if (!state) return { panHandlers: {}, flush: () => {} };
    return state.touch;
  },

  /** Subscribe to locally-known risk (screen-share). Fires immediately and on
   *  every change — so the app can raise an anti-scam banner with no server hop. */
  onLocalRisk(cb: (r: LocalRisk) => void): void {
    state?.risk.subscribe(cb);
  },

  /** Report screen-share / remote control the app's own shell detected (when the
   *  bundled native module isn't used). Raises local risk AND emits
   *  PASSIVE_REMOTE_ACCESS so the server scores REMOTE_ACCESS. */
  reportRemoteAccess(active: boolean): void {
    applyRemoteAccess(active, {
      screenShareLikely: active, accessibilitySuspect: false,
      extraDisplays: active ? 1 : 0, accessibilityMatches: [],
    });
  },

  /** Report call state the app's own shell detected (when the bundled native
   *  module isn't used, e.g. Expo Go). Raises local risk, stamps callSignals
   *  on subsequent business events (ACTIVE_CALL) and emits PASSIVE_CALL_STATE
   *  transitions (RECENT_CALL). */
  reportCallState(inCall: boolean, kind: 'GSM' | 'VoIP' = 'VoIP'): void {
    if (!state) return;
    const cs: CallSignals = {
      inGsmCall: inCall && kind === 'GSM',
      inVoipCall: inCall && kind === 'VoIP',
      speakerOn: false,
    };
    state.callWatch.report(cs);
  },

  /** Block screen capture — screenshots AND screen recording — while enabled.
   *  Call {@code preventScreenCapture(true)} when a sensitive screen (transfer,
   *  OTP, balance) mounts and {@code false} when it unmounts, so a coached
   *  victim can't screenshot account details to send to a scammer. Safe no-op
   *  if expo-screen-capture isn't installed. */
  preventScreenCapture(enable: boolean): Promise<void> {
    return preventScreenCapture(enable);
  },

  /** Notified when the user screenshots the app. Fires in addition to the
   *  PASSIVE_SCREENSHOT event sent to the backend — use it to show a local
   *  "don't share screenshots of your account" warning. */
  onScreenshot(cb: () => void): void {
    if (state) state.screenshotCb = cb;
  },

  /** Notified when a fraud analyst terminates this session from the console
   *  (kill switch). The SDK has already unbound the user and rotated its
   *  session; the host app should force logout and invalidate its own auth
   *  tokens. Arrives within one flush interval. Defense in depth — never the
   *  only logout path. */
  onSessionTerminated(cb: (sessionId: string) => void): void {
    if (state) state.terminatedCb = cb;
  },

  /** Force-upload queued events (flushes touch strokes first). Call right before
   *  a risky backend call, e.g. just before your server's /score. */
  async flush(): Promise<void> {
    if (!state) return;
    state.touch.flush();
    await state.transport.flush();
  },

  /** SHA-256 hex of an identifier — hash PII before setUser. */
  hash(value: string): Promise<string> {
    return sha256(value);
  },

  /** Test/teardown hook. */
  _reset(): void {
    if (!state) return;
    state.transport.stop();
    state.watch.stop();
    state.callWatch.stop();
    state.shotWatch.stop();
    state.appSub.remove();
    state = null;
  },
};

export { BusinessEvent };
export { InterventionSheet } from './ui/InterventionSheet';
export type {
  InterventionSheetProps,
  InterventionDecision,
  InterventionResult,
  InterventionAction,
} from './ui/InterventionSheet';
export type { SdkConfig, SdkEvent, LocalRisk, CallSignals } from './types';
export type { RemoteAccessStatus } from './collectors/remoteAccess';
