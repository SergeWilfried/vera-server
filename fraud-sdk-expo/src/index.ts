// fraud-sdk-expo — React Native / Expo behavioral-fraud SDK.
//
//   await FraudSdk.init({ tenantId, siteKey, collectorUrl });
//   FraudSdk.session().setUser(await FraudSdk.hash(email));
//   <TextInput {...FraudSdk.trackInput('login.pin')} />       // keystroke timing
//   <View {...FraudSdk.touch().panHandlers}>…</View>          // touch dynamics
//   FraudSdk.session().event(BusinessEvent.txnInitiated({ amountBucket: 'HIGH' }));
//   const token = await FraudSdk.session().getToken();         // -> bank backend
//   FraudSdk.onLocalRisk(r => setBanner(r.reasons.includes('SCREEN_SHARE')));
//
// Emits the same mobile wire as the Android SDK, so the collector and scoring
// treat an RN session identically. Public site-key auth (no secret in the app);
// the session token is minted server-side. Privacy: timing/geometry only, never
// keystroke content; hash identifiers via FraudSdk.hash() before setUser.

import { AppState, type AppStateStatus } from 'react-native';
import type { SdkConfig, SdkEvent, LocalRisk } from './types';
import { Transport } from './wire/transport';
import { RiskTracker } from './core/risk';
import { newId, hash as sha256 } from './platform/crypto';
import { getInstallId } from './platform/storage';
import { fingerprint } from './platform/device';
import { keystrokeProps, type KeystrokeProps } from './collectors/keystroke';
import { createTouchCapture, type TouchCapture } from './collectors/touch';
import {
  createRemoteAccessWatch,
  type RemoteAccessStatus,
  type RemoteAccessWatch,
} from './collectors/remoteAccess';
import { BusinessEvent } from './events';

interface State {
  cfg: Required<SdkConfig>;
  installId: string;
  sessionId: string;
  userRef?: string;
  token?: string;
  transport: Transport;
  risk: RiskTracker;
  touch: TouchCapture;
  watch: RemoteAccessWatch;
  appSub: { remove(): void };
}

let state: State | null = null;

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
    const res = await fetch(state.cfg.collectorUrl.replace(/\/$/, '') + '/v1/collect/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Tenant-Id': state.cfg.tenantId,
        'X-Site-Key': state.cfg.siteKey,
      },
      body: JSON.stringify({ sessionId: state.sessionId, installId: state.installId, userRef: state.userRef }),
    });
    if (res.ok) state.token = (await res.json()).token;
  } catch {
    /* token is best-effort; the bank backend can retry */
  }
}

function applyRemoteAccess(active: boolean, status: RemoteAccessStatus): void {
  if (!state) return;
  state.risk.setRemoteAccess(active);
  if (active) enqueue('PASSIVE_REMOTE_ACCESS', status);
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
    state.sessionId = newId();
    void refreshToken();
  },
  event(e: BusinessEvent): void {
    enqueue(e.type, e.payload);
  },
  screenView(screenId: string): void {
    enqueue('SCREEN_VIEWED', { screenId });
  },
  async getToken(): Promise<string> {
    if (!state) return '';
    if (!state.token) await refreshToken();
    return state.token ?? '';
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
    };
    const installId = await getInstallId();
    const transport = new Transport(cfg, installId, newId);
    const risk = new RiskTracker();
    const touch = createTouchCapture(enqueue);
    const watch = createRemoteAccessWatch(cfg.remoteAccessPollMs, applyRemoteAccess);
    const appSub = AppState.addEventListener('change', (s: AppStateStatus) => {
      if (s === 'background' || s === 'inactive') void transport.flush();
    });
    state = { cfg, installId, sessionId: newId(), transport, risk, touch, watch, appSub };
    transport.start();

    enqueue('PASSIVE_DEVICE_FINGERPRINT', fingerprint());
    watch.start(); // no-op (returns false) if there's no native module
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
    state.appSub.remove();
    state = null;
  },
};

export { BusinessEvent };
export type { SdkConfig, SdkEvent, LocalRisk } from './types';
export type { RemoteAccessStatus } from './collectors/remoteAccess';
