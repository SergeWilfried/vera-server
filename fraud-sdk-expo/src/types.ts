// Wire types — identical envelope to the Android SDK, the web SDK and
// simulate-sdk.js, so mobile RN events persist through the very same collector
// path and score with the existing mobile signals. No server changes needed.

export interface SdkEvent {
  /** Client-generated unique id — lets the server dedupe resent batches. */
  eventId?: string;
  type: string;
  sessionId: string;
  installId: string;
  userRef?: string;
  ts: number;
  payload?: unknown;
  /** In-call context at the moment of a BIZ_* event (coached-scam signal) —
   *  same top-level wire field the Android SDK sends. */
  callSignals?: CallSignals;
}

/** Call state as reported by the native module. On iOS the generic in-call
 *  flag arrives as inGsmCall (a third-party app cannot tell a carrier call
 *  from another app's CallKit call); on Android GSM and VoIP are distinct. */
export interface CallSignals {
  inGsmCall: boolean;
  inVoipCall: boolean;
  ringing?: boolean;
  speakerOn: boolean;
  btAudio?: boolean;
  wiredHeadset?: boolean;
}

export interface SdkConfig {
  /** Per-tenant id (matches the server's tenant registry). */
  tenantId: string;
  /** PUBLIC per-tenant site key (safe to ship in the app bundle). Used by
   *  browser builds, where the Origin allowlist does the real gating. */
  siteKey: string;
  /** Per-tenant NATIVE app credential, sent as X-App-Key on the collect
   *  path. Required on iOS/Android: the server no longer accepts the public
   *  site key alone for requests without a browser Origin. Never used (or
   *  needed) when running on web. */
  appKey?: string;
  /** Collector base URL. */
  collectorUrl: string;
  /** X-Sdk header value. */
  sdk?: string;
  /** Batch upload cadence (ms). */
  flushIntervalMs?: number;
  /** Command-poll cadence (ms) when there is nothing to upload. Server-issued
   *  commands (the analyst kill switch) ride upload responses, so an idle app
   *  would never hear about them; this posts an empty batch at most this often
   *  to collect them. 0 disables polling. Default 30000. */
  heartbeatMs?: number;
  /** Hard deadline for every request the SDK makes (ms). The SDK must never
   *  hold up the host app's login when the collector is unreachable, so this
   *  bounds the wait rather than trusting the platform socket. Default 10000. */
  timeoutMs?: number;
  /** Poll cadence for the native screen-share watch (ms). */
  remoteAccessPollMs?: number;
  /** Poll cadence for the native in-call watch (ms). */
  callPollMs?: number;
}

/** A behavioral "stroke" — shared shape for mouse (web) and touch (mobile). */
export interface Stroke {
  t: number;
  dur: number;
  len: number;
  straight: number;
  gap: number;
}

/** Locally-known risk the host app can react to immediately, with no server
 *  round-trip — e.g. to show an anti-scam banner while a transfer is in flight. */
export interface LocalRisk {
  level: 'none' | 'warn';
  reasons: string[]; // e.g. 'SCREEN_SHARE', 'ACTIVE_CALL'
}
