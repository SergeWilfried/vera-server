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
}

export interface SdkConfig {
  /** Per-tenant id (matches the server's tenant registry). */
  tenantId: string;
  /** PUBLIC per-tenant site key (safe to ship in the app bundle). */
  siteKey: string;
  /** Collector base URL. */
  collectorUrl: string;
  /** X-Sdk header value. */
  sdk?: string;
  /** Batch upload cadence (ms). */
  flushIntervalMs?: number;
  /** Poll cadence for the native screen-share watch (ms). */
  remoteAccessPollMs?: number;
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
  reasons: string[]; // e.g. 'SCREEN_SHARE'
}
