// Wire types — the browser envelope matches the Android SDK / simulate-sdk.js
// exactly, so the collector persists web and mobile events through one path.

export interface SdkEvent {
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
  /** PUBLIC per-tenant site key (safe to ship in browser JS). */
  siteKey: string;
  /** Collector base URL (default same-origin '' -> uses location.origin). */
  collectorUrl?: string;
  /** X-Sdk header value. */
  sdk?: string;
  /** Batch upload cadence (ms). */
  flushIntervalMs?: number;
}

/** A behavioral "stroke" — shared shape for mouse and touch dynamics. */
export interface Stroke {
  t: number;
  dur: number;
  len: number;
  straight: number;
  gap: number;
}
