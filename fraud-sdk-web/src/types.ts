// Wire types — the browser envelope matches the Android SDK / simulate-sdk.js
// exactly, so the collector persists web and mobile events through one path.

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
  /** PUBLIC per-tenant site key (safe to ship in browser JS). */
  siteKey: string;
  /** Collector base URL (default same-origin '' -> uses location.origin). */
  collectorUrl?: string;
  /** X-Sdk header value. */
  sdk?: string;
  /** Batch upload cadence (ms). */
  flushIntervalMs?: number;
  /** Command-poll cadence (ms) when there is nothing to upload. Server-issued
   *  commands (the analyst kill switch) ride upload responses, so an idle tab
   *  would never hear about them; this posts an empty batch at most this often
   *  to collect them. 0 disables polling. Default 30000. */
  heartbeatMs?: number;
  /** Log integration problems (e.g. a failed token mint) to the console. */
  debug?: boolean;
}

/** A behavioral "stroke" — shared shape for mouse and touch dynamics. */
export interface Stroke {
  t: number;
  dur: number;
  len: number;
  straight: number;
  gap: number;
}
