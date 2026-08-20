// Batched upload: queue -> NDJSON -> POST /v1/collect (public site key +
// Origin auth). navigator.sendBeacon on page hide so the last events survive
// navigation; fetch(keepalive) otherwise.

import type { SdkConfig, SdkEvent } from './types.js';
import { randomId } from './session.js';

/** Server-issued command riding a batch response (the action channel's
 *  device leg) — e.g. an analyst kill switch. */
export interface ServerCommand {
  id?: string;
  kind?: string;
  sessionId?: string;
}

export class Transport {
  private queue: SdkEvent[] = [];
  private timer: ReturnType<typeof setInterval> | null = null;
  private readonly base: string;
  /** Set by the SDK: invoked with any commands the server returns. */
  onCommands?: (commands: ServerCommand[]) => void;

  /** Epoch ms of the last POST (upload or heartbeat) — paces the poll. */
  private lastPostAt = 0;

  constructor(
    private cfg: Required<Pick<SdkConfig, 'tenantId' | 'siteKey' | 'sdk' | 'flushIntervalMs'>> &
      { collectorUrl: string; heartbeatMs?: number },
    private installId: string,
    /** Current session id, read at call time (it rotates on logout/terminate).
     *  Sent as X-Session-Id so an EMPTY heartbeat can still be matched to a
     *  session server-side. */
    private currentSessionId: () => string = () => '',
  ) {
    this.base = cfg.collectorUrl.replace(/\/$/, '');
  }

  /** Poll for server commands when there is nothing to upload — containment
   *  must not depend on the customer interacting with the page. */
  private async heartbeat(): Promise<void> {
    const every = this.cfg.heartbeatMs ?? 30_000;
    if (!every || Date.now() - this.lastPostAt < every) return;
    this.lastPostAt = Date.now();
    try {
      const res = await fetch(this.base + '/v1/collect', {
        method: 'POST',
        headers: this.headers(),
        body: '',
      });
      if (res.ok && this.onCommands) {
        try {
          const data = (await res.json()) as { commands?: ServerCommand[] } | null;
          if (data?.commands?.length) this.onCommands(data.commands);
        } catch {
          /* no JSON body — fine */
        }
      }
    } catch {
      /* offline — the next beat retries */
    }
  }

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.flush(), this.cfg.flushIntervalMs);
    if (typeof window !== 'undefined') {
      // keepalive fetch survives navigation (the modern sendBeacon) and keeps
      // header-based site-key auth uniform with the periodic flush.
      window.addEventListener('pagehide', () => void this.flush());
      window.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'hidden') void this.flush();
      });
    }
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  enqueue(ev: SdkEvent): void {
    // Stamp once at the chokepoint: the failure path re-queues events, and
    // a stable id is what lets the server drop the resent copies.
    if (!ev.eventId) ev.eventId = randomId();
    if (this.queue.length < 500) this.queue.push(ev);
  }

  private ndjson(batch: SdkEvent[]): string {
    return batch.map((e) => JSON.stringify(e)).join('\n');
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = {
      'Content-Type': 'application/x-ndjson',
      'X-Tenant-Id': this.cfg.tenantId,
      'X-Site-Key': this.cfg.siteKey,
      'X-Install-Id': this.installId,
      'X-Sdk': this.cfg.sdk,
    };
    const sid = this.currentSessionId();
    if (sid) h['X-Session-Id'] = sid;
    return h;
  }

  async flush(): Promise<void> {
    if (this.queue.length === 0) {
      await this.heartbeat();
      return;
    }
    this.lastPostAt = Date.now();
    const batch = this.queue.splice(0, this.queue.length);
    try {
      const res = await fetch(this.base + '/v1/collect', {
        method: 'POST',
        headers: this.headers(),
        body: this.ndjson(batch),
        keepalive: true,
      });
      // The batch response may carry server commands (analyst kill switch).
      // Parse defensively — a malformed body must never break the upload loop.
      if (res.ok && this.onCommands) {
        try {
          const data = (await res.json()) as { commands?: ServerCommand[] } | null;
          if (data?.commands?.length) this.onCommands(data.commands);
        } catch {
          /* no JSON body — fine */
        }
      }
    } catch {
      // best-effort telemetry: re-queue a bounded tail for the next tick
      this.queue = batch.slice(-100).concat(this.queue);
    }
  }
}
