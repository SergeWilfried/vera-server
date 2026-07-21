// Batched upload: queue -> NDJSON -> POST /v1/collect (public site key +
// Origin auth). navigator.sendBeacon on page hide so the last events survive
// navigation; fetch(keepalive) otherwise.

import type { SdkConfig, SdkEvent } from './types.js';
import { randomId } from './session.js';

export class Transport {
  private queue: SdkEvent[] = [];
  private timer: ReturnType<typeof setInterval> | null = null;
  private readonly base: string;

  constructor(
    private cfg: Required<Pick<SdkConfig, 'tenantId' | 'siteKey' | 'sdk' | 'flushIntervalMs'>> & { collectorUrl: string },
    private installId: string,
  ) {
    this.base = cfg.collectorUrl.replace(/\/$/, '');
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
    return {
      'Content-Type': 'application/x-ndjson',
      'X-Tenant-Id': this.cfg.tenantId,
      'X-Site-Key': this.cfg.siteKey,
      'X-Install-Id': this.installId,
      'X-Sdk': this.cfg.sdk,
    };
  }

  async flush(): Promise<void> {
    if (this.queue.length === 0) return;
    const batch = this.queue.splice(0, this.queue.length);
    try {
      await fetch(this.base + '/v1/collect', {
        method: 'POST',
        headers: this.headers(),
        body: this.ndjson(batch),
        keepalive: true,
      });
    } catch {
      // best-effort telemetry: re-queue a bounded tail for the next tick
      this.queue = batch.slice(-100).concat(this.queue);
    }
  }
}
