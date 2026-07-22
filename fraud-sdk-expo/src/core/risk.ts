// Local risk tracker. On mobile the anti-scam tell is screen-share / remote
// control (reported by the native module below), so a single subscriber is
// notified immediately whenever that state flips — no server round-trip, so the
// host app can raise a "someone may be watching your screen" banner in-place.

import type { LocalRisk } from '../types';

export class RiskTracker {
  private remoteActive = false;
  private cb?: (r: LocalRisk) => void;

  setRemoteAccess(active: boolean): void {
    if (this.remoteActive === active) return;
    this.remoteActive = active;
    this.emit();
  }

  subscribe(cb: (r: LocalRisk) => void): void {
    this.cb = cb;
    this.emit(); // fire immediately with the current state
  }

  current(): LocalRisk {
    const reasons: string[] = [];
    if (this.remoteActive) reasons.push('SCREEN_SHARE');
    return { level: reasons.length ? 'warn' : 'none', reasons };
  }

  private emit(): void {
    this.cb?.(this.current());
  }
}
