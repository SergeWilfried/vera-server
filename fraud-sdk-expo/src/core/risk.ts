// Local risk tracker. On mobile the anti-scam tells are screen-share / remote
// control and an active call (reported by the native modules), so a single
// subscriber is notified immediately whenever either state flips — no server
// round-trip, so the host app can raise a "someone may be watching your
// screen" / "your bank is not on this call" banner in-place.

import type { LocalRisk } from '../types';

export class RiskTracker {
  private remoteActive = false;
  private callActive = false;
  private cb?: (r: LocalRisk) => void;

  setRemoteAccess(active: boolean): void {
    if (this.remoteActive === active) return;
    this.remoteActive = active;
    this.emit();
  }

  setActiveCall(active: boolean): void {
    if (this.callActive === active) return;
    this.callActive = active;
    this.emit();
  }

  subscribe(cb: (r: LocalRisk) => void): void {
    this.cb = cb;
    this.emit(); // fire immediately with the current state
  }

  current(): LocalRisk {
    const reasons: string[] = [];
    if (this.remoteActive) reasons.push('SCREEN_SHARE');
    if (this.callActive) reasons.push('ACTIVE_CALL');
    return { level: reasons.length ? 'warn' : 'none', reasons };
  }

  private emit(): void {
    this.cb?.(this.current());
  }
}
