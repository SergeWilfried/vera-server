// In-call watch — mirrors the native Android SDK's CallSignalCollector +
// CallStateWatch. The native module (Android AudioManager / iOS CXCallObserver)
// reports call state; this side polls it and:
//
//   1. caches the latest snapshot, so business events can carry `callSignals`
//      synchronously — the server scores ACTIVE_CALL / CALL_HANDS_FREE;
//   2. reports idle<->in-call transitions, emitted as PASSIVE_CALL_STATE — the
//      server scores RECENT_CALL ("hang up, then send it" coaching);
//   3. flips local risk so the host app can raise an anti-scam banner
//      ("your bank is not on this call") with no server round-trip.
//
// If no native module is present (Expo Go), start() returns false and the app
// falls back to manual FraudSdk.reportCallState(...) from its own shell.

import { requireOptionalNativeModule } from 'expo';
import type { CallSignals } from '../types';

interface NativeCallSignals {
  getStatus(): Promise<CallSignals>;
}

// Expo modules live in Expo's registry, NOT react-native's NativeModules —
// resolving via NativeModules silently returns undefined in every build.
const Native = requireOptionalNativeModule<NativeCallSignals>('VeraCallSignals');

export type CallKind = 'GSM' | 'VoIP';

export interface CallSignalsWatch {
  /** Begin polling. Returns false if no native module is available. */
  start: () => boolean;
  stop: () => void;
  /** Latest known snapshot, or null when nothing has reported yet. */
  snapshot: () => CallSignals | null;
  /** Manual fallback / test hook — feed a reading as if the poll returned it. */
  report: (s: CallSignals) => void;
}

export function createCallSignalsWatch(
  pollMs: number,
  onTransition: (active: boolean, kind: CallKind, durationMs: number) => void,
): CallSignalsWatch {
  let timer: ReturnType<typeof setInterval> | null = null;
  let last: CallSignals | null = null;
  let active = false;
  let kind: CallKind = 'GSM';
  let startedAt = 0;
  // While a manual report says "in call", native polls are ignored — otherwise
  // the next idle poll would clobber a shell-driven report seconds later.
  // Cleared by reporting an idle state.
  let manualActive = false;

  const apply = (s: CallSignals) => {
    last = s;
    const nowActive = !!(s.inGsmCall || s.inVoipCall);
    if (nowActive === active) return;
    active = nowActive;
    if (nowActive) {
      kind = s.inVoipCall ? 'VoIP' : 'GSM';
      startedAt = Date.now();
      onTransition(true, kind, 0);
    } else {
      onTransition(false, kind, Date.now() - startedAt);
    }
  };

  const readOnce = async () => {
    if (!Native || manualActive) return;
    try {
      apply(await Native.getStatus());
    } catch {
      /* native call failed — leave state unchanged */
    }
  };

  return {
    start() {
      if (!Native || timer) return !!timer;
      void readOnce();
      timer = setInterval(() => void readOnce(), pollMs);
      return true;
    },
    stop() {
      if (timer) clearInterval(timer);
      timer = null;
    },
    snapshot: () => last,
    report(s: CallSignals) {
      manualActive = !!(s.inGsmCall || s.inVoipCall);
      apply(s);
    },
  };
}
