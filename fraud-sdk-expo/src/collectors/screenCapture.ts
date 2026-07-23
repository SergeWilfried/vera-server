// Screenshot detection + capture prevention, via expo-screen-capture.
//
//  Detection: addScreenshotListener fires when the user screenshots the app.
//    Under coaching, victims are told to screenshot an OTP / balance / transfer
//    confirmation and send it to the "agent" — so a screenshot during a
//    sensitive flow is a fraud signal. Emitted as PASSIVE_SCREENSHOT.
//
//  Prevention: preventScreenCaptureAsync blocks screenshots AND screen
//    recording (Android FLAG_SECURE / iOS secure overlay) while active — the
//    host app turns it on around sensitive screens (transfer, OTP) so the
//    account details can't be captured at all.
//
// Cross-platform and works in Expo Go — no bundled native module needed. If
// the package is somehow absent, every call degrades to a safe no-op.

import type { EmitterSubscription } from 'react-native';

// Import lazily/defensively: expo-screen-capture is a normal dependency, but
// keeping the surface behind a typed shim means a missing module never throws
// at import time — the SDK must never break the host app.
interface ScreenCaptureModule {
  addScreenshotListener(listener: () => void): EmitterSubscription;
  preventScreenCaptureAsync(key?: string): Promise<void>;
  allowScreenCaptureAsync(key?: string): Promise<void>;
}

let mod: ScreenCaptureModule | null = null;
try {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  mod = require('expo-screen-capture') as ScreenCaptureModule;
} catch {
  mod = null;
}

// One prevention key so nested/duplicate enable calls collapse to a single
// FLAG_SECURE lifetime — the OS ref-counts by key.
const PREVENT_KEY = 'vera-fraud-sdk';

export interface ScreenshotWatch {
  /** Begin listening. Returns false if the module is unavailable. */
  start: () => boolean;
  stop: () => void;
}

export function createScreenshotWatch(onShot: () => void): ScreenshotWatch {
  let sub: EmitterSubscription | null = null;
  return {
    start() {
      if (!mod || sub) return !!sub;
      try {
        sub = mod.addScreenshotListener(onShot);
        return true;
      } catch {
        return false;
      }
    },
    stop() {
      try {
        sub?.remove();
      } catch {
        /* ignore */
      }
      sub = null;
    },
  };
}

/** Block screen capture (screenshots + recording) on sensitive screens. */
export async function preventScreenCapture(enable: boolean): Promise<void> {
  if (!mod) return;
  try {
    if (enable) await mod.preventScreenCaptureAsync(PREVENT_KEY);
    else await mod.allowScreenCaptureAsync(PREVENT_KEY);
  } catch {
    /* best-effort hardening; never throw into the host app */
  }
}
