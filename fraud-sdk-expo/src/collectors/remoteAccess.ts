// Screen-share / remote-access watch. On Android the native module (see
// android/) reports an extra VirtualDisplay (AnyDesk/TeamViewer/MediaProjection
// screen-share) or a remote-control accessibility service. This JS side polls
// that native status and, when it flips, hands the SDK a fresh reading so it can
// raise the local anti-scam banner AND emit PASSIVE_REMOTE_ACCESS for scoring.
//
// If no native module is present (Expo Go, iOS), start() returns false and the
// app falls back to manual FraudSdk.reportRemoteAccess(...) from its own shell.

import { NativeModules } from 'react-native';

export interface RemoteAccessStatus {
  screenShareLikely: boolean;
  accessibilitySuspect: boolean;
  extraDisplays: number;
  accessibilityMatches: string[];
  /** Android 15+ on-device screen recording (folded into screenShareLikely). */
  screenRecording?: boolean;
}

interface NativeRemoteAccess {
  getStatus(): Promise<RemoteAccessStatus>;
}

const Native = (NativeModules as Record<string, unknown>)['VeraRemoteAccess'] as
  | NativeRemoteAccess
  | undefined;

export interface RemoteAccessWatch {
  /** Begin polling. Returns false if no native module is available. */
  start: () => boolean;
  stop: () => void;
}

export function createRemoteAccessWatch(
  pollMs: number,
  onChange: (active: boolean, status: RemoteAccessStatus) => void,
): RemoteAccessWatch {
  let timer: ReturnType<typeof setInterval> | null = null;
  let last = false;

  const readOnce = async () => {
    if (!Native) return;
    try {
      const s = await Native.getStatus();
      const active = !!(s.screenShareLikely || s.accessibilitySuspect);
      if (active !== last) {
        last = active;
        onChange(active, s);
      }
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
  };
}
