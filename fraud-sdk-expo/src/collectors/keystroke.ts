// Keystroke dynamics for a TextInput — inter-key latency, deletions and a paste
// heuristic. Timing only, never the characters. Emitted as PASSIVE_KEYSTROKES
// (same payload the Android/web SDKs send), flushed when the field blurs.

import type { NativeKeyPressEvent } from 'react-native';

interface Key { op: 'i' | 'd'; dt: number; paste?: true }
type Emit = (type: string, payload: unknown) => void;

export interface KeystrokeProps {
  onKeyPress: (e: NativeKeyPressEvent) => void;
  onChangeText: (text: string) => void;
  onBlur: () => void;
}

/** Build props to spread onto a <TextInput> for field `fieldId`. */
export function keystrokeProps(fieldId: string, emit: Emit): KeystrokeProps {
  let lastTs = 0;
  let lastLen = 0;
  const keys: Key[] = [];

  return {
    onKeyPress: (e) => {
      const now = Date.now();
      const dt = lastTs ? now - lastTs : 0;
      lastTs = now;
      keys.push({ op: e.nativeEvent.key === 'Backspace' ? 'd' : 'i', dt });
    },
    onChangeText: (text) => {
      // A jump of >1 char with no matching key burst ≈ a paste (autofill / RAT).
      if (text.length - lastLen > 1) keys.push({ op: 'i', dt: 0, paste: true });
      lastLen = text.length;
    },
    onBlur: () => {
      if (keys.length) emit('PASSIVE_KEYSTROKES', { fieldId, keys: keys.splice(0) });
    },
  };
}
