// Touch dynamics via PanResponder — per-stroke duration, path length and
// straightness. Robotic/injected input (a RAT driving the screen) shows up as
// near-perfectly straight strokes at constant speed. Emitted as
// PASSIVE_TOUCH_STROKES, the same shape the Android SDK sends, so the server's
// touch-anomaly / remote-access heuristics apply unchanged.
//
// It's a PASSIVE observer: the capture-phase negotiators run for every touch and
// always return false, so the wrapping view NEVER becomes the responder — taps,
// scrolls and child gestures keep working while we record geometry. Stroke end
// is inferred from a short idle gap (no release fires when we don't capture).

import { PanResponder } from 'react-native';
import type { GestureResponderEvent } from 'react-native';
import type { Stroke } from '../types';

type Emit = (type: string, payload: unknown) => void;
const IDLE_END_MS = 120;

export interface TouchCapture {
  /** Spread onto a wrapping <View> to observe gestures (never blocks them). */
  panHandlers: Record<string, unknown>;
  /** Flush any buffered strokes (e.g. right before a /score). */
  flush: () => void;
}

export function createTouchCapture(emit: Emit): TouchCapture {
  const strokes: Stroke[] = [];
  let active = false;
  let start = 0;
  let len = 0;
  let startX = 0;
  let startY = 0;
  let lastX = 0;
  let lastY = 0;
  let idle: ReturnType<typeof setTimeout> | null = null;

  const emitBuffered = () => {
    if (strokes.length) emit('PASSIVE_TOUCH_STROKES', { strokes: strokes.splice(0) });
  };

  const finish = () => {
    if (idle) { clearTimeout(idle); idle = null; }
    if (!active) return;
    active = false;
    const dur = Date.now() - start;
    const disp = Math.hypot(lastX - startX, lastY - startY);
    const straight = len > 0 ? Math.min(1, disp / len) : 1;
    // Ignore taps (no real path) — only movement is a "stroke".
    if (len >= 4) {
      strokes.push({ t: start, dur, len: Math.round(len), straight: Number(straight.toFixed(3)), gap: 0 });
      if (strokes.length >= 8) emitBuffered();
    }
  };

  const begin = (x: number, y: number) => {
    active = true;
    start = Date.now();
    len = 0;
    startX = lastX = x;
    startY = lastY = y;
  };

  const extend = (x: number, y: number) => {
    if (!active) begin(x, y);
    len += Math.hypot(x - lastX, y - lastY);
    lastX = x;
    lastY = y;
    if (idle) clearTimeout(idle);
    idle = setTimeout(finish, IDLE_END_MS);
  };

  const pan = PanResponder.create({
    onStartShouldSetPanResponderCapture: (e: GestureResponderEvent) => {
      begin(e.nativeEvent.locationX, e.nativeEvent.locationY);
      return false; // never capture — let the touch reach its real target
    },
    onMoveShouldSetPanResponderCapture: (e: GestureResponderEvent) => {
      extend(e.nativeEvent.locationX, e.nativeEvent.locationY);
      return false;
    },
  });

  return {
    panHandlers: pan.panHandlers,
    flush: () => { finish(); emitBuffered(); },
  };
}
