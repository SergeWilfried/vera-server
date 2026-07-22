// Touch dynamics via PanResponder — per-stroke duration, path length and
// straightness. Robotic/injected input (a RAT driving the screen) shows up as
// near-perfectly straight strokes at constant speed. Emitted as
// PASSIVE_TOUCH_STROKES, the same shape the Android SDK sends, so the server's
// touch-anomaly / remote-access heuristics apply unchanged.

import { PanResponder } from 'react-native';
import type { GestureResponderEvent } from 'react-native';
import type { Stroke } from '../types.js';

type Emit = (type: string, payload: unknown) => void;

export interface TouchCapture {
  /** Spread onto a wrapping <View> to observe gestures. */
  panHandlers: Record<string, unknown>;
  /** Flush any buffered strokes (e.g. right before a /score). */
  flush: () => void;
}

export function createTouchCapture(emit: Emit): TouchCapture {
  const strokes: Stroke[] = [];
  let start = 0;
  let len = 0;
  let startX = 0;
  let startY = 0;
  let lastX = 0;
  let lastY = 0;

  const flush = () => {
    if (strokes.length) emit('PASSIVE_TOUCH_STROKES', { strokes: strokes.splice(0) });
  };

  const pan = PanResponder.create({
    onStartShouldSetPanResponder: () => true,
    onMoveShouldSetPanResponder: () => true,
    onPanResponderGrant: (e: GestureResponderEvent) => {
      const { locationX, locationY } = e.nativeEvent;
      start = Date.now();
      len = 0;
      startX = lastX = locationX;
      startY = lastY = locationY;
    },
    onPanResponderMove: (e: GestureResponderEvent) => {
      const { locationX, locationY } = e.nativeEvent;
      len += Math.hypot(locationX - lastX, locationY - lastY);
      lastX = locationX;
      lastY = locationY;
    },
    onPanResponderRelease: () => {
      const dur = Date.now() - start;
      const disp = Math.hypot(lastX - startX, lastY - startY);
      const straight = len > 0 ? Math.min(1, disp / len) : 1;
      strokes.push({ t: start, dur, len: Math.round(len), straight: Number(straight.toFixed(3)), gap: 0 });
      if (strokes.length >= 8) flush();
    },
  });

  return { panHandlers: pan.panHandlers, flush };
}
