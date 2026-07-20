// Mouse dynamics — the web analogue of touch strokes. A "stroke" is a burst
// of movement between pauses; we aggregate timing/geometry only (no content).
// Robotic input is unnaturally straight with constant velocity.

import type { SdkEvent, Stroke } from '../types.js';

const IDLE_MS = 120;             // gap that ends a stroke
const FLUSH_EVERY = 12;          // strokes per batch

export function attachMouse(
  installId: string,
  sessionId: string,
  getUserRef: () => string | undefined,
  emit: (ev: SdkEvent) => void,
): () => void {
  if (typeof window === 'undefined') return () => {};

  let downT = 0, lastT = 0, lastX = 0, lastY = 0, startX = 0, startY = 0, pathLen = 0, lastEndT = 0;
  let strokes: Stroke[] = [];

  const finish = (t: number) => {
    if (downT === 0) return;
    const direct = Math.hypot(lastX - startX, lastY - startY);
    strokes.push({
      t: downT,
      dur: t - downT,
      len: Math.round(pathLen),
      straight: pathLen > 0 ? Math.round((100 * direct) / pathLen) / 100 : 1,
      gap: lastEndT > 0 ? downT - lastEndT : -1,
    });
    lastEndT = t;
    downT = 0;
    if (strokes.length >= FLUSH_EVERY) flush();
  };

  const flush = () => {
    if (strokes.length === 0) return;
    emit({ type: 'PASSIVE_MOUSE_STROKES', sessionId, installId, userRef: getUserRef(),
           ts: Date.now(), payload: { strokes } });
    strokes = [];
  };

  const onMove = (e: MouseEvent) => {
    const now = performance.now();
    if (downT === 0 || now - lastT > IDLE_MS) {
      if (downT !== 0) finish(lastT);
      downT = now; startX = e.clientX; startY = e.clientY; pathLen = 0;
    } else {
      pathLen += Math.hypot(e.clientX - lastX, e.clientY - lastY);
    }
    lastT = now; lastX = e.clientX; lastY = e.clientY;
  };

  window.addEventListener('mousemove', onMove, { passive: true });
  window.addEventListener('pointermove', onMove, { passive: true });
  const idle = setInterval(() => { if (downT !== 0 && performance.now() - lastT > IDLE_MS) finish(lastT); flush(); }, 2000);

  return () => {
    window.removeEventListener('mousemove', onMove);
    window.removeEventListener('pointermove', onMove);
    clearInterval(idle);
    flush();
  };
}
