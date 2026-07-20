// Per-field keystroke dynamics — TIMING ONLY, never characters. Mirrors the
// Android KeystrokeCapture: inter-key latency, insert/delete, paste flag.
// Flushes when focus leaves the field. Same PASSIVE_KEYSTROKES wire shape.

import type { SdkEvent } from '../types.js';

interface KeyTiming {
  dt: number;
  op: 'i' | 'd';
  paste?: true;
}

export function attachKeystrokes(
  el: HTMLInputElement | HTMLTextAreaElement,
  fieldId: string,
  installId: string,
  sessionId: string,
  getUserRef: () => string | undefined,
  emit: (ev: SdkEvent) => void,
): () => void {
  if (!el || typeof el.addEventListener !== 'function') return () => {};

  let lastTs = 0;
  let prevLen = el.value ? el.value.length : 0;
  let timings: KeyTiming[] = [];
  let pasted = false;

  const onPaste = () => { pasted = true; };
  const onInput = () => {
    const now = performance.now();
    const len = el.value.length;
    const delta = len - prevLen;
    const k: KeyTiming = { dt: lastTs > 0 ? Math.round(now - lastTs) : -1, op: delta >= 0 ? 'i' : 'd' };
    if (pasted || delta > 2) k.paste = true;
    pasted = false;
    lastTs = now;
    prevLen = len;
    if (timings.length < 200) timings.push(k);
  };
  const onBlur = () => {
    if (timings.length === 0) return;
    emit({ type: 'PASSIVE_KEYSTROKES', sessionId, installId, userRef: getUserRef(),
           ts: Date.now(), payload: { fieldId, keys: timings } });
    timings = [];
  };

  el.addEventListener('paste', onPaste);
  el.addEventListener('input', onInput);
  el.addEventListener('blur', onBlur);

  return () => {
    el.removeEventListener('paste', onPaste);
    el.removeEventListener('input', onInput);
    el.removeEventListener('blur', onBlur);
    onBlur();
  };
}
