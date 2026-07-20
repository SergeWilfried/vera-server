// Navigation flow — emits SCREEN_VIEWED on SPA route changes (history
// pushState/replaceState + popstate) and the initial load. Uses stable path
// ids, not titles.

import type { SdkEvent } from '../types.js';

export function attachNav(
  installId: string,
  sessionId: string,
  getUserRef: () => string | undefined,
  emit: (ev: SdkEvent) => void,
): () => void {
  if (typeof window === 'undefined' || typeof history === 'undefined') return () => {};

  const screen = () => {
    emit({ type: 'SCREEN_VIEWED', sessionId, installId, userRef: getUserRef(),
           ts: Date.now(), payload: { screenId: location.pathname } });
  };

  const origPush = history.pushState.bind(history);
  const origReplace = history.replaceState.bind(history);
  history.pushState = function (this: History, ...args: Parameters<History['pushState']>) {
    origPush(...args);
    screen();
  };
  history.replaceState = function (this: History, ...args: Parameters<History['replaceState']>) {
    origReplace(...args);
    screen();
  };
  window.addEventListener('popstate', screen);
  screen(); // initial

  return () => {
    history.pushState = origPush;
    history.replaceState = origReplace;
    window.removeEventListener('popstate', screen);
  };
}
