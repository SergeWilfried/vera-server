/** fetch with a hard deadline.
 *
 * React Native's fetch has no default timeout, so a collector that accepts
 * the TCP connection but never answers leaves the promise pending for as
 * long as the socket survives — minutes, not seconds. That is not a
 * theoretical case: it is what a stalled deployment looks like from the
 * handset, and it froze the demo bank on its login spinner because
 * setUser() awaits the token mint.
 *
 * Fraud tooling sits in front of the bank's login, so it must fail open: a
 * vendor outage may degrade signals, it must never block the customer. Every
 * request the SDK makes goes through here.
 */

/** Long enough to survive a slow mobile network, short enough that a wedged
 *  collector can't hold a login screen hostage. */
export const DEFAULT_TIMEOUT_MS = 10_000;

export async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
): Promise<Response> {
  // No AbortController (very old runtime): a request with no deadline still
  // beats no telemetry at all — the callers all treat failure as non-fatal.
  if (typeof AbortController === 'undefined') return fetch(url, init);

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}
