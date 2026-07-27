// Session + install identity. installId persists across sessions (a browser
// device id, powering "known device"); sessionId rotates per page session.
// The session token is minted SERVER-SIDE (the browser holds no HMAC key).

const INSTALL_KEY = 'vw_fraud_install';
const SINCE_KEY = 'vw_fraud_install_since';

function store(): Storage | null {
  try {
    return typeof localStorage !== 'undefined' ? localStorage : null;
  } catch {
    return null;
  }
}

const memory: Record<string, string> = {};

function persistentGet(key: string): string | null {
  const s = store();
  return s ? s.getItem(key) : (memory[key] ?? null);
}
function persistentSet(key: string, val: string): void {
  const s = store();
  if (s) s.setItem(key, val);
  else memory[key] = val;
}

export function randomId(): string {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) return crypto.randomUUID();
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
  });
}

export function getInstallId(): string {
  return getInstall().id;
}

export interface Install {
  id: string;
  /** Epoch ms when this install was first created; null if it predates the
   *  firstSeen feature (unknown — never treated as new). */
  firstSeen: number | null;
}

// firstSeen records when this browser install was created, so the engine gets
// device novelty (a fresh install / new-device takeover) even with no ledger view.
export function getInstall(): Install {
  let id = persistentGet(INSTALL_KEY);
  let since = persistentGet(SINCE_KEY);
  if (!id) {
    id = randomId();
    since = String(Date.now());
    persistentSet(INSTALL_KEY, id);
    persistentSet(SINCE_KEY, since);
  }
  // id but no since = predates this feature → age unknown, never faked as new.
  return { id, firstSeen: since ? Number(since) : null };
}
