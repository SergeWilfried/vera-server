// Session + install identity. installId persists across sessions (a browser
// device id, powering "known device"); sessionId rotates per page session.
// The session token is minted SERVER-SIDE (the browser holds no HMAC key).

const INSTALL_KEY = 'vw_fraud_install';

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
  let id = persistentGet(INSTALL_KEY);
  if (!id) {
    id = randomId();
    persistentSet(INSTALL_KEY, id);
  }
  return id;
}
