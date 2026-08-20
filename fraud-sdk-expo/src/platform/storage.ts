// Install identity. installId persists across app launches (the device id that
// powers "known device" scoring); sessionId rotates per app session. We also
// record firstSeen — when this install was created — so the engine gets device
// novelty even when it has no ledger view of the account (external destination,
// new-device takeover). Persisted in the OS keystore via expo-secure-store —
// hence async, unlike the web SDK's synchronous localStorage. The session token
// is minted SERVER-SIDE (the app holds no HMAC key; auth is the public site key).

import * as SecureStore from 'expo-secure-store';
import { newId } from './crypto';

const INSTALL_KEY = 'vw_fraud_install';
const SINCE_KEY = 'vw_fraud_install_since';

export interface Install {
  id: string;
  /** Epoch ms when this install was first created; null if it predates the
   *  firstSeen feature (unknown — never treated as new). */
  firstSeen: number | null;
}

export async function getInstall(): Promise<Install> {
  let id: string | null = null;
  let since: string | null = null;
  try {
    id = await SecureStore.getItemAsync(INSTALL_KEY);
    since = await SecureStore.getItemAsync(SINCE_KEY);
  } catch {
    /* keystore unavailable (e.g. first boot / simulator) — regenerate */
  }
  if (!id) {
    // Brand-new install: stamp firstSeen now.
    id = newId();
    since = String(Date.now());
    try {
      await SecureStore.setItemAsync(INSTALL_KEY, id);
      await SecureStore.setItemAsync(SINCE_KEY, since);
    } catch {
      /* best-effort; a fresh id each launch just reads as a new device */
    }
  }
  // An install with an id but no since predates this feature — its age is
  // unknown, so report null rather than fake newness.
  return { id, firstSeen: since ? Number(since) : null };
}

/** Generic keystore access for collectors that must remember something across
 *  sessions (e.g. the SIM identity fingerprint). Both degrade to a no-op /
 *  null when the keystore is unavailable — never throw into the host app. */
export async function getItem(key: string): Promise<string | null> {
  try {
    return await SecureStore.getItemAsync(key);
  } catch {
    return null;
  }
}

export async function setItem(key: string, value: string): Promise<void> {
  try {
    await SecureStore.setItemAsync(key, value);
  } catch {
    /* keystore unavailable — the comparison simply restarts next launch */
  }
}

/** @deprecated use getInstall(); kept for callers that only need the id. */
export async function getInstallId(): Promise<string> {
  return (await getInstall()).id;
}
