// Install identity. installId persists across app launches (the device id that
// powers "known device" scoring); sessionId rotates per app session. Persisted
// in the OS keystore via expo-secure-store — hence async, unlike the web SDK's
// synchronous localStorage. The session token is minted SERVER-SIDE (the app
// holds no HMAC key; auth is the public site key).

import * as SecureStore from 'expo-secure-store';
import { newId } from './crypto.js';

const INSTALL_KEY = 'vw_fraud_install';

export async function getInstallId(): Promise<string> {
  let id: string | null = null;
  try {
    id = await SecureStore.getItemAsync(INSTALL_KEY);
  } catch {
    /* keystore unavailable (e.g. first boot / simulator) — regenerate */
  }
  if (!id) {
    id = newId();
    try {
      await SecureStore.setItemAsync(INSTALL_KEY, id);
    } catch {
      /* best-effort; a fresh id each launch just reads as a new device */
    }
  }
  return id;
}
