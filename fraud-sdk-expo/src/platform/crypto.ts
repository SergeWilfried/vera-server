// Crypto adapter (Expo). SHA-256 for hashing PII before setUser, and UUIDs for
// session/install/event ids. Native-backed via expo-crypto.

import * as Crypto from 'expo-crypto';

export function newId(): string {
  return Crypto.randomUUID();
}

/** SHA-256 hex of an identifier — hash PII before binding it as userRef. */
export async function hash(value: string): Promise<string> {
  return Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA256, value);
}
