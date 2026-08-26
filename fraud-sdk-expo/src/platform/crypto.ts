// Crypto adapter (Expo). SHA-256 for hashing PII before setUser, and UUIDs for
// session/install/event ids. Native-backed via expo-crypto.

import * as Crypto from 'expo-crypto';

export function newId(): string {
  return Crypto.randomUUID();
}

// Per-tenant salt, set once at init. Must match the value configured in the
// Android SDK (tenantHashSalt): the server matches userRef verbatim, so the
// same customer on two platforms only links if both SDKs hash identically.
let hashSalt = '';

export function setHashSalt(salt: string): void {
  hashSalt = salt;
}

/** SHA-256 hex of an identifier — hash PII before binding it as userRef.
 *  Contract shared with the Android SDK's Hashing.java, byte for byte:
 *  sha256(salt_utf8 || trim(value)_utf8), lowercase hex. */
// Cross-SDK test vectors — all SDKs must produce exactly these:
//   ("", "olivia@demobank.cz")
//     -> 0dbb84a570fa61f59f29885c5fcd314d43110e91af23f6d7de73416913df1ce1
//   ("pepper-tenant-1", "  +225 07 88 00 12  ")   (trims to the bare number)
//     -> e13016792da46cfd00eda399cb03eef77ce4f18a8c4bd913b3428b0387022ffc
//   ("pepper-tenant-1", "c\u00f4te@exemple.ci")       (UTF-8, not a Latin-1 slip)
//     -> 2db329d52aa30cbd2933e94bd12d72c6f183bfb54f933a98195616ec5c9e6837
export async function hash(value: string): Promise<string> {
  return Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA256, hashSalt + value.trim());
}
