// Store-sanctioned attestation — Play Integrity on Android, App Attest on
// iOS. The strongest device/app-genuineness signal either store offers, and
// the sanctioned replacement for half the integrity heuristics: instead of
// the SDK guessing "rooted?", Google/Apple sign a verdict the server
// verifies with them directly.
//
// The token/attestation blob is OPAQUE to the SDK: it is forwarded in a
// PASSIVE_ATTESTATION event and decoded server-side (the tenant configures
// Google service-account / Apple verification there). The request is bound
// to this session via nonce = base64url(SHA-256(sessionId|installId)), which
// the server recomputes from the event envelope, so a captured token cannot
// vouch for another device or session.
//
// Failure is a signal, never an exception: UNAVAILABLE / API_ERROR statuses
// go to the wire (the server scores ATTESTATION_MISSING on platforms where
// attestation should exist). In Expo Go both native modules are absent and
// the collector emits UNAVAILABLE:expo-go — expected, unscored.

import { requireOptionalNativeModule } from 'expo';
import * as Crypto from 'expo-crypto';
import { Platform } from 'react-native';
import type { EmitFn } from './types';

interface PlayIntegrityNative {
  requestToken(nonce: string, cloudProjectNumber: number):
    Promise<{ status: string; token: string }>;
}
interface AppAttestNative {
  attest(challenge: string):
    Promise<{ status: string; keyId: string; attestation: string }>;
}

const playIntegrity = requireOptionalNativeModule<PlayIntegrityNative>('VeraPlayIntegrity');
const appAttest = requireOptionalNativeModule<AppAttestNative>('VeraAppAttest');

function hexToBase64Url(hex: string): string {
  let bin = '';
  for (let i = 0; i < hex.length; i += 2) {
    bin += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
  }
  // btoa exists in RN's JSC/Hermes global scope
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function reportAttestation(
  emit: EmitFn,
  sessionId: string,
  installId: string,
  cloudProjectNumber?: number,
): Promise<void> {
  try {
    const digestHex = await Crypto.digestStringAsync(
      Crypto.CryptoDigestAlgorithm.SHA256, `${sessionId}|${installId}`);
    const nonce = hexToBase64Url(digestHex);

    if (Platform.OS === 'android') {
      if (!cloudProjectNumber) return;               // tenant has not enabled it
      if (!playIntegrity) {
        emit('PASSIVE_ATTESTATION', {
          provider: 'PLAY_INTEGRITY', status: 'UNAVAILABLE:expo-go', token: '', nonce,
        });
        return;
      }
      const r = await playIntegrity.requestToken(nonce, cloudProjectNumber);
      emit('PASSIVE_ATTESTATION', {
        provider: 'PLAY_INTEGRITY', status: r.status, token: r.token, nonce,
      });
    } else if (Platform.OS === 'ios') {
      if (!appAttest) {
        emit('PASSIVE_ATTESTATION', {
          provider: 'APP_ATTEST', status: 'UNAVAILABLE:expo-go',
          keyId: '', attestation: '', nonce,
        });
        return;
      }
      const r = await appAttest.attest(nonce);
      emit('PASSIVE_ATTESTATION', {
        provider: 'APP_ATTEST', status: r.status,
        keyId: r.keyId, attestation: r.attestation, nonce,
      });
    }
  } catch {
    // never let attestation break init
  }
}
