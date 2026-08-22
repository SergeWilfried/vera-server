// Transport integrity — "is this traffic tunnelled, and is anything set up to
// read it?" These are the two checks a RASP product advertises that the scoring
// engine previously had no input for: VPN/proxy and MITM.
//
// Backed by the bundled VeraNetIntegrity native module (Android). It is absent
// in Expo Go, on iOS and on web, and the collector reports nothing at all in
// that case rather than guessing — a fabricated "no VPN" is worse than silence,
// because the server would score it as a clean transport.
//
// Deliberately NOT a block: a VPN is ordinary consumer behaviour (privacy apps,
// corporate profiles, ad blockers that run a local tunnel) and treating it as
// fraud punishes exactly the security-conscious customers. These signals earn
// their weight in combination, which is what the server's scoring does with
// them.

import { requireOptionalNativeModule } from 'expo';
import type { EmitFn } from './types';

interface NetIntegrityNative {
  getStatus(): Promise<{
    vpnActive: boolean;
    vpnBasis: string;
    proxyConfigured: boolean;
    proxyBasis: string;
    userCaCount: number;
    systemCaCount: number;
  }>;
}

const native = requireOptionalNativeModule<NetIntegrityNative>('VeraNetIntegrity');

export interface NetIntegrityStatus {
  vpnActive: boolean;
  /** How the tunnel was seen: 'transport' | 'interface' | 'none' | 'unavailable'. */
  vpnBasis: string;
  proxyConfigured: boolean;
  /** How the proxy was seen: 'defaultProxy' | 'jvm-props' | 'none' | 'unavailable'. */
  proxyBasis: string;
  /** User-installed root CAs. -1 = trust store unreadable, distinct from 0. */
  userCaCount: number;
  /** System CAs, for sanity-checking the above: 0 means the read failed. */
  systemCaCount: number;
}

/** Read the transport snapshot; null when the native module isn't present. */
export async function collectNetIntegrity(): Promise<NetIntegrityStatus | null> {
  if (!native) return null;
  try {
    return await native.getStatus();
  } catch {
    return null;
  }
}

/** Emit PASSIVE_NET_INTEGRITY once, at init. Never throws. */
export async function reportNetIntegrity(emit: EmitFn): Promise<boolean> {
  try {
    const status = await collectNetIntegrity();
    if (!status) return false;
    emit('PASSIVE_NET_INTEGRITY', status);
    return true;
  } catch {
    return false;
  }
}
