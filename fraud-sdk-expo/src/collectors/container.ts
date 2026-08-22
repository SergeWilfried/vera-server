// Is this app instance a clone?
//
// The server links multi-accounting on installId. A cloned container gets its
// own data dir and keystore, so it mints its OWN installId — one handset then
// looks like two unrelated devices and the device link silently fails. This
// collector reports the clone itself, which is the signal the link needs to
// stay honest.
//
// Detects being cloned, not the presence of a cloning tool: no package
// denylist, no <queries>, and nothing that switching from Parallel Space to
// Dual Apps would evade. Backed by the bundled VeraContainer native module
// (Android); absent on iOS, web and in Expo Go, where the collector reports
// nothing rather than asserting a clean primary-user instance.

import { requireOptionalNativeModule } from 'expo';
import type { EmitFn } from './types';

interface ContainerNative {
  getStatus(): Promise<{
    androidUserId: number;
    secondaryUser: boolean;
    virtualized: boolean;
    dataDirBasis: string;
    adminPresent: boolean;
  }>;
}

const native = requireOptionalNativeModule<ContainerNative>('VeraContainer');

export interface ContainerStatus {
  /** 0 = primary user. A clone or a work profile runs above it. */
  androidUserId: number;
  secondaryUser: boolean;
  /** Running inside another app's sandbox (Parallel Space and friends). */
  virtualized: boolean;
  /** 'standard' | 'nested' | 'unrecognised' | 'unavailable'. */
  dataDirBasis: string;
  /** A device admin is active — the tell that separates a managed work
   *  profile from a cloned app, since both are secondary users. */
  adminPresent: boolean;
}

/** Read the container snapshot; null when the native module isn't present. */
export async function collectContainer(): Promise<ContainerStatus | null> {
  if (!native) return null;
  try {
    return await native.getStatus();
  } catch {
    return null;
  }
}

/** Emit PASSIVE_APP_CONTAINER once, at init. Never throws. */
export async function reportContainer(emit: EmitFn): Promise<boolean> {
  try {
    const status = await collectContainer();
    if (!status) return false;
    emit('PASSIVE_APP_CONTAINER', status);
    return true;
  } catch {
    return false;
  }
}
