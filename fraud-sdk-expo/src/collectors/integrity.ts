// Device-integrity snapshot — the RN counterpart of the Android SDK's
// IntegrityCollector. A rooted/jailbroken handset, an emulator, or a debug
// build are the environment tells behind account-takeover and industrialised
// new-account fraud, and they are exactly what the scoring engine's
// DEVICE_INTEGRITY / EMULATOR / DEBUG_BUILD signals consume.
//
// Everything here comes from expo-device, so it works in Expo Go and needs no
// bundled native module and no permissions. Two fields the native Android SDK
// can report are deliberately NOT faked here:
//   • installerPackage — RN has no access, and the server treats an ABSENT
//     field as unknown (an empty string is itself the sideload indicator), so
//     omitting it is the correct wire behaviour, not a gap in the payload.
//   • accessibilityServices — already reported by the remote-access collector.

import type { EmitFn } from './types';

interface DeviceModule {
  isDevice: boolean;
  isRootedExperimentalAsync?: () => Promise<boolean>;
  isSideLoadingEnabledAsync?: () => Promise<boolean>;
}

let device: DeviceModule | null = null;
try {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  device = require('expo-device') as DeviceModule;
} catch {
  device = null;
}

export interface IntegrityStatus {
  rootLikely: boolean;
  emulatorLikely: boolean;
  debuggable: boolean;
  /** Android: "install unknown apps" allowed. Informational — the server's
   *  sideload signal keys off installerPackage, which RN cannot read. */
  sideLoadingEnabled?: boolean;
}

/** Collect the integrity snapshot; null when expo-device is unavailable. */
export async function collectIntegrity(): Promise<IntegrityStatus | null> {
  if (!device) return null;
  let rootLikely = false;
  let sideLoadingEnabled: boolean | undefined;
  try {
    rootLikely = (await device.isRootedExperimentalAsync?.()) ?? false;
  } catch {
    /* probe failed — absence of evidence, not evidence of integrity */
  }
  try {
    sideLoadingEnabled = await device.isSideLoadingEnabledAsync?.();
  } catch {
    sideLoadingEnabled = undefined;
  }
  return {
    rootLikely,
    // isDevice is false on simulators and emulators — the same tell the
    // Android SDK derives from the build fingerprint.
    emulatorLikely: device.isDevice === false,
    debuggable: typeof __DEV__ !== 'undefined' && __DEV__,
    ...(sideLoadingEnabled === undefined ? {} : { sideLoadingEnabled }),
  };
}

/** Emit PASSIVE_APP_INTEGRITY once, at init. Never throws. */
export async function reportIntegrity(emit: EmitFn): Promise<boolean> {
  try {
    const status = await collectIntegrity();
    if (!status) return false;
    emit('PASSIVE_APP_INTEGRITY', status);
    return true;
  } catch {
    return false;
  }
}
