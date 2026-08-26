// Device-integrity snapshot — the RN counterpart of the Android SDK's
// IntegrityCollector. A rooted/jailbroken handset, an emulator, or a debug
// build are the environment tells behind account-takeover and industrialised
// new-account fraud, and they are exactly what the scoring engine's
// DEVICE_INTEGRITY / EMULATOR / DEBUG_BUILD signals consume.
//
// The expo-device fields work in Expo Go with no native module. The fields
// JavaScript cannot reach — hookingFramework, installerPackage,
// devOptionsEnabled, the full enabled-accessibility-service list — come from
// the bundled VeraAppIntegrity module (a port of the native Android SDK's
// IntegrityCollector) and are merged in when it is present. In Expo Go the
// module is absent and those fields are OMITTED, never fabricated: the server
// treats an absent installerPackage as unknown, while an empty string is
// itself the sideload indicator.

import { requireOptionalNativeModule } from 'expo';
import type { EmitFn } from './types';

interface AppIntegrityNative {
  getStatus(): Promise<{
    hookingFramework: string;
    installerPackage: string;
    devOptionsEnabled: boolean;
    accessibilityServices: string[];
  }>;
}

const native = requireOptionalNativeModule<AppIntegrityNative>('VeraAppIntegrity');

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
   *  sideload signal keys off installerPackage. */
  sideLoadingEnabled?: boolean;
  /** 'frida' | 'xposed' | 'substrate' | ''. Native module only. */
  hookingFramework?: string;
  /** '' = manual install (sideload). Present only with the native module —
   *  the server reads absence as unknown. */
  installerPackage?: string;
  /** Native module only. */
  devOptionsEnabled?: boolean;
  /** All enabled accessibility-service packages. Native module only. */
  accessibilityServices?: string[];
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
  let nat: Awaited<ReturnType<AppIntegrityNative['getStatus']>> | null = null;
  if (native) {
    try {
      nat = await native.getStatus();
    } catch {
      nat = null;
    }
  }
  return {
    rootLikely,
    // isDevice is false on simulators and emulators — the same tell the
    // Android SDK derives from the build fingerprint.
    emulatorLikely: device.isDevice === false,
    debuggable: typeof __DEV__ !== 'undefined' && __DEV__,
    ...(sideLoadingEnabled === undefined ? {} : { sideLoadingEnabled }),
    ...(nat ?? {}),
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
