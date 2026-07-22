// Device fingerprint via expo-device. Emitted as PASSIVE_DEVICE_FINGERPRINT —
// the same event type the Android SDK sends — so the collector and scoring treat
// an RN session exactly like a native one (device identity, "known device").

import * as Device from 'expo-device';
import { Platform } from 'react-native';

export interface DeviceFingerprint {
  manufacturer: string;
  model: string;
  osName: string;
  osVersion: string;
  platform: string;
  platformVersion: string;
  isPhysical: boolean;
  totalMemory: number;
}

export function fingerprint(): DeviceFingerprint {
  return {
    manufacturer: Device.manufacturer ?? '',
    model: Device.modelName ?? '',
    osName: Device.osName ?? '',
    osVersion: Device.osVersion ?? '',
    platform: Platform.OS,
    platformVersion: String((Platform as { Version?: unknown }).Version ?? ''),
    isPhysical: Device.isDevice,
    totalMemory: Device.totalMemory ?? 0,
  };
}
