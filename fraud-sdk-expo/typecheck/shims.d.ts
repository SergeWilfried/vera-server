// Dev-only ambient declarations so the SDK typechecks HERE without the real
// react-native / expo-* packages installed (no RN toolchain in this repo).
// These mirror just the surface the SDK uses; the shipped package resolves the
// real types from the consumer's node_modules. NOT included by tsconfig.json.

declare module 'react-native' {
  export interface NativeKeyPressEvent {
    nativeEvent: { key: string };
  }
  export interface GestureResponderEvent {
    nativeEvent: { locationX: number; locationY: number; timestamp: number };
  }
  export interface PanResponderGestureState {
    dx: number;
    dy: number;
    vx: number;
    vy: number;
    moveX: number;
    moveY: number;
  }
  export interface PanResponderInstance {
    panHandlers: Record<string, unknown>;
  }
  export const PanResponder: {
    create(config: Record<string, unknown>): PanResponderInstance;
  };
  export const Platform: { OS: 'ios' | 'android' | 'web' | string };
  export type AppStateStatus = 'active' | 'background' | 'inactive' | string;
  export const AppState: {
    addEventListener(
      type: 'change',
      handler: (state: AppStateStatus) => void,
    ): { remove(): void };
  };
  export const NativeModules: Record<string, unknown>;
  export class NativeEventEmitter {
    constructor(mod?: unknown);
    addListener(event: string, cb: (payload: unknown) => void): { remove(): void };
  }
}

declare module 'expo-crypto' {
  export enum CryptoDigestAlgorithm {
    SHA256 = 'SHA-256',
  }
  export function digestStringAsync(
    algorithm: CryptoDigestAlgorithm,
    data: string,
  ): Promise<string>;
  export function randomUUID(): string;
}

declare module 'expo-secure-store' {
  export function getItemAsync(key: string): Promise<string | null>;
  export function setItemAsync(key: string, value: string): Promise<void>;
}

declare module 'expo-device' {
  export const manufacturer: string | null;
  export const modelName: string | null;
  export const osName: string | null;
  export const osVersion: string | null;
  export const deviceType: number | null;
  export const isDevice: boolean;
  export const totalMemory: number | null;
}
